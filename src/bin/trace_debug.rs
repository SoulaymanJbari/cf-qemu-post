use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_qemu_post::log_parser::{LogParser, LogRecord};
use clap::Parser;
use rayon::prelude::*;

const COPY_WINDOW: usize = 200;
const COPY_WINDOW_STALE_THRESHOLD: usize = 20;

static NEXT_KERNEL_REC_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct KernelRecord {
    rec_id: u64,
    cpu: u8,
    size: u64,
    src_address: u64,
    dst_address: u64,
    stale: usize,
}

impl fmt::Debug for KernelRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KernelRecord {{ rec_id: {}, cpu: {}, size: {}, src: 0x{:016x}, dst: 0x{:016x} }}",
            self.rec_id, self.cpu, self.size, self.src_address, self.dst_address
        )
    }
}

#[derive(Clone)]
struct MemCpy {
    rec_id: u64,
    from: u64,
    to: u64,
    size: u64,
    current_from: u64,
    current_to: u64,
    associated_indices: Vec<usize>,
    associated_records: Vec<LogRecord>,
    first_insn_count: u64,
    first_global_idx: usize,
}

struct RowcloneEvent {
    rec_id: u64,
    cpu: u8,
    target_global_idx: usize,
    end_global_idx: usize,
    from: u64,
    to: u64,
    removed_accesses_count: usize,
    records: Vec<LogRecord>,
}

fn parse_hex_address(hex_str: &str) -> Option<u64> {
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn parse_kernel_line(line: &str) -> Option<KernelRecord> {
    let line = line.trim();
    if line.starts_with('#') || line.is_empty() {
        return None;
    }

    let mut parts = line.split_whitespace();
    let cpu: u8 = parts.next()?.parse().ok()?;
    let src_address = parse_hex_address(parts.next()?)?;
    let dst_address = parse_hex_address(parts.next()?)?;

    Some(KernelRecord {
        rec_id: NEXT_KERNEL_REC_ID.fetch_add(1, Ordering::Relaxed),
        cpu,
        size: 4096,
        src_address,
        dst_address,
        stale: 0,
    })
}

fn mem_copy_match(mem_access: &LogRecord, copy: &MemCpy) -> bool {
    (copy.current_from == mem_access.address && mem_access.store == 0)
        || (copy.current_to == mem_access.address && mem_access.store == 1)
}

fn copy_done(copy: &MemCpy) -> bool {
    copy.current_from >= copy.from + copy.size && copy.current_to >= copy.to + copy.size
}

fn update_copy(
    copies: &mut [MemCpy],
    copy_idx: usize,
    mem_access: &LogRecord,
    global_idx: usize,
) -> bool {
    let access_size_bytes = 1 << mem_access.size;
    let copy = &mut copies[copy_idx];

    if mem_access.store == 1 {
        copy.current_to += access_size_bytes;
        copy.associated_indices.push(global_idx);
        copy.associated_records.push(mem_access.clone());
    } else if copy.current_from < copy.from + copy.size {
        copy.current_from += access_size_bytes;
        copy.associated_indices.push(global_idx);
        copy.associated_records.push(mem_access.clone());
    }
    copy_done(copy)
}

fn update_stale(rec_id: u64, copy_window: &mut [KernelRecord]) {
    for copy in copy_window {
        if copy.rec_id < rec_id {
            copy.stale += 1;
        }
    }
}

fn remove_stale_copies(
    rec_id: u64,
    copy_window: &mut Vec<KernelRecord>,
    copy_logs: &mut impl Iterator<Item = KernelRecord>,
    evicted_stale: &mut Vec<KernelRecord>,
) {
    update_stale(rec_id, copy_window);
    copy_window.retain(|copy| {
        if copy.stale > COPY_WINDOW_STALE_THRESHOLD {
            evicted_stale.push(copy.clone());
            false
        } else {
            true
        }
    });

    while copy_window.len() < COPY_WINDOW {
        if let Some(record) = copy_logs.next() {
            copy_window.push(record);
        } else {
            return;
        }
    }
}

fn track_active_copies(
    mem_access: &LogRecord,
    active_copies: &mut Vec<MemCpy>,
    global_idx: usize,
    rowclone_events: &mut Vec<RowcloneEvent>,
    copy_window: &mut Vec<KernelRecord>,
    copy_logs: &mut impl Iterator<Item = KernelRecord>,
    evicted_stale: &mut Vec<KernelRecord>,
) -> bool {
    for idx in 0..active_copies.len() {
        if mem_copy_match(mem_access, &active_copies[idx]) {
            let done = update_copy(active_copies, idx, mem_access, global_idx);
            if done {
                let rec_id = active_copies[idx].rec_id;
                let removed_count = active_copies[idx].associated_indices.len();
                copy_window.retain(|i| i.rec_id != rec_id);
                remove_stale_copies(rec_id, copy_window, copy_logs, evicted_stale);

                let internal_records = std::mem::take(&mut active_copies[idx].associated_records);

                rowclone_events.push(RowcloneEvent {
                    rec_id,
                    cpu: mem_access.cpu,
                    target_global_idx: active_copies[idx].first_global_idx,
                    end_global_idx: global_idx,
                    from: active_copies[idx].from,
                    to: active_copies[idx].to,
                    removed_accesses_count: removed_count,
                    records: internal_records,
                });
                active_copies.remove(idx);
            }
            return true;
        }
    }
    false
}

fn check_potential_copy_start(
    mem_access: &LogRecord,
    copy_window: &[KernelRecord],
    potential_copies: &mut Vec<MemCpy>,
    global_idx: usize,
) -> bool {
    let mut potential_copy = false;
    for copy in copy_window {
        let is_start = mem_access.store == 0 && copy.src_address == mem_access.address;

        if is_start {
            let mut existing = false;
            for pot_copy in potential_copies.iter_mut() {
                if pot_copy.rec_id == copy.rec_id {
                    if pot_copy.current_to == pot_copy.to {
                        pot_copy.associated_indices.clear();
                        pot_copy.associated_records.clear();

                        pot_copy.first_insn_count = mem_access.insn_count;
                        pot_copy.first_global_idx = global_idx;
                        pot_copy.associated_indices.push(global_idx);
                        pot_copy.associated_records.push(mem_access.clone());

                        let access_size_bytes = 1 << mem_access.size;
                        pot_copy.current_from = mem_access.address + access_size_bytes;
                        potential_copy = true;
                    }
                    existing = true;
                    break;
                }
            }
            if !existing {
                let access_size_bytes = 1 << mem_access.size;
                let mut indices = Vec::with_capacity(768);
                let mut records = Vec::with_capacity(768);
                indices.push(global_idx);
                records.push(mem_access.clone());

                potential_copies.push(MemCpy {
                    rec_id: copy.rec_id,
                    from: mem_access.address,
                    to: copy.dst_address,
                    size: copy.size,
                    current_from: mem_access.address + access_size_bytes,
                    current_to: copy.dst_address,
                    associated_indices: indices,
                    associated_records: records,
                    first_insn_count: mem_access.insn_count,
                    first_global_idx: global_idx,
                });
                potential_copy = true;
            }
        }
    }
    potential_copy
}

fn process_single_cpu_trace_debug(
    trace_path: &Path,
    kernel_records: Vec<KernelRecord>,
    debug_dir: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut parser = LogParser::new(trace_path.to_str().unwrap())?;
    let mut baseline_history: Vec<LogRecord> = Vec::new();

    while let Some(Ok(record)) = parser.next() {
        baseline_history.push(record);
    }

    if baseline_history.is_empty() {
        eprintln!("[AVERTISSEMENT] Fichier vide ignoré : {:?}", trace_path);
        return Ok(());
    }
    let cpu_id = baseline_history[0].cpu;
    let total_kernel_initial = kernel_records.len();
    eprintln!(
        "[CPU {}] Trace chargée ({} accès mémoire, {} entrées kernel associées).",
        cpu_id,
        baseline_history.len(),
        total_kernel_initial
    );

    let initial_records = kernel_records.clone();
    let mut kernel_iter = kernel_records.into_iter();
    let mut copy_window: Vec<KernelRecord> = kernel_iter.by_ref().take(COPY_WINDOW).collect();

    let mut active_copies: Vec<MemCpy> = Vec::new();
    let mut rowclone_events: Vec<RowcloneEvent> = Vec::new();
    let mut evicted_stale: Vec<KernelRecord> = Vec::new();

    for (current_idx, mem_access) in baseline_history.iter().enumerate() {
        if track_active_copies(
            mem_access,
            &mut active_copies,
            current_idx,
            &mut rowclone_events,
            &mut copy_window,
            &mut kernel_iter,
            &mut evicted_stale,
        ) {
            continue;
        }
        check_potential_copy_start(mem_access, &copy_window, &mut active_copies, current_idx);
    }

    // 1. Écriture du journal des copies DÉTECTÉES
    let debug_out_path = debug_dir.join(format!("debug_cpu_{}.log", cpu_id));
    let mut writer = BufWriter::new(File::create(debug_out_path)?);

    let mut total_loads = 0;
    let mut total_stores = 0;

    for event in &rowclone_events {
        writeln!(writer, "=============================================================")?;
        writeln!(
            writer,
            "ROWCOPY DÉTECTÉ - ID Rec: {} | CPU: {} | Index trace: [{} -> {}]",
            event.rec_id, event.cpu, event.target_global_idx, event.end_global_idx
        )?;
        writeln!(
            writer,
            "Source (From): 0x{:016x} -> Destination (To): 0x{:016x}",
            event.from, event.to
        )?;
        writeln!(
            writer,
            "Nombre d'accès interceptés : {}",
            event.removed_accesses_count
        )?;
        writeln!(writer, "-------------------------------------------------------------")?;

        for (local_idx, rec) in event.records.iter().enumerate() {
            if rec.store == 1 {
                total_stores += 1;
            } else {
                total_loads += 1;
            }
            writeln!(
                writer,
                "  [{local_idx:03}] CPU: {} | INSN: {} | ADDR: 0x{:016x} | TYPE: {} | SIZE: 2^{}",
                rec.cpu,
                rec.insn_count,
                rec.address,
                if rec.store == 1 { "STORE" } else { "LOAD" },
                rec.size
            )?;
        }
        writeln!(writer)?;
    }
    writer.flush()?;

    // 2. Écriture du journal des copies MANQUÉES / NON EFFECTUÉES
    let completed_ids: HashSet<u64> = rowclone_events.iter().map(|e| e.rec_id).collect();
    let missed_out_path = debug_dir.join(format!("missed_cpu_{}.log", cpu_id));
    let mut missed_writer = BufWriter::new(File::create(missed_out_path)?);

    let mut count_incomplete = 0;
    let mut count_stale = 0;
    let mut count_never_started = 0;
    let mut count_never_entered = 0;

    for rec in &initial_records {
        if completed_ids.contains(&rec.rec_id) {
            continue;
        }

        writeln!(missed_writer, "=============================================================")?;
        if let Some(active) = active_copies.iter().find(|c| c.rec_id == rec.rec_id) {
            count_incomplete += 1;
            let bytes_from = active.current_from.saturating_sub(active.from);
            let bytes_to = active.current_to.saturating_sub(active.to);
            writeln!(
                missed_writer,
                "STATUT: INCOMPLÈTE EN FIN DE TRACE | ID: {} | CPU: {}",
                rec.rec_id, rec.cpu
            )?;
            writeln!(
                missed_writer,
                "Source: 0x{:016x} -> Destination: 0x{:016x}",
                rec.src_address, rec.dst_address
            )?;
            writeln!(missed_writer, "Progression au moment de l'arrêt :")?;
            writeln!(
                missed_writer,
                "  - Source lue        : {} / {} octets ({:.1}%)",
                bytes_from,
                rec.size,
                (bytes_from as f64 / rec.size as f64) * 100.0
            )?;
            writeln!(
                missed_writer,
                "  - Destination écrite: {} / {} octets ({:.1}%)",
                bytes_to,
                rec.size,
                (bytes_to as f64 / rec.size as f64) * 100.0
            )?;
            writeln!(
                missed_writer,
                "  - Accès interceptés : {}",
                active.associated_indices.len()
            )?;
        } else if evicted_stale.iter().any(|e| e.rec_id == rec.rec_id) {
            count_stale += 1;
            writeln!(
                missed_writer,
                "STATUT: ÉVINCÉE DE LA FENÊTRE (STALE > {}) | ID: {} | CPU: {}",
                COPY_WINDOW_STALE_THRESHOLD, rec.rec_id, rec.cpu
            )?;
            writeln!(
                missed_writer,
                "Source: 0x{:016x} -> Destination: 0x{:016x}",
                rec.src_address, rec.dst_address
            )?;
            writeln!(
                missed_writer,
                "Détail : La fenêtre glissante a purgé cette copie car 20 copies ultérieures se sont terminées avant elle."
            )?;
        } else if copy_window.iter().any(|w| w.rec_id == rec.rec_id) {
            count_never_started += 1;
            writeln!(
                missed_writer,
                "STATUT: JAMAIS DÉMARRÉE (DANS LA FENÊTRE) | ID: {} | CPU: {}",
                rec.rec_id, rec.cpu
            )?;
            writeln!(
                missed_writer,
                "Source: 0x{:016x} -> Destination: 0x{:016x}",
                rec.src_address, rec.dst_address
            )?;
            writeln!(
                missed_writer,
                "Détail : Aucun accès LOAD initial à l'adresse 0x{:016x} n'a été intercepté.",
                rec.src_address
            )?;
        } else {
            count_never_entered += 1;
            writeln!(
                missed_writer,
                "STATUT: JAMAIS ENTRÉE DANS LA FENÊTRE | ID: {} | CPU: {}",
                rec.rec_id, rec.cpu
            )?;
            writeln!(
                missed_writer,
                "Source: 0x{:016x} -> Destination: 0x{:016x}",
                rec.src_address, rec.dst_address
            )?;
            writeln!(
                missed_writer,
                "Détail : La fenêtre est restée bloquée avant que cette entrée n'y entre.",
            )?;
        }
    }
    missed_writer.flush()?;

    let total_missed = count_incomplete + count_stale + count_never_started + count_never_entered;
    eprintln!(
        "[CPU {}] Rapport : {} Total Kernel | {} Validées | {} Manquées\n  \
         -> Incomplètes: {} | Évincées (stale): {} | Jamais démarrées: {} | Hors-fenêtre: {}",
        cpu_id,
        total_kernel_initial,
        rowclone_events.len(),
        total_missed,
        count_incomplete,
        count_stale,
        count_never_started,
        count_never_entered
    );

    Ok(())
}

#[derive(Parser, Debug)]
#[command(about = "Dump de debug des accès LOAD/STORE associés aux RowClones")]
struct Args {
    #[arg(short, long)]
    log_dir: String,

    #[arg(short, long)]
    kernel_logfile: String,

    #[arg(short, long, default_value = "debug_logs")]
    output_dir: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let debug_dir = Path::new(&args.output_dir);
    fs::create_dir_all(debug_dir)?;

    eprintln!("Lecture et indexation du journal kernel : {}", args.kernel_logfile);
    let kernel_file = File::open(&args.kernel_logfile)?;
    let mut kernel_by_cpu: HashMap<u8, Vec<KernelRecord>> = HashMap::new();
    for line in BufReader::new(kernel_file).lines().filter_map(Result::ok) {
        if let Some(record) = parse_kernel_line(&line) {
            kernel_by_cpu.entry(record.cpu).or_default().push(record);
        }
    }

    let trace_files: Vec<PathBuf> = fs::read_dir(&args.log_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("log.txt"))
                .unwrap_or(false)
        })
        .collect();

    eprintln!(
        "{} fichiers de traces détectés. Traitement parallèle en cours...\n",
        trace_files.len()
    );

    trace_files.par_iter().for_each(|trace_path| {
        if let Ok(mut p) = LogParser::new(trace_path.to_str().unwrap()) {
            if let Some(Ok(first_rec)) = p.next() {
                let cpu_records = kernel_by_cpu.get(&first_rec.cpu).cloned().unwrap_or_default();
                if let Err(e) = process_single_cpu_trace_debug(trace_path, cpu_records, debug_dir) {
                    eprintln!("[ERREUR] Échec sur {:?} : {}", trace_path, e);
                }
            }
        }
    });

    eprintln!("\nPipeline de debug terminée avec succès.");
    eprintln!("Rapports écrits dans : {}", args.output_dir);

    Ok(())
}