use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cf_qemu_post::log_parser::{LogParser, LogRecord};
use clap::Parser;
use rayon::prelude::*;

const COPY_WINDOW: usize = 200;
const COPY_WINDOW_STALE_TRESHOLD: usize = 20;

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
            "KernelRecord {{ cpu: {}, size: {}, src: 0x{:016x}, dst: 0x{:016x} }}",
            self.cpu, self.size, self.src_address, self.dst_address
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
    first_insn_count: u64,
    first_global_idx: usize,
}

#[derive(Clone)]
struct RowcloneEvent {
    target_global_idx: usize,
    end_global_idx: usize,
    insn_count: u64,
    end_insn_count: u64,
    from: u64,
    to: u64,
    ttbr0: u64,
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
    copies: &mut Vec<MemCpy>,
    copy_idx: usize,
    mem_access: &LogRecord,
    global_idx: usize,
) -> bool {
    let access_size_bytes = 1 << mem_access.size;
    let copy = &mut copies[copy_idx];
    if mem_access.store == 1 {
        copy.current_to += access_size_bytes;
        copy.associated_indices.push(global_idx);
    } else if copy.current_from < copy.from + copy.size {
        copy.current_from += access_size_bytes;
        copy.associated_indices.push(global_idx);
    }
    copy_done(copy)
}

fn update_stale(rec_id: u64, copy_window: &mut Vec<KernelRecord>) {
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
) {
    update_stale(rec_id, copy_window);
    copy_window.retain(|copy| copy.stale <= COPY_WINDOW_STALE_TRESHOLD);

    while copy_window.len() < COPY_WINDOW {
        if let Some(record) = copy_logs.next() {
            copy_window.push(record);
        } else {
            return;
        }
    }
}

fn track_active_copies(
    records: &[LogRecord],
    mem_access: &LogRecord,
    active_copies: &mut Vec<MemCpy>,
    global_idx: usize,
    valid_indices: &mut [bool],
    rowclone_events: &mut Vec<RowcloneEvent>,
    copy_window: &mut Vec<KernelRecord>,
    copy_logs: &mut impl Iterator<Item = KernelRecord>,
) -> bool {
    for idx in 0..active_copies.len() {
        if mem_copy_match(mem_access, &active_copies[idx]) {
            let done = update_copy(active_copies, idx, mem_access, global_idx);
            if done {
                let completed_first_idx = active_copies[idx].first_global_idx;
                let rec_id = active_copies[idx].rec_id;
                copy_window.retain(|i| i.rec_id != rec_id);
                remove_stale_copies(rec_id, copy_window, copy_logs);

                for &saved_idx in &active_copies[idx].associated_indices {
                    valid_indices[saved_idx] = true;
                }

                let first_rec = &records[active_copies[idx].first_global_idx];
                let ttbr0_phys = (first_rec.ttbr0_pfn as u64) << 12;

                rowclone_events.push(RowcloneEvent {
                    target_global_idx: active_copies[idx].first_global_idx,
                    end_global_idx: global_idx,
                    insn_count: active_copies[idx].first_insn_count,
                    end_insn_count: mem_access.insn_count,
                    from: active_copies[idx].from,
                    to: active_copies[idx].to,
                    ttbr0: ttbr0_phys,
                });
                active_copies.retain(|c| c.first_global_idx != completed_first_idx);
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
                        pot_copy.first_insn_count = mem_access.insn_count;
                        pot_copy.first_global_idx = global_idx;
                        pot_copy.associated_indices.push(global_idx);

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
                indices.push(global_idx);
                potential_copies.push(MemCpy {
                    rec_id: copy.rec_id,
                    from: mem_access.address,
                    to: copy.dst_address,
                    size: copy.size,
                    current_from: mem_access.address + access_size_bytes,
                    current_to: copy.dst_address,
                    associated_indices: indices,
                    first_insn_count: mem_access.insn_count,
                    first_global_idx: global_idx,
                });
                potential_copy = true;
            }
        }
    }
    potential_copy
}

struct RamulatorFormatter<W: Write> {
    writer: BufWriter<W>,
    prev_insn_count: u64,
    first: bool,
}

impl<W: Write> RamulatorFormatter<W> {
    fn new(writer: BufWriter<W>) -> Self {
        Self {
            writer,
            prev_insn_count: 0,
            first: true,
        }
    }

    fn write_regular(&mut self, access: &LogRecord) -> io::Result<()> {
        if self.first {
            self.prev_insn_count = access.insn_count;
            self.first = false;
        }

        let bubble = if access.insn_count < self.prev_insn_count {
            0
        } else {
            access.insn_count - self.prev_insn_count
        };

        if access.store == 1 {
            writeln!(self.writer, "{} -1 0x{:016x}", bubble, access.address)?;
        } else {
            writeln!(self.writer, "{} 0x{:016x}", bubble, access.address)?;
        }

        self.prev_insn_count = access.insn_count;
        Ok(())
    }

    fn write_rowclone(&mut self, event: &RowcloneEvent) -> io::Result<()> {
        if self.first {
            self.prev_insn_count = event.insn_count;
            self.first = false;
        }

        let bubble = if event.insn_count < self.prev_insn_count {
            0
        } else {
            event.insn_count - self.prev_insn_count
        };
        writeln!(
            self.writer,
            "{} 0x{:016x} 0x{:016x}",
            bubble, event.from, event.to
        )?;
        self.prev_insn_count = event.end_insn_count;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn process_single_cpu_trace(
    trace_path: &Path,
    kernel_records: Vec<KernelRecord>,
    post_log_dir: &Path,
    post_log_rc_dir: &Path,
    cluster_gap: Option<usize>,
    min_cluster_copies: usize,
    margin_before: usize,
    margin_after: usize,
    allowed_ttbr0_pfns: Option<&HashSet<u32>>,
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
    let total_raw = baseline_history.len();
    eprintln!("[CPU {}] Trace brute chargée ({} accès).", cpu_id, total_raw);

    let mut kernel_iter = kernel_records.into_iter();
    let mut copy_window: Vec<KernelRecord> = kernel_iter.by_ref().take(COPY_WINDOW).collect();

    let mut active_copies: Vec<MemCpy> = Vec::new();
    let mut valid_indices = vec![false; baseline_history.len()];
    let mut rowclone_events: Vec<RowcloneEvent> = Vec::new();

    // PASSE 1 : Détection fidèle des RowClones
    for current_idx in 0..baseline_history.len() {
        let mem_access = baseline_history[current_idx];
        if track_active_copies(
            &baseline_history,
            &mem_access,
            &mut active_copies,
            current_idx,
            &mut valid_indices,
            &mut rowclone_events,
            &mut copy_window,
            &mut kernel_iter,
        ) {
            continue;
        }
        check_potential_copy_start(&mem_access, &copy_window, &mut active_copies, current_idx);
    }

    let detected_rc_count = rowclone_events.len();

    // CONSTRUCTION DU MASQUE ROI
    let mut in_roi = if let Some(max_gap) = cluster_gap {
        if detected_rc_count == 0 {
            vec![false; baseline_history.len()]
        } else {
            let mut mask = vec![false; baseline_history.len()];
            let mut valid_clusters: Vec<Vec<RowcloneEvent>> = Vec::new();
            let mut current_cluster: Vec<RowcloneEvent> = vec![rowclone_events[0].clone()];

            for w in rowclone_events.windows(2) {
                let acc_gap = w[1].target_global_idx.saturating_sub(w[0].end_global_idx);
                if acc_gap <= max_gap {
                    current_cluster.push(w[1].clone());
                } else {
                    if current_cluster.len() >= min_cluster_copies {
                        valid_clusters.push(current_cluster);
                    }
                    current_cluster = vec![w[1].clone()];
                }
            }
            if current_cluster.len() >= min_cluster_copies {
                valid_clusters.push(current_cluster);
            }

            for cluster in &valid_clusters {
                let cluster_start = cluster.first().unwrap().target_global_idx;
                let cluster_end = cluster.last().unwrap().end_global_idx;

                let start = cluster_start.saturating_sub(margin_before);
                let end = (cluster_end + margin_after).min(baseline_history.len() - 1);

                for idx in start..=end {
                    mask[idx] = true;
                }
            }
            mask
        }
    } else {
        vec![true; baseline_history.len()]
    };

    // APPLICATION DU FILTRAGE TTBR0 (intersecte le masque ROI s'il existe)
    if let Some(allowed_pfns) = allowed_ttbr0_pfns {
        for (idx, rec) in baseline_history.iter().enumerate() {
            if in_roi[idx] && !allowed_pfns.contains(&rec.ttbr0_pfn) {
                in_roi[idx] = false;
            }
        }
    }

    let kept_count = in_roi.iter().filter(|&&k| k).count();
    eprintln!(
        "[CPU {}] Filtrage appliqué : {}/{} accès conservés ({:.2}%).",
        cpu_id,
        kept_count,
        total_raw,
        if total_raw > 0 { (kept_count as f64 * 100.0) / (total_raw as f64) } else { 0.0 }
    );

    // PASSE 2 : Écriture Ramulator avec compensation exacte du compteur d'instructions
    let baseline_out_path = post_log_dir.join(format!("cpu_{}.trace", cpu_id));
    let rowclone_out_path = post_log_rc_dir.join(format!("cpu_{}.trace", cpu_id));

    let mut bl_fmt = RamulatorFormatter::new(BufWriter::new(File::create(baseline_out_path)?));
    let mut rc_fmt = RamulatorFormatter::new(BufWriter::new(File::create(rowclone_out_path)?));

    let events_map: HashMap<usize, &RowcloneEvent> = rowclone_events
        .iter()
        .map(|e| (e.target_global_idx, e))
        .collect();

    let mut final_rowclones = 0;
    let mut total_removed_loads = 0;
    let mut total_removed_stores = 0;
    let mut written_accesses = 0usize;

    let mut cumulated_skipped_insns: u64 = 0;
    let mut prev_raw_insn = baseline_history[0].insn_count;

    for (idx, mem_access) in baseline_history.iter().enumerate() {
        let delta_insn = mem_access.insn_count.saturating_sub(prev_raw_insn);
        prev_raw_insn = mem_access.insn_count;

        if !in_roi[idx] {
            cumulated_skipped_insns += delta_insn;
            continue;
        }

        let mut adj_access = *mem_access;
        adj_access.insn_count = adj_access.insn_count.saturating_sub(cumulated_skipped_insns);

        written_accesses += 1;
        bl_fmt.write_regular(&adj_access)?;

        if valid_indices[idx] {
            if adj_access.store == 1 {
                total_removed_stores += 1;
            } else {
                total_removed_loads += 1;
            }

            if let Some(event) = events_map.get(&idx) {
                let mut adj_event = (*event).clone();
                adj_event.insn_count = adj_event.insn_count.saturating_sub(cumulated_skipped_insns);
                adj_event.end_insn_count = adj_event.end_insn_count.saturating_sub(cumulated_skipped_insns);

                rc_fmt.write_rowclone(&adj_event)?;
                final_rowclones += 1;
            }
            continue;
        }

        rc_fmt.write_regular(&adj_access)?;
    }

    bl_fmt.flush()?;
    rc_fmt.flush()?;
    eprintln!(
        "[CPU {}] Écriture terminée -> RowClones émis: {}/{} | Supprimés: LD={}, ST={} | Accès écrits: {}\n",
        cpu_id, final_rowclones, detected_rc_count, total_removed_loads, total_removed_stores, written_accesses
    );
    Ok(())
}

#[derive(Parser, Debug)]
#[command(about = "Traitement des traces CPU pour Ramulator avec filtrage par TTBR0 et clustering")]
struct Args {
    #[arg(short, long)]
    log_dir: String,

    #[arg(short, long)]
    kernel_logfile: String,

    /// Ne conserver que les TTBR0 qui contiennent au moins une copie RowClone
    #[arg(long)]
    only_rc_ttbr0: bool,

    /// Filtrer sur un TTBR0 spécifique en hexadécimal (ex: 0x2da563000)
    #[arg(long)]
    specific_ttbr0: Option<String>,

    /// Écart maximal en accès entre deux copies pour former un cluster (ex: 10000)
    #[arg(long)]
    cluster_gap: Option<usize>,

    /// Taille minimale du cluster en nombre de copies (défaut: 10)
    #[arg(long, default_value_t = 10)]
    min_copies: usize,

    /// Rab global (avant ET après) le cluster en nombre d'accès
    #[arg(long)]
    roi_margin: Option<usize>,

    /// Rab spécifique AVANT le cluster
    #[arg(long)]
    margin_before: Option<usize>,

    /// Rab spécifique APRÈS le cluster
    #[arg(long)]
    margin_after: Option<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let post_log_dir = Path::new("post_log");
    let post_log_rc_dir = Path::new("post_log_rowclone");
    fs::create_dir_all(post_log_dir)?;
    fs::create_dir_all(post_log_rc_dir)?;

    let default_margin = args.roi_margin.unwrap_or(0);
    let m_before = args.margin_before.unwrap_or(default_margin);
    let m_after = args.margin_after.unwrap_or(default_margin);

    eprintln!("Lecture du journal kernel : {}", args.kernel_logfile);
    let kernel_file = File::open(&args.kernel_logfile)?;
    let mut kernel_by_cpu: HashMap<u8, Vec<KernelRecord>> = HashMap::new();
    for line in BufReader::new(kernel_file).lines().filter_map(Result::ok) {
        if let Some(record) = parse_kernel_line(&line) {
            kernel_by_cpu.entry(record.cpu).or_default().push(record);
        }
    }

    let mut trace_files: Vec<PathBuf> = fs::read_dir(&args.log_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("log.txt"))
                .unwrap_or(false)
        })
        .collect();

    trace_files.sort();

    // Détermination de l'ensemble des TTBR0 autorisés
    let allowed_ttbr0_pfns: Option<HashSet<u32>> = if let Some(ref specific_hex) = args.specific_ttbr0 {
        let ttbr0_val = parse_hex_address(specific_hex)
            .ok_or("Format d'adresse hexadécimale invalide pour --specific-ttbr0")?;
        let pfn = (ttbr0_val >> 12) as u32;
        eprintln!(
            "--- FILTRAGE ACTIF : TTBR0 spécifique 0x{:016x} (PFN: 0x{:08x}) uniquement ---",
            ttbr0_val, pfn
        );
        let mut set = HashSet::new();
        set.insert(pfn);
        Some(set)
    } else if args.only_rc_ttbr0 {
        eprintln!("--- RECHERCHE GLOBALE DES TTBR0 CONTENANT DES ROWCLONES ---");
        let rc_pfns: HashSet<u32> = trace_files
            .par_iter()
            .map(|trace_path| {
                let mut local_pfns = HashSet::new();
                if let Ok(mut parser) = LogParser::new(trace_path.to_str().unwrap()) {
                    let mut records = Vec::new();
                    while let Some(Ok(rec)) = parser.next() {
                        records.push(rec);
                    }
                    if !records.is_empty() {
                        let cpu_id = records[0].cpu as u8;
                        let cpu_records = kernel_by_cpu.get(&cpu_id).cloned().unwrap_or_default();
                        let mut kernel_iter = cpu_records.into_iter();
                        let mut copy_window: Vec<KernelRecord> = kernel_iter.by_ref().take(COPY_WINDOW).collect();
                        let mut active_copies = Vec::new();
                        let mut valid_indices = vec![false; records.len()];
                        let mut rowclone_events = Vec::new();

                        for idx in 0..records.len() {
                            let mem_access = records[idx];
                            if track_active_copies(
                                &records,
                                &mem_access,
                                &mut active_copies,
                                idx,
                                &mut valid_indices,
                                &mut rowclone_events,
                                &mut copy_window,
                                &mut kernel_iter,
                            ) {
                                continue;
                            }
                            check_potential_copy_start(&mem_access, &copy_window, &mut active_copies, idx);
                        }

                        for ev in rowclone_events {
                            local_pfns.insert((ev.ttbr0 >> 12) as u32);
                        }
                    }
                }
                local_pfns
            })
            .reduce(HashSet::new, |mut acc, item| {
                acc.extend(item);
                acc
            });

        eprintln!("TTBR0 avec RowClones découverts ({} processus) :", rc_pfns.len());
        for pfn in &rc_pfns {
            eprintln!("  -> 0x{:016x} (PFN: 0x{:08x})", (*pfn as u64) << 12, pfn);
        }
        Some(rc_pfns)
    } else {
        None
    };

    eprintln!(
        "\n{} traces trouvées. Exécution avec cluster_gap={:?}, min_copies={}, rab=[-{}, +{}]\n",
        trace_files.len(),
        args.cluster_gap,
        args.min_copies,
        m_before,
        m_after
    );

    let gap = args.cluster_gap;
    let min_c = args.min_copies;
    let allowed_ref = allowed_ttbr0_pfns.as_ref();

    trace_files.par_iter().for_each(|trace_path| {
        if let Ok(mut p) = LogParser::new(trace_path.to_str().unwrap()) {
            if let Some(Ok(first_rec)) = p.next() {
                let cpu_records = kernel_by_cpu.get(&(first_rec.cpu as u8)).cloned().unwrap_or_default();
                if let Err(e) = process_single_cpu_trace(
                    trace_path,
                    cpu_records,
                    post_log_dir,
                    post_log_rc_dir,
                    gap,
                    min_c,
                    m_before,
                    m_after,
                    allowed_ref,
                ) {
                    eprintln!("[ERREUR] Échec sur {:?} : {}", trace_path, e);
                }
            }
        }
    });

    eprintln!("\nTraitement terminé avec succès !");
    eprintln!("Fichiers générés dans : post_log/ et post_log_rowclone/");
    Ok(())
}