use std::collections::HashMap;
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
    from : u64,
    to: u64,
    size: u64,
    current_from: u64,
    current_to: u64,
    associated_indices: Vec<usize>,
    first_insn_count: u64,
    first_global_idx: usize,
}

struct RowcloneEvent {
    target_global_idx: usize,
    end_global_idx: usize,
    insn_count: u64,
    from: u64,
    to: u64,
}
fn parse_hex_address(hex_str: &str) -> Option<u64> {
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn parse_kernel_line(line: &str) ->Option<KernelRecord> {
    let line = line.trim();
    if line.starts_with("#") || line.is_empty() {
        return None;
    }

    let mut parts = line.split_whitespace();
    let cpu: u8 = parts.next()?.parse().ok()?;
    let src_address = parse_hex_address(parts.next()?)?;
    let dst_address = parse_hex_address(parts.next()?)?;

    Some(KernelRecord {
        rec_id : NEXT_KERNEL_REC_ID.fetch_add(1, Ordering::Relaxed),
        cpu,
        size: 4096,
        src_address,
        dst_address,
        stale: 0,
    })
}

fn mem_copy_match(mem_access: &LogRecord, copy: &MemCpy) -> bool {
    (copy.current_from == mem_access.address && mem_access.store == 0) ||
    (copy.current_to == mem_access.address && mem_access.store == 1) 
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
            copy.stale +=1;
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
                let rec_id = active_copies[idx].rec_id;
                copy_window.retain(|i| i.rec_id != rec_id);
                remove_stale_copies(rec_id, copy_window, copy_logs);

                for &saved_idx in &active_copies[idx].associated_indices {
                    valid_indices[saved_idx] = true;
                }
                rowclone_events.push(RowcloneEvent {
                    target_global_idx: active_copies[idx].first_global_idx,
                    end_global_idx: global_idx,
                    insn_count: active_copies[idx].first_insn_count,
                    from: active_copies[idx].from,
                    to: active_copies[idx].to,
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
                    current_from : mem_access.address + access_size_bytes,
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

// Ramulator Formating
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
        writeln!(self.writer, "{} 0x{:016x} 0x{:016x}", bubble, event.from, event.to)?;
        self.prev_insn_count = event.insn_count;
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

//CPU function

fn process_single_cpu_trace(
    trace_path: &Path,
    kernel_records: Vec<KernelRecord>,
    post_log_dir: &Path,
    post_log_rc_dir: &Path,
    crop_bounds: bool,
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
    eprintln!("[CPU {}] Trace chargée ({} accès).", cpu_id, baseline_history.len());

    let mut kernel_iter = kernel_records.into_iter();
    let mut copy_window: Vec<KernelRecord> = kernel_iter.by_ref().take(COPY_WINDOW).collect();

    let mut active_copies: Vec<MemCpy> = Vec::new();
    let mut valid_indices = vec![false; baseline_history.len()];
    let mut rowclone_events: Vec<RowcloneEvent> = Vec::new();

    //Pass 1 : Detection
    for (current_idx, mem_access) in baseline_history.iter().enumerate() {
        if track_active_copies(mem_access, &mut active_copies, current_idx, &mut valid_indices,
            &mut rowclone_events, &mut copy_window, &mut kernel_iter) {
                continue;
        }
        check_potential_copy_start(mem_access, &copy_window, &mut active_copies, current_idx);
    }

    let (start_bound, end_bound) = if crop_bounds && !rowclone_events.is_empty() {
        let first_idx = rowclone_events.iter().map(|e| e.target_global_idx).min().unwrap_or(0);
        let last_idx = rowclone_events.iter().map(|e| e.end_global_idx).max().unwrap_or(baseline_history.len());
        eprintln!("[CPU {}] Option CROP active : [{} à {}]", cpu_id, first_idx, last_idx);
        (first_idx, last_idx)
    } else {
        (0, baseline_history.len())
    };

    //Pass 2 : Writing
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

    for (idx, mem_access) in baseline_history.iter().enumerate() {
        if idx < start_bound || idx > end_bound {
            continue;
        }

        bl_fmt.write_regular(mem_access)?;

        if valid_indices[idx] {
            if mem_access.store == 1 {
                total_removed_stores += 1;
            } else {
                total_removed_loads += 1;
            }

            if let Some(event) = events_map.get(&idx) {
                rc_fmt.write_rowclone(event)?;
                final_rowclones += 1;
            }
            continue;
        }

        rc_fmt.write_regular(mem_access)?;
    }
    bl_fmt.flush()?;
    rc_fmt.flush()?;
    eprintln!(
        "[CPU {}] Terminé -> RowClones: {}, Supprimés (LD: {}, ST: {})",
        cpu_id, final_rowclones, total_removed_loads, total_removed_stores
    );
    Ok(())
}

#[derive(Parser, Debug)]
#[command(about = "Traitement parallèle des traces CPU et détection RowClone")]

struct Args {
    #[arg(short, long)]
    log_dir: String,

    #[arg(short, long)]
    kernel_logfile: String,

    #[arg(short, long, default_value_t = false)]
    crop: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let post_log_dir = Path::new("post_log");
    let post_log_rc_dir = Path::new("post_log_rowclone");
    fs::create_dir_all(post_log_dir)?;
    fs::create_dir_all(post_log_rc_dir)?;

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
    eprintln!("{} fichiers de traces détectés. Démarrage du traitement parallèle...\n", trace_files.len());
    trace_files.par_iter().for_each(|trace_path| {
        if let Ok(mut p) = LogParser::new(trace_path.to_str().unwrap()) {
            if let Some(Ok(first_rec)) = p.next() {
                let cpu_records = kernel_by_cpu.get(&first_rec.cpu).cloned().unwrap_or_default();
                if let Err(e) = process_single_cpu_trace(trace_path, cpu_records, post_log_dir,
                                                        post_log_rc_dir, args.crop) {
                    eprintln!("[ERREUR] Échec sur {:?} : {}", trace_path, e);
                }
            }
        }
    });

    eprintln!("\nPipeline terminée avec succès !");
    eprintln!("Fichiers générés dans :");
    eprintln!(" - post_log/");
    eprintln!(" - post_log_rowclone/");

    Ok(())

}
