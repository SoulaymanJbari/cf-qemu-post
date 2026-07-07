use cf_qemu_post::log_parser;
use cf_qemu_post::lookahead_iter::LookaheadIterator;
use cf_qemu_post::memory_access::{MemRecord, MemoryAccess, RowcloneRecord};
use clap::{Parser, command};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};

const COPY_WINDOW: usize = 200;
const COPY_WINDOW_STALE_THRESHOLD: usize = 20;

static NEXT_KERNEL_REC_ID: AtomicU64 = AtomicU64::new(0);

struct KernelRecord {
    rec_id: u64,
    cpu: u8,
    size: u64,
    operation: char,
    kernel_address: u64,
    user_address: u64,
    stale: usize,
}

static KERNEL_LOG_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"([^\s]+)\s+\[(\d+)\].*rowclone_(read|write):\s+\[RC\]\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)"#).expect("failed to compile regex")
});

impl fmt::Debug for KernelRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KernelRecord {{cpu: {}, size: {}, op: {}, kernel_address: 0x{:016x}, user_address: 0x{:016x} }}",
            self.cpu,
            self.size,
            self.operation,
            self.kernel_address,
            self.user_address
        )
    }
}

#[derive(Clone)]
struct MemCpy {
    rec_id: u64,
    cpu: usize,
    from: u64,
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
    cpu: usize,
    insn_count: u64,
    from: u64,
    to: u64,
}

fn parse_hex_address(hex_str: &str) -> Option<u64> {
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn parse_kernel_line(line: &str) -> Option<KernelRecord> {
    if let Some(caps) = KERNEL_LOG_PATTERN.captures(line) {
        let op_str = &caps[3];
        let operation = if op_str == "read" { 'r' } else { 'w' };
        let src_addr = parse_hex_address(&caps[4])?;
        let dst_addr = parse_hex_address(&caps[5])?;
        let (kernel_address, user_address) = if operation == 'r' {
            (src_addr, dst_addr)
        } else {
            (dst_addr, src_addr)
        };
        Some(KernelRecord {
            rec_id: NEXT_KERNEL_REC_ID.fetch_add(1, Ordering::Relaxed),
            cpu: caps[2].parse().ok()?,
            size: 4096,
            operation,
            kernel_address,
            user_address,
            stale: 0,
        })
    } else {
        None
    }
}

fn mem_copy_match(mem_access: &log_parser::LogRecord, copy: &MemCpy) -> bool {
    if mem_access.cpu as usize != copy.cpu {
        return false;
    }
    (copy.current_from == mem_access.address && mem_access.store == 0)
        || (copy.current_to == mem_access.address && mem_access.store == 1)
}

fn copy_done(copy: &MemCpy) -> bool {
    copy.current_to >= copy.to + copy.size
}

fn update_copy(
    copies: &mut Vec<MemCpy>,
    copy_idx: usize,
    mem_access: &log_parser::LogRecord,
    global_idx: usize,
) -> bool {
    let access_size_bytes = 1 << mem_access.size;
    let copy = &mut copies[copy_idx];
    if mem_access.store == 1 {
        copy.current_to += access_size_bytes;
    } else {
        copy.current_from += access_size_bytes;
    }
    copy.associated_indices.push(global_idx);
    copy_done(copy)
}

fn next_kernel_line(
    lines: &mut impl Iterator<Item = io::Result<String>>,
) -> Option<KernelRecord> {
    while let Some(Ok(line)) = lines.next() {
        if let Some(record) = parse_kernel_line(&line) {
            return Some(record);
        } else {
            eprintln!("not parsed?");
        }
    }
    None
}

fn print_rowclone<W: Write>(copy: &RowcloneEvent, output: &mut BufWriter<W>) {
    writeln!(
        output,
        "{}",
        RowcloneRecord {
            cpu: copy.cpu,
            insn_count: copy.insn_count,
            from: copy.from,
            to: copy.to,
        }
    );
}

fn print_regular_access<W: Write>(
    mem_access: &log_parser::LogRecord,
    output: &mut BufWriter<W>,
) {
    writeln!(
        output,
        "{}",
        MemRecord {
            cpu: mem_access.cpu.into(),
            insn_count: mem_access.insn_count,
            address: mem_access.address,
            store: mem_access.store == 1,
        }
    );
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
    copy_logs: &mut impl Iterator<Item = io::Result<String>>,
) {
    update_stale(rec_id, copy_window);
    copy_window.retain(|copy| copy.stale <= COPY_WINDOW_STALE_THRESHOLD);

    while copy_window.len() < COPY_WINDOW {
        if let Some(line) = next_kernel_line(copy_logs) {
            copy_window.push(line);
        } else {
            return;
        }
    }
}

fn track_active_copies(
    mem_access: &log_parser::LogRecord,
    active_copies: &mut Vec<MemCpy>,
    global_idx: usize,
    valid_indices: &mut Vec<bool>,
    rowclone_events: &mut Vec<RowcloneEvent>,
    copy_window: &mut Vec<KernelRecord>,
    copy_logs: &mut impl Iterator<Item = io::Result<String>>,
) -> bool {
    for idx in 0..active_copies.len() {
        if mem_copy_match(mem_access, &active_copies[idx]) {
            let done = update_copy(active_copies, idx, mem_access, global_idx);
            if done {
                eprintln!("Rowclone finished!");
                let rec_id = active_copies[idx].rec_id;
                copy_window.retain(|i| i.rec_id != rec_id);
                remove_stale_copies(rec_id, copy_window, copy_logs);

                for &saved_idx in &active_copies[idx].associated_indices {
                    valid_indices[saved_idx] = true;
                }
                rowclone_events.push(RowcloneEvent {
                    target_global_idx: active_copies[idx].first_global_idx,
                    end_global_idx: global_idx,
                    cpu: active_copies[idx].cpu,
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
    mem_access: &log_parser::LogRecord,
    copy_window: &Vec<KernelRecord>,
    potential_copies: &mut Vec<MemCpy>,
    global_idx: usize,
) -> bool {
    let mut potential_copy = false;

    for copy in copy_window {
        if mem_access.cpu != copy.cpu {
            continue;
        }
        let is_start = match copy.operation {
            'r' => {
                mem_access.store == 0 && copy.kernel_address == mem_access.address
            }
            'w' => {
                mem_access.store == 0 && copy.user_address == mem_access.address
            }
            _ => {
                eprintln!("Invalid operation in kernel record!");
                false
            }
        };
        if is_start {
            let mut existing_potential_copy = false;
            for pot_copy in potential_copies.iter_mut() {
                if pot_copy.rec_id == copy.rec_id {
                    if pot_copy.current_to == pot_copy.to {
                        pot_copy.associated_indices.push(global_idx);
                        potential_copy = true;
                    }
                    existing_potential_copy = true;
                    break;
                }
            }
            if !existing_potential_copy {
                let to = if copy.operation == 'w' {
                    copy.kernel_address
                } else {
                    copy.user_address
                };
                eprintln!("new potential copy");
                let mut indices = Vec::new();
                indices.push(global_idx);
                potential_copies.push(MemCpy {
                    rec_id: copy.rec_id,
                    from: mem_access.address,
                    to,
                    cpu: copy.cpu as usize,
                    size: copy.size,
                    current_from: mem_access.address + (1 << mem_access.size),
                    current_to: to,
                    associated_indices: indices,
                    first_insn_count: mem_access.insn_count,
                    first_global_idx: global_idx,
                });
                potential_copy = true;
                break;
            }
        }
    }
    potential_copy
}

fn match_copy_to_mem_accesses<W1: Write, W2: Write>(
    baseline_history: Vec<log_parser::LogRecord>,
    mut copy_logs: impl Iterator<Item = io::Result<String>>,
    copy_window: &mut Vec<KernelRecord>,
    rowclone_output: &mut BufWriter<W1>,
    baseline_output: &mut BufWriter<W2>,
    crop_bounds: bool,
) {
    let mut active_copies: Vec<MemCpy> = vec![];
    let mut valid_indices = vec![false; baseline_history.len()];
    let mut rowclone_events: Vec<RowcloneEvent> = vec![];
    let mut mem_accesses = LookaheadIterator::new(baseline_history.iter());
    let mut current_global_idx = 0;
    while let Some(mem_access) = mem_accesses.next() {
       if track_active_copies(
            &mem_access,
            &mut active_copies,
            current_global_idx,
            &mut valid_indices,
            &mut rowclone_events,
            copy_window,
            &mut copy_logs
        ) {
            current_global_idx += 1;
            continue;
        } else if check_potential_copy_start(&mem_access, copy_window, &mut active_copies, current_global_idx) {
            current_global_idx += 1;
            continue;
        }
        current_global_idx += 1;
    }

    let (start_bound, end_bound) = if crop_bounds && !rowclone_events.is_empty() {
        let first_idx = rowclone_events.iter().map(|e| e.target_global_idx).min().unwrap_or(0);
        let last_idx = rowclone_events.iter().map(|e| e.end_global_idx).max().unwrap_or(baseline_history.len());
        eprintln!("Option CROP active. Bornes détectées : [{} à {}]", first_idx, last_idx);
        (first_idx, last_idx)
    } else {
        (0, baseline_history.len())
    };

    eprintln!("Génération finale du fichier...");
    let mut final_rowclones = 0;
    for (idx, mem_access) in baseline_history.iter().enumerate() {

        if idx < start_bound || idx > end_bound {
            continue;
        }

        print_regular_access(mem_access, baseline_output);
        if valid_indices[idx] {
            if let Some(event) = rowclone_events.iter().find(|e| e.target_global_idx == idx) {
                print_rowclone(event, rowclone_output);
                final_rowclones += 1;
            }
            continue;
        }
        print_regular_access(mem_access, rowclone_output);
    }

    eprintln!("Rowclones validated: {}", final_rowclones);
    eprintln!("Rowclones uncompleted: {}", active_copies.len());
}

pub fn add_rowclone_info(
    mem_reader: BufReader<std::io::Stdin>,
    kernel_logfile: &str,
    rowclone_output_file: &str,
    baseline_output_file: &str,
    crop_bounds: bool,
) -> io::Result<()> {

    eprintln!("Passe 1 : Chargement de la trace mémoire...");
    let baseline_history: Vec<log_parser::LogRecord> = mem_reader
        .lines()
        .filter_map(|line| line.ok()?.parse::<log_parser::LogRecord>().ok())
        .collect();
    eprintln!("Trace chargée ({} accès).", baseline_history.len());

    let kernel_log = File::open(kernel_logfile)?;
    let rowclone_file = File::create(rowclone_output_file)?;
    let mut rc_writer = BufWriter::new(rowclone_file);
    let baseline_file = File::create(baseline_output_file)?;
    let mut bl_writer = BufWriter::new(baseline_file);
    let reader = BufReader::new(kernel_log);
    let mut lines = reader.lines();
    let mut copy_window = lines
        .by_ref()
        .filter_map(|l| {
            let line = l.expect("Failed to read copy line");
            parse_kernel_line(&line)
        })
        .take(COPY_WINDOW)
        .collect();
    
    eprintln!("Passe 2 : Analyse et filtrage...");
    match_copy_to_mem_accesses(baseline_history, lines, &mut copy_window, &mut rc_writer, &mut bl_writer, crop_bounds);

    eprintln!("Unmatched Rowclones: {}", copy_window.len());
    let _ = rc_writer.flush();
    let _ = bl_writer.flush();
    Ok(())
}
#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    kernel_logfile: String,

    #[arg(short, long)]
    output_file: String,

    #[arg(short, long)]
    baseline_file: String,

    #[arg(short, long, default_value_t = false)]
    crop: bool,
}

fn main() {
    let args = Args::parse();
    let reader = BufReader::new(std::io::stdin());
    if add_rowclone_info(reader, &args.kernel_logfile, &args.output_file, &args.baseline_file, args.crop).is_ok() {
        eprintln!("Finished adding rowclone info");
    } else {
        eprintln!("Error adding rowclone info");
    }
}
