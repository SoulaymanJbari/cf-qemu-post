use cf_qemu_post::log_parser;
use cf_qemu_post::lookahead_iter::LookaheadIterator;
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
    command: String,
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
            "KernelRecord {{command: {}, cpu: {}, size: {}, op: {}, kernel_address: 0x{:016x}, user_address: 0x{:016x} }}",
            self.command,
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
    insn_count: u64,
    from: u64,
    to: u64,
    size: u64,
    current_from: u64,
    current_to: u64,
    associated_indices: Vec<usize>,
    associated_records: Vec<log_parser::LogRecord>, // Pour l'analyse du dump textuel
    first_insn_count: u64,
    first_global_idx: usize,
}

struct RowcloneEvent {
    rec_id: u64,
    target_global_idx: usize,
    end_global_idx: usize,
    cpu: usize,
    insn_count: u64,
    from: u64,
    to: u64,
    removed_accesses_count: usize,
    records: Vec<log_parser::LogRecord>,
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
            command: caps[1].to_string(),
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
    let current_cpu = mem_access.cpu as usize;
    let copy = &mut copies[copy_idx];
    if mem_access.store == 1 {
        copy.current_to += access_size_bytes;
    } else {
        copy.current_from += access_size_bytes;
    }
    if copy.cpu != current_cpu {
        copy.first_insn_count = mem_access.insn_count;
    }
    copy.insn_count = mem_access.insn_count;
    copy.cpu = current_cpu;
    copy.associated_indices.push(global_idx);
    copy.associated_records.push(mem_access.clone());
    copy_done(&copy)
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
                let removed_count = active_copies[idx].associated_indices.len();
                copy_window.retain(|i| i.rec_id != rec_id);
                remove_stale_copies(rec_id, copy_window, copy_logs);
                
                let internal_records = std::mem::take(&mut active_copies[idx].associated_records);

                rowclone_events.push(RowcloneEvent {
                    rec_id,
                    target_global_idx: active_copies[idx].first_global_idx,
                    end_global_idx: global_idx,
                    cpu: active_copies[idx].cpu,
                    insn_count: active_copies[idx].first_insn_count,
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
                        pot_copy.insn_count = mem_access.insn_count;
                        pot_copy.associated_indices.push(global_idx);
                        pot_copy.associated_records.push(mem_access.clone());
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
                let mut records = Vec::new();
                records.push(mem_access.clone());
                potential_copies.push(MemCpy {
                    rec_id: copy.rec_id,
                    insn_count: mem_access.insn_count,
                    from: mem_access.address,
                    to,
                    cpu: copy.cpu as usize,
                    size: copy.size,
                    current_from: mem_access.address + (1 << mem_access.size),
                    current_to: to,
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

fn analyze_copies_only<W: Write>(
    baseline_history: Vec<log_parser::LogRecord>,
    mut copy_logs: impl Iterator<Item = io::Result<String>>,
    copy_window: &mut Vec<KernelRecord>,
    mut analysis_output: Option<&mut BufWriter<W>>,
) {
    let mut active_copies: Vec<MemCpy> = vec![];
    let mut rowclone_events: Vec<RowcloneEvent> = vec![];
    let mut mem_accesses = LookaheadIterator::new(baseline_history.iter());
    let mut current_global_idx = 0;

    while let Some(mem_access) = mem_accesses.next() {
       if track_active_copies(
            &mem_access,
            &mut active_copies,
            current_global_idx,
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

    let mut total_removed_accesses = 0;
    let final_rowclones = rowclone_events.len();

    // Exportation exclusive vers le fichier d'analyse
    if let Some(ref mut analysis_writer) = analysis_output {
        for event in &rowclone_events {
            total_removed_accesses += event.removed_accesses_count;
            writeln!(analysis_writer, "=============================================================").unwrap();
            writeln!(analysis_writer, "ROWCOPY DETECTE - ID Rec: {} | CPU: {}", event.rec_id, event.cpu).unwrap();
            writeln!(analysis_writer, "Source (From): 0x{:016x} -> Destination (To): 0x{:016x}", event.from, event.to).unwrap();
            writeln!(analysis_writer, "Nombre d'accès intercepte: {}", event.removed_accesses_count).unwrap();
            writeln!(analysis_writer, "-------------------------------------------------------------").unwrap();
            for (local_idx, rec) in event.records.iter().enumerate() {
                writeln!(
                    analysis_writer,
                    "  [{local_idx}] CPU: {} | INSN: {} | ADDR: 0x{:016x} | TYPE: {} | SIZE: 2^{}",
                    rec.cpu,
                    rec.insn_count,
                    rec.address,
                    if rec.store == 1 { "STORE" } else { "LOAD" },
                    rec.size
                ).unwrap();
            }
        }
    } else {
        // Si aucun fichier de dump n'est passé, on compte quand même
        for event in &rowclone_events {
            total_removed_accesses += event.removed_accesses_count;
        }
    }

    let average_removed = if final_rowclones > 0 {
        total_removed_accesses as f64 / final_rowclones as f64
    } else {
        0.0
    };

    eprintln!("================ STATS DE FILTRAGE DETECTEES ================");
    eprintln!("Rowclones complets valides              : {}", final_rowclones);
    eprintln!("Total LOAD/STORE supprimes de la trace : {}", total_removed_accesses);
    eprintln!("Moyenne LOAD/STORE supprimes par copie : {:.2}", average_removed);
    eprintln!("=============================================================");
    eprintln!("Rowclones uncompleted: {}", active_copies.len());
}

pub fn add_rowclone_info(
    mem_reader: BufReader<std::io::Stdin>,
    kernel_logfile: &str,
    analysis_output_file: Option<&str>,
) -> io::Result<()> {

    eprintln!("Passe 1 : Chargement de la trace mémoire...");
    let baseline_history: Vec<log_parser::LogRecord> = mem_reader
        .lines()
        .filter_map(|line| line.ok()?.parse::<log_parser::LogRecord>().ok())
        .collect();
    eprintln!("Trace chargée ({} accès).", baseline_history.len());

    let kernel_log = File::open(kernel_logfile)?;
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
    
    eprintln!("Passe 2 : Analyse microarchitecturale...");
    
    if let Some(ana_file_path) = analysis_output_file {
        let ana_file = File::create(ana_file_path)?;
        let mut ana_writer = BufWriter::new(ana_file);
        analyze_copies_only(baseline_history, lines, &mut copy_window, Some(&mut ana_writer));
        let _ = ana_writer.flush();
    } else {
        analyze_copies_only::<File>(baseline_history, lines, &mut copy_window, None);
    }

    eprintln!("Unmatched Rowclones: {}", copy_window.len());
    Ok(())
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    kernel_logfile: String,

    #[arg(short, long)] // Rend le fichier d'analyse obligatoire pour récupérer le debug complet
    analysis_file: Option<String>,
}

fn main() {
    let args = Args::parse();
    let reader = BufReader::new(io::stdin());
    
    if add_rowclone_info(reader, &args.kernel_logfile, args.analysis_file.as_deref()).is_ok() {
        eprintln!("Analysis pipeline completed successfully.");
    } else {
        eprintln!("Error running analysis pipeline");
    }
}