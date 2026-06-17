use cf_qemu_post::log_parser;
use cf_qemu_post::lookahead_iter::LookaheadIterator;
use cf_qemu_post::memory_access::{MemRecord, MemoryAccess, RowcloneRecord};
use clap::{Parser, command};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};

const COPY_WINDOW: usize = 200;
const COPY_WINDOW_STALE_THRESHOLD: usize = 20;
const COPY_CONFIDENCE_THRESHOLD: u64 = 128;
const COPY_CONFIDENCE_WINDOW: usize = 200000;

static NEXT_KERNEL_REC_ID: AtomicU64 = AtomicU64::new(0);

struct KernelRecord {
    rec_id: u64,
    command: String,
    cpu: u32,
    size: u64,
    operation: char,
    kernel_address: u64,
    user_address: u64,
    stale: usize,
}

type AddrMap<T> = HashMap<u64, Vec<T>>;

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

fn page_number(address: u64) -> u64 {
    address & !0xFFF
}

fn mem_copy_match(mem_access: &log_parser::LogRecord, copy: &MemCpy) -> bool {
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
) -> bool {
    let access_size_bytes = 1 << mem_access.size;
    let copy = &mut copies[copy_idx];
    if mem_access.store == 1 {
        copy.current_to += access_size_bytes;
    } else {
        copy.current_from += access_size_bytes;
    }
    copy.insn_count = mem_access.insn_count;
    copy.cpu = mem_access.cpu as usize;
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

fn push_ongoing_copy(
    ongoing_copies: &mut Vec<MemCpy>,
    potential_copies: &mut Vec<MemCpy>,
    idx: usize,
) {
    let copy = potential_copies.remove(idx);
    ongoing_copies.push(copy);
}

fn print_rowclone(copy: &MemCpy, output: &mut BufWriter<std::io::Stdout>) {
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

fn print_regular_access(
    mem_access: &log_parser::LogRecord,
    output: &mut BufWriter<std::io::Stdout>,
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

fn part_of_ongoing_copy(
    mem_access: &log_parser::LogRecord,
    ongoing_copies: &mut Vec<MemCpy>,
) -> bool {
    for (idx, copy) in ongoing_copies.iter().enumerate() {
        if mem_copy_match(mem_access, copy) {
            let done = update_copy(ongoing_copies, idx, &mem_access);
            if done {
                ongoing_copies.remove(idx);
            }
            return true;
        }
    }
    false
}

fn copy_matched(potential_copies: &Vec<MemCpy>, idx: usize) -> bool {
    let copy = &potential_copies[idx];
    (copy.current_to - copy.to) > COPY_CONFIDENCE_THRESHOLD
        && (copy.current_from - copy.from) > COPY_CONFIDENCE_THRESHOLD
}
fn part_of_potential_copy(
    mem_access: &log_parser::LogRecord,
    potential_copies: &mut Vec<MemCpy>,
    ongoing_copies: &mut Vec<MemCpy>,
    rowclones: &mut usize,
    copy_window: &mut Vec<KernelRecord>,
    copy_logs: &mut impl Iterator<Item = io::Result<String>>,
    output: &mut BufWriter<std::io::Stdout>,
) -> bool {
    let mut potential_copy = false;
    let mut matches: Vec<usize> = vec![];
    for (idx, copy) in potential_copies.iter().enumerate() {
        if mem_copy_match(mem_access, copy) {
            potential_copy = true;
            matches.push(idx);
        }
    }
    for idx in matches.iter().rev() {
        let done = update_copy(potential_copies, *idx, &mem_access);
        if done {
            eprintln!("new rowclone");
            *rowclones += 1;
            let rec_id = potential_copies[*idx].rec_id;
            copy_window.retain(|i| i.rec_id != rec_id);
            remove_stale_copies(rec_id, copy_window, copy_logs);
            print_rowclone(&potential_copies[*idx], output);
            potential_copies.remove(*idx);
        } else if copy_matched(potential_copies, *idx) {
            eprintln!("new rowclone");
            *rowclones += 1;
            let rec_id = potential_copies[*idx].rec_id;
            copy_window.retain(|i| i.rec_id != rec_id);
            remove_stale_copies(rec_id, copy_window, copy_logs);
            print_rowclone(&potential_copies[*idx], output);
            push_ongoing_copy(ongoing_copies, potential_copies, *idx);
        }
    }
    potential_copy
}

fn check_potential_copy_start(
    mem_access: &log_parser::LogRecord,
    copy_window: &Vec<KernelRecord>,
    potential_copies: &mut Vec<MemCpy>,
) -> bool {
    let mut potential_copy = false;

    for copy in copy_window {
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
                potential_copies.push(MemCpy {
                    rec_id: copy.rec_id,
                    insn_count: mem_access.insn_count,
                    from: mem_access.address,
                    to,
                    cpu: mem_access.cpu as usize,
                    size: copy.size,
                    current_from: mem_access.address + (1 << mem_access.size),
                    current_to: to,
                });
                potential_copy = true;
            }
        }
    }
    potential_copy
}

fn match_copy_to_mem_accesses(
    mem_reader: BufReader<std::io::Stdin>,
    mut copy_logs: impl Iterator<Item = io::Result<String>>,
    copy_window: &mut Vec<KernelRecord>,
    output: &mut BufWriter<std::io::Stdout>,
) {
    let mut ongoing_copies: Vec<MemCpy> = vec![];
    let mut potential_copies: Vec<MemCpy> = vec![];
    let mut mem_accesses = LookaheadIterator::new(
        mem_reader
            .lines()
            .filter_map(|line| line.ok()?.parse::<log_parser::LogRecord>().ok()),
    );
    let mut rowclones = 0;
    while let Some(mem_access) = mem_accesses.next() {
        if part_of_ongoing_copy(&mem_access, &mut ongoing_copies) {
            continue;
        } else if part_of_potential_copy(
            &mem_access,
            &mut potential_copies,
            &mut ongoing_copies,
            &mut rowclones,
            copy_window,
            &mut copy_logs,
            output,
        ) {
            continue;
        } else if check_potential_copy_start(&mem_access, &copy_window, &mut potential_copies) {
            continue;
        }

        print_regular_access(&mem_access, output);
    }

    eprintln!("Rowclones matched: {}", rowclones);
    eprintln!("Potential copies: {}", potential_copies.len());
    eprintln!("Unfinished copies: {}", ongoing_copies.len());
}

pub fn add_rowclone_info(
    mem_reader: BufReader<std::io::Stdin>,
    kernel_logfile: &str,
) -> io::Result<()> {

    let kernel_log = File::open(kernel_logfile)?;
    let mut writer = BufWriter::new(std::io::stdout());
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

    match_copy_to_mem_accesses(mem_reader, lines, &mut copy_window, &mut writer);

    eprintln!("Unmatched Rowclones: {}", copy_window.len());
    let _ = writer.flush();
    Ok(())
}
#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    kernel_logfile: String,
}

fn main() {
    let args = Args::parse();
    let reader = BufReader::new(std::io::stdin());
    if add_rowclone_info(reader, &args.kernel_logfile).is_ok() {
        eprintln!("Finished adding rowclone info");
    } else {
        eprintln!("Error adding rowclone info");
    }
}
