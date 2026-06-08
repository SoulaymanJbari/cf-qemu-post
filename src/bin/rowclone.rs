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
const COPY_WINDOW_STALE_THRESHOLD: usize = 20; // if 10 newer logs have been matched expect no more matches
// for this one
const COPY_CONFIDENCE_THRESHOLD: u64 = 128; // how many bytes worth of matching of loads AND stores we should see 
// TODO: [yb] make confidence threshold dependent on
// transfer size
// TODO: [yb] this is too large, optimize, by perhaps keeping track of all copy begins in a vec and loop through whole
// file once after that
const COPY_CONFIDENCE_WINDOW: usize = 200000; // in the next COPY_CONFIDENCE_WINDOW accesses

static NEXT_KERNEL_REC_ID: AtomicU64 = AtomicU64::new(0);

// need ongoing copy operations.
// when a new memory access matches a beginning address of a read/write in the current window ->
// check next N memory accesses to decide whether it is the beginning of the copy -> add to ongoing
// memory operations
// check new memory record whether it matches any of the ongoing copy operations, skip it if yes
// if determined to be not a start of a memory region nor belong to an ongoing one just print it as
// a regular load/store
//

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
    Regex::new(r#"N=([^,]+),([rw]),(\d+),(\d+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)"#).expect("failed to compile regex")
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
    // Remove the "0x" prefix and parse as a base 16 number
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn parse_kernel_line(line: &str) -> Option<KernelRecord> {
    // Regular expression to capture the CSV-like part of the log line
    if let Some(caps) = KERNEL_LOG_PATTERN.captures(line) {
        Some(KernelRecord {
            rec_id: NEXT_KERNEL_REC_ID.fetch_add(1, Ordering::Relaxed),
            command: caps[1].to_string(),
            cpu: caps[3].parse().ok()?,
            size: caps[4].parse().ok()?,
            operation: caps[2].chars().next()?,
            kernel_address: parse_hex_address(&caps[6])?,
            user_address: parse_hex_address(&caps[8])?,
            stale: 0,
        })
    } else {
        eprintln!("Failed to parse kernel line: {}", line);
        None
    }
}

fn address_in_same_subarray(a: u64, b: u64) -> bool {
    let subarray_mask = 0x7F; // 7 bits
    let subarray_lsb = 21;
    let a_subarray = (a >> subarray_lsb) & subarray_mask;
    let b_subarray = (b >> subarray_lsb) & subarray_mask;

    return a_subarray == b_subarray;
}

fn page_number(address: u64) -> u64 {
    address & !0xFFF
}

fn mem_copy_match(mem_access: &log_parser::LogRecord, copy: &MemCpy) -> bool {
    // TODO: [yb] make this somewhat fuzzy in case a mem access is missed occasionally..
    (copy.current_from == mem_access.address && mem_access.store == 0)
        || (copy.current_to == mem_access.address && mem_access.store == 1)
}

fn copy_done(copy: &MemCpy) -> bool {
    // TODO: [yb] handle multi page copies
    copy.current_to >= copy.to + copy.size
}

fn update_copy(
    copies: &mut Vec<MemCpy>,
    copy_idx: usize,
    mem_access: &log_parser::LogRecord,
) -> bool {
    // mem_access.size is in shifts (0 = 1 byte, 1 = 2 bytes,...)
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

#[derive(Debug)]
struct Stats {
    total: usize,
    not4kb: usize,
    notaligned: usize,
    not_same_subarray: usize,
    rowclone: usize,
}

fn filter_non_rowclone(record: KernelRecord, stats: &mut Stats) -> Option<KernelRecord> {
    const PAGE_SIZE: u64 = 4096;
    stats.total += 1;
    if record.size != PAGE_SIZE {
        stats.not4kb += 1;
    } else if (record.user_address & (PAGE_SIZE - 1)) != 0 {
        stats.notaligned += 1;
    } else if !address_in_same_subarray(record.user_address, record.kernel_address) {
        stats.not_same_subarray += 1;
    } else {
        stats.rowclone += 1;
        return Some(record);
    }
    None
}

fn next_kernel_line(
    lines: &mut impl Iterator<Item = io::Result<String>>,
    stats: &mut Stats,
) -> Option<KernelRecord> {
    while let Some(Ok(line)) = lines.next() {
        if let Some(record) = parse_kernel_line(&line) {
            if let Some(record) = filter_non_rowclone(record, stats) {
                return Some(record);
            }
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
    stats: &mut Stats,
) {
    update_stale(rec_id, copy_window);
    copy_window.retain(|copy| copy.stale <= COPY_WINDOW_STALE_THRESHOLD);

    while copy_window.len() < COPY_WINDOW {
        if let Some(line) = next_kernel_line(copy_logs, stats) {
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
    stats: &mut Stats,
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
            remove_stale_copies(rec_id, copy_window, copy_logs, stats);
            print_rowclone(&potential_copies[*idx], output);
            potential_copies.remove(*idx);
        } else if copy_matched(potential_copies, *idx) {
            eprintln!("new rowclone");
            *rowclones += 1;
            let rec_id = potential_copies[*idx].rec_id;
            copy_window.retain(|i| i.rec_id != rec_id);
            remove_stale_copies(rec_id, copy_window, copy_logs, stats);
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
                // kernel to user copy
                mem_access.store == 0 && copy.kernel_address == mem_access.address
            }
            'w' => {
                //user to kernel copy
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
                    // TODO: [yb] print previous potential copy
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
    stats: &mut Stats,
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
        // TODO: [yb] potentially run accesses through cache here immediately (avoiding
        // intermediate file)
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
            stats,
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
    let mut stats = Stats {
        total: 0,
        not4kb: 0,
        notaligned: 0,
        not_same_subarray: 0,
        rowclone: 0,
    };

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
        .filter_map(|record| filter_non_rowclone(record, &mut stats))
        .take(COPY_WINDOW)
        .collect();

    match_copy_to_mem_accesses(mem_reader, lines, &mut copy_window, &mut writer, &mut stats);

    eprintln!("Unmatched Rowclones: {}", copy_window.len());
    eprintln!("{:#?}", stats);
    let _ = writer.flush();
    Ok(())
}
#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    // Whether the input logs are in binary format
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
