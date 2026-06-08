use clap::{Parser, command};
use once_cell::sync::Lazy;
use regex::Regex;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug)]
struct Stats {
    total: usize,
    not4kb: usize,
    notaligned: usize,
    not_same_subarray: usize,
    rowclone: usize,
}

struct KernelRecord {
    size: u64,
    operation: char,
    kernel_address: u64,
    user_address: u64,
}

static KERNEL_LOG_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"N=([^,]+),([rw]),(\d+),(\d+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)"#).expect("failed to compile regex")
});

fn parse_hex_address(hex_str: &str) -> Option<u64> {
    u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).ok()
}

fn parse_kernel_line(line: &str) -> Option<KernelRecord> {
    if let Some(caps) = KERNEL_LOG_PATTERN.captures(line) {
        Some(KernelRecord {
            size: caps[4].parse().ok()?,
            operation: caps[2].chars().next()?,
            kernel_address: parse_hex_address(&caps[6])?,
            user_address: parse_hex_address(&caps[8])?,
        })
    } else {
        None
    }
}

fn address_in_same_subarray(a: u64, b: u64) -> bool {
    let subarray_mask = 0x7F; // 7 bits
    let subarray_lsb = 21;
    let a_subarray = (a >> subarray_lsb) & subarray_mask;
    let b_subarray = (b >> subarray_lsb) & subarray_mask;

    a_subarray == b_subarray
}

fn filter_non_rowclone(record: KernelRecord, stats: &mut Stats) {
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
    }
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long)]
    kernel_logfile: String,
}

fn main() -> io::Result<()> {
    let args = Args::parse();
    
    let mut stats = Stats {
        total: 0,
        not4kb: 0,
        notaligned: 0,
        not_same_subarray: 0,
        rowclone: 0,
    };

    let kernel_log = File::open(&args.kernel_logfile)?;
    let reader = BufReader::new(kernel_log);

    for line in reader.lines() {
        let line = line?;
        if let Some(record) = parse_kernel_line(&line) {
            filter_non_rowclone(record, &mut stats);
        }
    }

    // Afficher uniquement la structure Stats comme demandé
    println!("{:#?}", stats);
    Ok(())
}
