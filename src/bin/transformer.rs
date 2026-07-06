use std::{
    io::{BufRead, BufReader, BufWriter, Write},
    str::FromStr,
};

use cf_qemu_post::{
    log_parser::{self},
    memory_access::{MemRecord, MemoryAccess},
};
use clap::Parser;

fn parse_rowclone_record(line: &str) -> Result<MemoryAccess, Box<dyn std::error::Error>> {
    MemoryAccess::from_str(line)
}

fn parse_binary_record(line: &str) -> Result<MemoryAccess, Box<dyn std::error::Error>> {
    let access = log_parser::LogRecord::from_str(line)?;
    Ok(MemoryAccess::Regular(MemRecord {
        cpu: access.cpu.into(),
        address: access.address,
        insn_count: access.insn_count,
        store: access.store == 1,
    }))
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    #[arg(short, long, default_value_t = false)]
    binary_in: bool,
    #[arg(short, long, default_value_t = 8)]
    cpus: usize,

    #[arg(short, long)]
    log_dir: String,
}

fn ramulator_mem_format(rec: &MemRecord, prev_insn_count: &u64) -> String {
    let bubble = if rec.insn_count < *prev_insn_count {
        0
    } else {
        rec.insn_count - prev_insn_count
    };
    if rec.store {
        format!("{} -1 0x{:016x}", bubble, rec.address)
    } else {
        format!("{} 0x{:016x}", bubble, rec.address)
    }
}

fn main() {
    let args = Args::parse();
    let reader = BufReader::new(std::io::stdin()); 
    let mut writers: Vec<BufWriter<std::fs::File>> = (0..args.cpus)
        .map(|cpu_id| {
            let filename = format!("{}/cpu_{}.trace", args.log_dir, cpu_id);
            let file = std::fs::File::create(&filename)
                .unwrap_or_else(|_| panic!("Failed to create output file: {}", filename));
            BufWriter::new(file)
        })
        .collect();
        
    let input_parser = if args.binary_in {
        parse_binary_record
    } else {
        parse_rowclone_record
    };

    let mut lines = reader.lines();
    let mut first = vec![true; args.cpus];
    let mut prev_insn_count = vec![0; args.cpus];

    while let Some(Ok(line)) = lines.next() {
        if let Ok(rec) = input_parser(&line) {
            match rec {
                MemoryAccess::Regular(mem) => {
                    let cpu = mem.cpu;
                    if first[cpu] {
                        prev_insn_count[cpu] = mem.insn_count;
                        first[cpu] = false;
                    }                
                    let _ = writeln!(
                        writers[cpu],
                        "{}",
                        ramulator_mem_format(&mem, &prev_insn_count[cpu])
                    );
                    
                    prev_insn_count[cpu] = mem.insn_count;
                }
                MemoryAccess::Rowclone(rc) => {
                    let cpu = rc.cpu;
                    if first[cpu] {
                        prev_insn_count[cpu] = rc.insn_count;
                        first[cpu] = false;
                    }                
                    let _ = writeln!(
                        writers[cpu],
                        "{} 0x{:016x} 0x{:016x}",
                        rc.insn_count - prev_insn_count[cpu],
                        rc.from,
                        rc.to,
                    );
                    
                    prev_insn_count[cpu] = rc.insn_count;
                }
            }
        }
    }
}