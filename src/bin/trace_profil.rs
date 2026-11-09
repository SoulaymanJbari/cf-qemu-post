use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use cf_qemu_post::log_parser::{LogParser, LogRecord};
use clap::Parser;
use rayon::prelude::*;

const COPY_WINDOW: usize = 200;
const COPY_WINDOW_STALE_TRESHOLD: usize = 20;

// Taille minimale d'un cluster en nombre de copies
const MIN_CLUSTER_COPIES: usize = 10;

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

#[derive(Clone, Debug)]
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

struct CpuData {
    records: Vec<LogRecord>,
    events: Vec<RowcloneEvent>,
}

#[derive(Default)]
struct Ttbr0Stats {
    total_accesses: usize,
    loads: usize,
    stores: usize,
    rowclones: usize,
    first_insn: u64,
    last_insn: u64,
    cpus: BTreeSet<u8>,
}

fn display_ttbr0_statistics(cpu_data_list: &[CpuData]) {
    let mut stats_map: HashMap<u64, Ttbr0Stats> = HashMap::new();

    for data in cpu_data_list {
        for rec in &data.records {
            let ttbr0 = (rec.ttbr0_pfn as u64) << 12;
            let entry = stats_map.entry(ttbr0).or_insert_with(|| Ttbr0Stats {
                first_insn: rec.insn_count,
                last_insn: rec.insn_count,
                ..Default::default()
            });

            entry.total_accesses += 1;
            if rec.store == 1 {
                entry.stores += 1;
            } else {
                entry.loads += 1;
            }

            entry.last_insn = entry.last_insn.max(rec.insn_count);
            entry.first_insn = entry.first_insn.min(rec.insn_count);
            entry.cpus.insert(rec.cpu as u8);
        }

        for ev in &data.events {
            if let Some(entry) = stats_map.get_mut(&ev.ttbr0) {
                entry.rowclones += 1;
            }
        }
    }

    let grand_total_accesses: usize = stats_map.values().map(|s| s.total_accesses).sum();
    let grand_total_rc: usize = stats_map.values().map(|s| s.rowclones).sum();

    let mut sorted_stats: Vec<(u64, Ttbr0Stats)> = stats_map.into_iter().collect();
    sorted_stats.sort_by(|a, b| b.1.total_accesses.cmp(&a.1.total_accesses));

    println!("\n#################################################################################################################################");
    println!("                                      PROFILAGE PAR PROCESSUS (TTBR0_EL1)");
    println!("#################################################################################################################################");
    println!(
        "{:<18} | {:<12} | {:<8} | {:<12} | {:<12} | {:<10} | {:<10} | {:<10}",
        "TTBR0 Physique", "Accès Totaux", "% Trace", "LOADs", "STOREs", "RowClones", "% RC", "CPUs Vus"
    );
    println!("{:-<129}", "");

    for (ttbr0, s) in &sorted_stats {
        let pct_trace = (s.total_accesses as f64 * 100.0) / (grand_total_accesses.max(1) as f64);
        let pct_rc = (s.rowclones as f64 * 100.0) / (grand_total_rc.max(1) as f64);
        let cpus_vec: Vec<u8> = s.cpus.iter().copied().collect();
        let cpus_str = format!("{:?}", cpus_vec);

        println!(
            "0x{:016x} | {:>12} | {:>7.2}% | {:>12} | {:>12} | {:>10} | {:>9.1}% | {:<10}",
            ttbr0,
            s.total_accesses,
            pct_trace,
            s.loads,
            s.stores,
            s.rowclones,
            pct_rc,
            cpus_str
        );
    }
    println!("#################################################################################################################################\n");
}

#[derive(Clone, Debug)]
struct ClusterResult {
    max_gap_threshold: usize,
    total_clusters: usize,
    clones_in_clusters: usize,
    avg_cluster_size: f64,
    avg_intra_cluster_gap_acc: f64,
    avg_intra_cluster_gap_insn: f64,
    max_cluster_size: usize,
    total_retained_insns: u64,
    total_retained_accesses: usize,
}

fn evaluate_clustering(cpu_data_list: &[CpuData], max_gap: usize, min_copies: usize) -> ClusterResult {
    let mut total_clusters = 0usize;
    let mut clones_in_clusters = 0usize;
    let mut intra_cluster_gaps_acc = Vec::new();
    let mut intra_cluster_gaps_insn = Vec::new();
    let mut max_cluster_size = 0usize;

    let mut total_retained_insns = 0u64;
    let mut total_retained_accesses = 0usize;

    for data in cpu_data_list {
        if data.events.is_empty() {
            continue;
        }

        let mut current_cluster: Vec<RowcloneEvent> = vec![data.events[0].clone()];
        let mut cpu_cluster_spans: Vec<(usize, usize)> = Vec::new();

        for w in data.events.windows(2) {
            let acc_gap = w[1].target_global_idx.saturating_sub(w[0].end_global_idx);
            let insn_gap = w[1].insn_count.saturating_sub(w[0].end_insn_count);

            if acc_gap <= max_gap {
                current_cluster.push(w[1].clone());
            } else {
                if current_cluster.len() >= min_copies {
                    total_clusters += 1;
                    clones_in_clusters += current_cluster.len();
                    max_cluster_size = max_cluster_size.max(current_cluster.len());

                    for win in current_cluster.windows(2) {
                        intra_cluster_gaps_acc.push(win[1].target_global_idx.saturating_sub(win[0].end_global_idx));
                        intra_cluster_gaps_insn.push(win[1].insn_count.saturating_sub(win[0].end_insn_count));
                    }

                    let s_idx = current_cluster.first().unwrap().target_global_idx;
                    let e_idx = current_cluster.last().unwrap().end_global_idx;
                    cpu_cluster_spans.push((s_idx, e_idx));
                }
                current_cluster.clear();
                current_cluster.push(w[1].clone());
            }
        }

        if current_cluster.len() >= min_copies {
            total_clusters += 1;
            clones_in_clusters += current_cluster.len();
            max_cluster_size = max_cluster_size.max(current_cluster.len());

            for win in current_cluster.windows(2) {
                intra_cluster_gaps_acc.push(win[1].target_global_idx.saturating_sub(win[0].end_global_idx));
                intra_cluster_gaps_insn.push(win[1].insn_count.saturating_sub(win[0].end_insn_count));
            }

            let s_idx = current_cluster.first().unwrap().target_global_idx;
            let e_idx = current_cluster.last().unwrap().end_global_idx;
            cpu_cluster_spans.push((s_idx, e_idx));
        }

        for (s, e) in cpu_cluster_spans {
            let acc_count = e.saturating_sub(s) + 1;
            let insn_count = data.records[e].insn_count.saturating_sub(data.records[s].insn_count);
            total_retained_accesses += acc_count;
            total_retained_insns += insn_count;
        }
    }

    let avg_cluster_size = if total_clusters > 0 {
        clones_in_clusters as f64 / total_clusters as f64
    } else {
        0.0
    };

    let avg_gap_acc = if !intra_cluster_gaps_acc.is_empty() {
        intra_cluster_gaps_acc.iter().sum::<usize>() as f64 / intra_cluster_gaps_acc.len() as f64
    } else {
        0.0
    };

    let avg_gap_insn = if !intra_cluster_gaps_insn.is_empty() {
        intra_cluster_gaps_insn.iter().sum::<u64>() as f64 / intra_cluster_gaps_insn.len() as f64
    } else {
        0.0
    };

    ClusterResult {
        max_gap_threshold: max_gap,
        total_clusters,
        clones_in_clusters,
        avg_cluster_size,
        avg_intra_cluster_gap_acc: avg_gap_acc,
        avg_intra_cluster_gap_insn: avg_gap_insn,
        max_cluster_size,
        total_retained_insns,
        total_retained_accesses,
    }
}

#[derive(Parser, Debug)]
#[command(about = "Optimisation du clustering RowClone avec grille de seuils étendue")]
struct Args {
    #[arg(short, long)]
    log_dir: String,

    #[arg(short, long)]
    kernel_logfile: String,

    /// Seuil minimum de copies par cluster (défaut: 10)
    #[arg(long, default_value_t = MIN_CLUSTER_COPIES)]
    min_copies: usize,

    /// Tester un écart personnalisé spécifique
    #[arg(long)]
    custom_gap: Option<usize>,
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 * 100.0) / (total as f64)
    }
}

fn pct_u64(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 * 100.0) / (total as f64)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    eprintln!("Indexation du journal noyau : {}", args.kernel_logfile);
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
    eprintln!("Extraction des traces et copies RowClone sur {} fichiers...", trace_files.len());

    let cpu_data_list: Vec<CpuData> = trace_files
        .par_iter()
        .filter_map(|trace_path| {
            let mut parser = LogParser::new(trace_path.to_str().unwrap()).ok()?;
            let mut records = Vec::new();
            while let Some(Ok(rec)) = parser.next() {
                records.push(rec);
            }
            if records.is_empty() {
                return None;
            }
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
            Some(CpuData {
                records,
                events: rowclone_events,
            })
        })
        .collect();

    let total_rc: usize = cpu_data_list.iter().map(|d| d.events.len()).sum();
    let total_raw_insns: u64 = cpu_data_list.iter().map(|d| {
        let first = d.records.first().map_or(0, |r| r.insn_count);
        let last = d.records.last().map_or(0, |r| r.insn_count);
        last.saturating_sub(first)
    }).sum();
    let total_raw_accesses: usize = cpu_data_list.iter().map(|d| d.records.len()).sum();

    println!("\n==========================================================================================");
    println!(
        " TRACE BRUTE : {} accès | {} instructions | {} RowClones détectés",
        total_raw_accesses, total_raw_insns, total_rc
    );
    println!(" FILTRAGE : Seuls les clusters contenant au moins {} copies sont retenus", args.min_copies);
    println!("==========================================================================================");

    // Profilage global par TTBR0
    display_ttbr0_statistics(&cpu_data_list);

    if total_rc < args.min_copies {
        println!("Nombre insuffisant de copies pour former un cluster de taille >= {}.", args.min_copies);
        return Ok(());
    }

    // Grille de seuils enrichie : résolution fine (5k - 20k) + seuils macroscopiques (jusqu'à 1M)
    let mut candidate_gaps = vec![
        1_000, 2_000, 3_000, 4_000, 5_000, 6_000, 7_500, 8_500, 10_000,
        12_500, 15_000, 20_000, 25_000, 30_000, 40_000, 50_000, 75_000,
        100_000, 150_000, 200_000, 500_000, 1_000_000, 2_000_000, 5_000_000, 10_000_000
    ];

    if let Some(custom) = args.custom_gap {
        if !candidate_gaps.contains(&custom) {
            candidate_gaps.push(custom);
            candidate_gaps.sort_unstable();
        }
    }

    let min_c = args.min_copies;
    let results: Vec<ClusterResult> = candidate_gaps
        .iter()
        .map(|&gap| evaluate_clustering(&cpu_data_list, gap, min_c))
        .collect();

    println!("\n#################################################################################################################################################################");
    println!("                        BALAYAGE DES SEUILS : CLUSTERS D'AU MOINS {} COPIES (NOMBRE D'INSTRUCTIONS ET VOLUMES)", min_c);
    println!("#################################################################################################################################################################");
    println!(
        "{:<9} | {:<9} | {:<12} | {:<10} | {:<16} | {:<15} | {:<15} | {:<22} | {:<16}",
        "Seuil Gap", "Nb Clust.", "Taille Moy.", "Taille Max", "Copies Couvertes", "Écart Moy. Acc.", "Écart Moy. Insn", "Instructions Gardées", "Accès Gardés"
    );
    println!("{:-<161}", "");

    for r in &results {
        println!(
            "{:>8}  | {:>9}  | {:>10.1}   | {:>10} | {:>6}/{} ({:>5.1}%) | {:>15.1} | {:>15.1} | {:>12} ({:>5.2}%) | {:>9} ({:>5.2}%)",
            r.max_gap_threshold,
            r.total_clusters,
            r.avg_cluster_size,
            r.max_cluster_size,
            r.clones_in_clusters,
            total_rc,
            pct(r.clones_in_clusters, total_rc),
            r.avg_intra_cluster_gap_acc,
            r.avg_intra_cluster_gap_insn,
            r.total_retained_insns,
            pct_u64(r.total_retained_insns, total_raw_insns),
            r.total_retained_accesses,
            pct(r.total_retained_accesses, total_raw_accesses),
        );
    }
    println!("#################################################################################################################################################################\n");

    Ok(())
}