use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use cf_qemu_post::log_parser::{LogParser, LogRecord};
use clap::Parser;
use rayon::prelude::*;

const PAGE_SHIFT: u64 = 12;
const CACHELINE_MASK: u64 = !0x3F;
const SPIN_MAX_DELTA_INSN: u64 = 16;
const SPIN_MIN_REPEATS: usize = 3;
const STACK_MAX_STRIDE: i64 = 128;

// 20% de 12 Go = 2.4 Go (0x99999999)
const TOTAL_RAM_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const SPLIT_20_80_ADDR: u64 = TOTAL_RAM_BYTES / 5;

// Seuil de fréquence pour identifier un "Heartbeat / Polling flag" pur en lecture seule
// Plus de 0.5% du trafic global du CPU en LOADs purs sans STOREs
const POLLING_HOTSPOT_SHARE_THRESHOLD: f64 = 0.005;

#[derive(Parser, Debug)]
#[command(about = "Profilage et simulation du nettoyage chirurgical de la trace mémoire QEMU")]
struct Args {
    /// Dossier contenant les fichiers de traces (log.txt*)
    #[arg(short, long)]
    log_dir: String,
}

#[derive(Default, Clone)]
struct CpuProfile {
    cpu_id: u8,
    total_accesses: usize,
    loads: usize,
    stores: usize,

    first_insn: u64,
    last_insn: u64,
    deadbeef_count: usize,

    // Origine des LOAD/STORE
    spin_wait_loads: usize,
    spin_wasted_insns: u64,
    seq_stream_accesses: usize,
    stack_like_accesses: usize,
    pointer_chasing_accesses: usize,
    page_local_other: usize,

    // Répartition fixe sur 12 Go (Bas 20% < 2.4 Go vs Haut 80% >= 2.4 Go)
    low_ram_20pct_accesses: usize,
    high_ram_80pct_accesses: usize,

    // Détail de la simulation du nettoyage chirurgical :
    // 1. Kernel (< 2.4 Go)
    removed_kernel_low: usize,
    // 2. Spin-waiting compressé (on conserve 1 lecture de verrou, on supprime les tours suivants)
    removed_spin_collapsed: usize,
    // 3. Heartbeats / Polling pur en lecture seule
    removed_polling_heartbeats: usize,
    // 4. TLB Miss / DEADBEEF
    removed_deadbeef: usize,

    total_removed_accesses: usize,
    total_removed_insns: u64,

    // Métriques après nettoyage simulé
    cleaned_accesses: usize,
    cleaned_insns: u64,
    cleaned_seq_stream_accesses: usize,
    cleaned_stack_accesses: usize,
    cleaned_ptr_chasing: usize,

    // Top 5 Hotspots
    top_cachelines: Vec<(u64, usize, usize, usize)>,
}

impl CpuProfile {
    fn total_insns(&self) -> u64 {
        self.last_insn.saturating_sub(self.first_insn)
    }

    fn mpki_raw(&self) -> f64 {
        let insns = self.total_insns();
        if insns == 0 {
            0.0
        } else {
            (self.total_accesses as f64 * 1000.0) / (insns as f64)
        }
    }

    fn mpki_cleaned(&self) -> f64 {
        if self.cleaned_insns == 0 {
            0.0
        } else {
            (self.cleaned_accesses as f64 * 1000.0) / (self.cleaned_insns as f64)
        }
    }
}

fn profile_single_cpu_trace(trace_path: &Path) -> Result<Option<CpuProfile>, Box<dyn std::error::Error + Send + Sync>> {
    let mut parser = LogParser::new(trace_path.to_str().unwrap())?;
    let mut records: Vec<LogRecord> = Vec::new();

    while let Some(Ok(record)) = parser.next() {
        records.push(record);
    }

    if records.is_empty() {
        return Ok(None);
    }

    let mut prof = CpuProfile {
        cpu_id: records[0].cpu,
        total_accesses: records.len(),
        first_insn: records[0].insn_count,
        last_insn: records.last().unwrap().insn_count,
        ..Default::default()
    };

    // Passe 1 : Identifier la fréquence de chaque ligne de cache pour repérer les drapeaux de polling pur (Heartbeats)
    let mut cl_map: HashMap<u64, (usize, usize, usize)> = HashMap::with_capacity(65536);
    for rec in &records {
        if rec.address == 0xDEADBEEF {
            continue;
        }
        let cl_addr = rec.address & CACHELINE_MASK;
        let entry = cl_map.entry(cl_addr).or_insert((0, 0, 0));
        entry.0 += 1;
        if rec.store != 0 {
            entry.2 += 1;
        } else {
            entry.1 += 1;
        }
    }

    // Définition des lignes de cache "Heartbeats / Polling pur" :
    // Très fréquentes (> 0.5% du CPU) et 100% lectures seules (ex: table ou flag sondé en permanence par des démons)
    let heartbeat_threshold = ((records.len() as f64) * POLLING_HOTSPOT_SHARE_THRESHOLD) as usize;
    let heartbeat_cachelines: HashMap<u64, usize> = cl_map
        .iter()
        .filter(|(_, v)| v.0 >= heartbeat_threshold && v.2 == 0 && v.1 == v.0)
        .map(|(&addr, _)| (addr, 0))
        .collect();

    // Passe 2 : Profilage détaillé + Nettoyage chirurgical (Collapsing + Kernel + Polling)
    let mut prev_addr: u64 = 0;
    let mut prev_insn: u64 = records[0].insn_count;

    let mut recent_cl_window = [0u64; 4];
    let mut win_idx = 0usize;
    let mut current_spin_streak = 0usize;
    let mut streak_insns = 0u64;

    for (i, rec) in records.iter().enumerate() {
        let is_store = rec.store != 0;
        if is_store {
            prof.stores += 1;
        } else {
            prof.loads += 1;
        }

        let delta_insn = rec.insn_count.saturating_sub(prev_insn);

        if rec.address == 0xDEADBEEF {
            prof.deadbeef_count += 1;
            prof.removed_deadbeef += 1;
            prof.total_removed_accesses += 1;
            prof.total_removed_insns += delta_insn;
            prev_insn = rec.insn_count;
            continue;
        }

        let is_low_ram = rec.address < SPLIT_20_80_ADDR;
        if is_low_ram {
            prof.low_ram_20pct_accesses += 1;
        } else {
            prof.high_ram_80pct_accesses += 1;
        }

        let cl_addr = rec.address & CACHELINE_MASK;
        let stride = (rec.address as i128 - prev_addr as i128) as i64;
        let abs_stride = stride.saturating_abs();

        let in_recent_window = recent_cl_window.contains(&cl_addr);
        let mut is_redundant_spin_iteration = false;

        if !is_store && in_recent_window && delta_insn <= SPIN_MAX_DELTA_INSN && i > 0 {
            current_spin_streak += 1;
            streak_insns += delta_insn;

            if current_spin_streak == SPIN_MIN_REPEATS {
                prof.spin_wait_loads += SPIN_MIN_REPEATS;
                prof.spin_wasted_insns += streak_insns;
                // Collapsing : on préserve la 1re tentative de lecture légitime,
                // on ne supprime que les répétitions artificielles (les tours > 1)
                is_redundant_spin_iteration = true;
            } else if current_spin_streak > SPIN_MIN_REPEATS {
                prof.spin_wait_loads += 1;
                prof.spin_wasted_insns += delta_insn;
                is_redundant_spin_iteration = true;
            } else {
                prof.page_local_other += 1;
            }
        } else {
            current_spin_streak = 0;
            streak_insns = 0;

            if stride == 8 || stride == 16 || stride == 4 || stride == 64 {
                prof.seq_stream_accesses += 1;
            } else if abs_stride > 0 && abs_stride <= STACK_MAX_STRIDE {
                prof.stack_like_accesses += 1;
            } else if (rec.address >> PAGE_SHIFT) != (prev_addr >> PAGE_SHIFT) {
                prof.pointer_chasing_accesses += 1;
            } else {
                prof.page_local_other += 1;
            }
        }

        // --- RÈGLES DE NETTOYAGE CHIRURGICAL ---
        // Règle 1 : Bruit Kernel (< 2.4 Go) -> 100% interruptions et scheduler artificiels
        if is_low_ram {
            prof.removed_kernel_low += 1;
            prof.total_removed_accesses += 1;
            prof.total_removed_insns += delta_insn;
        }
        // Règle 2 : Spinlock Collapsing -> Suppression des tours de boucle redondants (>= 2e répétition)
        else if is_redundant_spin_iteration {
            prof.removed_spin_collapsed += 1;
            prof.total_removed_accesses += 1;
            prof.total_removed_insns += delta_insn;
        }
        // Règle 3 : Heartbeats de fond -> drapeaux 100% RO martelés par les démons système
        else if !is_store && heartbeat_cachelines.contains_key(&cl_addr) && delta_insn <= 32 {
            prof.removed_polling_heartbeats += 1;
            prof.total_removed_accesses += 1;
            prof.total_removed_insns += delta_insn;
        }
        // Accès conservé dans la trace épurée (Trafic applicatif réel)
        else {
            if stride == 8 || stride == 16 || stride == 4 || stride == 64 {
                prof.cleaned_seq_stream_accesses += 1;
            } else if abs_stride > 0 && abs_stride <= STACK_MAX_STRIDE {
                prof.cleaned_stack_accesses += 1;
            } else if (rec.address >> PAGE_SHIFT) != (prev_addr >> PAGE_SHIFT) {
                prof.cleaned_ptr_chasing += 1;
            }
        }

        recent_cl_window[win_idx] = cl_addr;
        win_idx = (win_idx + 1) % recent_cl_window.len();

        prev_addr = rec.address;
        prev_insn = rec.insn_count;
    }

    let total_categorized = prof.spin_wait_loads
        + prof.seq_stream_accesses
        + prof.stack_like_accesses
        + prof.pointer_chasing_accesses;
    let valid_total = prof.total_accesses.saturating_sub(prof.deadbeef_count);
    prof.page_local_other = valid_total.saturating_sub(total_categorized);

    prof.cleaned_accesses = prof.total_accesses.saturating_sub(prof.total_removed_accesses);
    prof.cleaned_insns = prof.total_insns().saturating_sub(prof.total_removed_insns);

    let mut cl_vec: Vec<(u64, usize, usize, usize)> = cl_map
        .into_iter()
        .map(|(addr, (tot, ld, st))| (addr, tot, ld, st))
        .collect();
    cl_vec.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    cl_vec.truncate(5);
    prof.top_cachelines = cl_vec;

    Ok(Some(prof))
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 * 100.0) / (total as f64)
    }
}

fn print_cpu_report(p: &CpuProfile) {
    let valid = p.total_accesses.saturating_sub(p.deadbeef_count).max(1);
    let tot_insns = p.total_insns();
    let wasted_insn_pct = if tot_insns > 0 {
        (p.spin_wasted_insns as f64 * 100.0) / (tot_insns as f64)
    } else {
        0.0
    };

    println!("==========================================================================================");
    println!(
        " [CPU {:>2}]  Accès: {:>12} | Instructions: {:>12} | Intensité brute: {:>6.2} MPKI",
        p.cpu_id, p.total_accesses, tot_insns, p.mpki_raw()
    );
    println!("==========================================================================================");
    println!(
        "  MIX R/W       : LOADs: {:>5.1}% ({}) | STOREs: {:>5.1}% ({})",
        pct(p.loads, p.total_accesses),
        p.loads,
        pct(p.stores, p.total_accesses),
        p.stores
    );
    println!(
        "  RAM (12 Go)   : Bas 20% (< 2.4 Go) = {:>5.1}% | Haut 80% (>= 2.4 Go) = {:>5.1}%",
        pct(p.low_ram_20pct_accesses, valid),
        pct(p.high_ram_80pct_accesses, valid)
    );
    println!("\n  ORIGINE DES ACCÈS :");
    println!(
        "  - Spin-Waiting (Verrous)   : {:>6.2}% ({:>10} accès) -> {:.1}% des instructions CPU",
        pct(p.spin_wait_loads, valid),
        p.spin_wait_loads,
        wasted_insn_pct
    );
    println!(
        "  - Séquentiels (Copies)     : {:>6.2}% ({:>10} accès)",
        pct(p.seq_stream_accesses, valid),
        p.seq_stream_accesses
    );
    println!(
        "  - Pile / Contexte (<128B)  : {:>6.2}% ({:>10} accès)",
        pct(p.stack_like_accesses, valid),
        p.stack_like_accesses
    );
    println!(
        "  - Sauts Inter-Pages (4K)   : {:>6.2}% ({:>10} accès)",
        pct(p.pointer_chasing_accesses, valid),
        p.pointer_chasing_accesses
    );
    println!(
        "  - Autres intra-page        : {:>6.2}% ({:>10} accès)",
        pct(p.page_local_other, valid),
        p.page_local_other
    );

    println!("\n  >>> SIMULATION DU NETTOYAGE CHIRURGICAL :");
    println!(
        "  - Parasites Kernel (<2.4G)      : {:>5.2}% ({:>10} accès) -> IRQs, ticks horloge, scheduler",
        pct(p.removed_kernel_low, p.total_accesses),
        p.removed_kernel_low
    );
    println!(
        "  - Spin-Waiting Effondré         : {:>5.2}% ({:>10} accès) -> Tours redondants de verrous MTTCG",
        pct(p.removed_spin_collapsed, p.total_accesses),
        p.removed_spin_collapsed
    );
    println!(
        "  - Heartbeats / Polling pur (RO) : {:>5.2}% ({:>10} accès) -> Sondages périodiques de démons",
        pct(p.removed_polling_heartbeats, p.total_accesses),
        p.removed_polling_heartbeats
    );
    println!(
        "  * TOTAL ACCÈS PURGÉS            : {:>5.2}% ({:>10} accès éliminés)",
        pct(p.total_removed_accesses, p.total_accesses),
        p.total_removed_accesses
    );
    println!(
        "  * TOTAL INSTRUCTIONS SOUSTRAITES: {:>5.2}% ({:>10} instructions compensées)",
        if tot_insns > 0 { (p.total_removed_insns as f64 * 100.0) / tot_insns as f64 } else { 0.0 },
        p.total_removed_insns
    );
    println!(
        "  * NOUVELLE DENSITÉ DE COPIES    : {:>5.2}% (était à {:.2}% dans la trace brute)",
        pct(p.cleaned_seq_stream_accesses, p.cleaned_accesses),
        pct(p.seq_stream_accesses, p.total_accesses)
    );
    println!(
        "  * NOUVEAU MPKI APPLICATIF       : {:.2} (était à {:.2})",
        p.mpki_cleaned(),
        p.mpki_raw()
    );

    println!("\n  TOP 5 HOTSPOTS (Lignes de cache 64B) :");
    for (addr, tot, ld, st) in &p.top_cachelines {
        println!(
            "  * 0x{:012x} : {:>9} accès ({:>5.2}%) [LD: {:>8}, ST: {:>8}]",
            addr,
            tot,
            pct(*tot, valid),
            ld,
            st
        );
    }
    println!();
}

fn print_global_summary(profiles: &[CpuProfile]) {
    if profiles.is_empty() {
        return;
    }

    let total_acc: usize = profiles.iter().map(|p| p.total_accesses).sum();
    let total_insns: u64 = profiles.iter().map(|p| p.total_insns()).sum();
    let total_removed_acc: usize = profiles.iter().map(|p| p.total_removed_accesses).sum();
    let total_removed_insns: u64 = profiles.iter().map(|p| p.total_removed_insns).sum();
    let total_rem_kernel: usize = profiles.iter().map(|p| p.removed_kernel_low).sum();
    let total_rem_spin: usize = profiles.iter().map(|p| p.removed_spin_collapsed).sum();
    let total_rem_heartbeat: usize = profiles.iter().map(|p| p.removed_polling_heartbeats).sum();
    let total_raw_seq: usize = profiles.iter().map(|p| p.seq_stream_accesses).sum();
    let total_clean_seq: usize = profiles.iter().map(|p| p.cleaned_seq_stream_accesses).sum();

    let cleaned_acc = total_acc.saturating_sub(total_removed_acc);
    let cleaned_insns = total_insns.saturating_sub(total_removed_insns);

    println!("##########################################################################################");
    println!("        SYNTHÈSE GLOBALE MULTI-CŒURS : NETTOYAGE CHIRURGICAL DU BRUIT ({} CPUs)", profiles.len());
    println!("##########################################################################################");
    println!("  TRACE BRUTE :");
    println!("  - Accès Mémoire Totaux        : {}", total_acc);
    println!("  - Instructions Totales        : {}", total_insns);
    println!("  - MPKI Brut Global            : {:.2}", (total_acc as f64 * 1000.0) / (total_insns.max(1) as f64));
    println!("  - Densité initiale des copies : {:.2}% ({} accès séquentiels)", pct(total_raw_seq, total_acc), total_raw_seq);
    println!("------------------------------------------------------------------------------------------");
    println!("  BILAN DES ACCÈS PARASITES DUS À LA LENTEUR QEMU / MTTCG :");
    println!("  - 1. Bruit Kernel (<2.4G)     : {:>5.2}% ({} accès) [Ticks, IRQs, Sauvegardes pile]", pct(total_rem_kernel, total_acc), total_rem_kernel);
    println!("  - 2. Tours de Spinlock en trop: {:>5.2}% ({} accès) [Attente active sous MTTCG]", pct(total_rem_spin, total_acc), total_rem_spin);
    println!("  - 3. Heartbeats / Polling RO  : {:>5.2}% ({} accès) [Polling périodique des démons]", pct(total_rem_heartbeat, total_acc), total_rem_heartbeat);
    println!("  * TOTAL DU BRUIT PURGÉ        : {:>5.2}% ({} accès artificiels éliminés)", pct(total_removed_acc, total_acc), total_removed_acc);
    println!("  * TOTAL INSTRUCTIONS EFFACÉES : {:>5.2}% ({} instructions d'attente compensées)", if total_insns > 0 { (total_removed_insns as f64 * 100.0) / total_insns as f64 } else { 0.0 }, total_removed_insns);
    println!("------------------------------------------------------------------------------------------");
    println!("  TRACE NETTOYÉE RÉALISTE (Ce que Ramulator verra) :");
    println!("  - Accès Mémoire Utiles        : {} (soit {:.1}% du volume d'origine)", cleaned_acc, pct(cleaned_acc, total_acc));
    println!("  - Instructions Utiles         : {}", cleaned_insns);
    println!("  - MPKI Applicatif Global      : {:.2} (reflète la vraie intensité hors bruit)", (cleaned_acc as f64 * 1000.0) / (cleaned_insns.max(1) as f64));
    println!("  - NOUVELLE DENSITÉ DES COPIES : {:.2}% (concentration de RowClone multipliée)", pct(total_clean_seq, cleaned_acc));
    println!("##########################################################################################\n");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

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

    let mut profiles: Vec<CpuProfile> = trace_files
        .par_iter()
        .filter_map(|trace_path| profile_single_cpu_trace(trace_path).ok().flatten())
        .collect();

    profiles.sort_by_key(|p| p.cpu_id);

    for prof in &profiles {
        print_cpu_report(prof);
    }

    print_global_summary(&profiles);

    Ok(())
}