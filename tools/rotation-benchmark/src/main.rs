//! Rotation-rate microbenchmark.
//!
//! # Why this exists
//!
//! The Type 3 hybrid threat (small local agent + large external model,
//! see `docs/threat-model.md`) is defeated by rotating the mapping faster
//! than the local→external→local round-trip the attacker uses to refresh
//! its vocabulary.  That makes the *maximum supportable rotation rate*
//! a first-class number, not an implementation detail.
//!
//! This binary measures the wall-clock cost of the rotation steps that
//! Babbleon controls in software.  The kernel-side bind-mount swap is
//! out of scope here (needs root; covered by `RESEARCH.md` T9 estimates).
//!
//! # What we measure
//!
//!   - **Mapping rebuild**: `Mapper::build_table` over N tracked tools at
//!     a fresh epoch.  Pure compute: HMAC-SHA-256 + Feistel rounds + word
//!     lookups.
//!   - **Wrapper regeneration**: writing N wrapper scripts to a tempdir
//!     with per-host SHA-256 padding.  This is the file-IO cost of a
//!     rotation that also re-renders wrappers (which it doesn't strictly
//!     have to — wrappers can be pre-rendered for the next epoch).
//!   - **Total in-memory rotation**: rebuild + render.
//!
//! What we do NOT measure here:
//!
//!   - Bind-mount cross-namespace propagation (kernel-side, root-only).
//!   - Vault re-seal under Argon2id — this is the *cold* rotation path
//!     (token-bound at ~250 ms) and is not what the rotation-rate
//!     question is about.  Hot rotation keeps the host_secret in memory
//!     and never touches Argon2id.
//!
//! # Output
//!
//! Per-config summary printed to stdout: mean, median, p95, min, max
//! over `--iterations` rotations.  Caller can convert to a maximum
//! rotation rate (Hz) via `1000 / median_ms`.

use babbleon::enforcement::wrapper::write_wrapper;
use babbleon::mapping::Mapper;
use clap::Parser;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(about = "Microbenchmark for Babbleon mapping/wrapper rotation cost")]
struct Args {
    /// Tracked tool counts to sweep.
    #[arg(long, value_delimiter = ',', default_value = "10,100,1000,10000")]
    tool_counts: Vec<usize>,

    /// Rotation iterations per config (warmup is one extra).
    #[arg(short, long, default_value_t = 50)]
    iterations: usize,

    /// Skip wrapper regeneration (measure mapping rebuild only).
    #[arg(long)]
    no_wrappers: bool,
}

struct Stats {
    mean_us: f64,
    median_us: u128,
    p95_us: u128,
    min_us: u128,
    max_us: u128,
}

impl Stats {
    fn from(mut samples: Vec<Duration>) -> Self {
        samples.sort();
        let n = samples.len();
        let us: Vec<u128> = samples.iter().map(|d| d.as_micros()).collect();
        let mean_us = us.iter().sum::<u128>() as f64 / n as f64;
        let median_us = us[n / 2];
        let p95_idx = ((n as f64 - 1.0) * 0.95).round() as usize;
        let p95_us = us[p95_idx];
        Stats {
            mean_us,
            median_us,
            p95_us,
            min_us: us[0],
            max_us: us[n - 1],
        }
    }

    fn print(&self, label: &str) {
        let median_ms = self.median_us as f64 / 1000.0;
        let max_rate_hz = if median_ms > 0.0 {
            1000.0 / median_ms
        } else {
            f64::INFINITY
        };
        println!(
            "  {label:<26} median={:>9.3} ms  mean={:>9.3} ms  p95={:>9.3} ms  \
             min={:>9.3} ms  max={:>9.3} ms  ⇒ max ~{:>7.1} Hz",
            self.median_us as f64 / 1000.0,
            self.mean_us / 1000.0,
            self.p95_us as f64 / 1000.0,
            self.min_us as f64 / 1000.0,
            self.max_us as f64 / 1000.0,
            max_rate_hz,
        );
    }
}

fn make_tools(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("tool{i:08}")).collect()
}

fn run_one_config(n: usize, iterations: usize, do_wrappers: bool) {
    println!("\n=== {} tracked tools ===", n);

    let tracked = make_tools(n);

    let tmp = tempfile::tempdir().expect("tempdir");
    let real_root = tmp.path().join("real");
    let wrapper_root = tmp.path().join("wrappers");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::create_dir_all(&wrapper_root).unwrap();

    if do_wrappers {
        for t in &tracked {
            let p = real_root.join(t);
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    // We measure TWO paths:
    //
    //   - cold:   each iteration uses a fresh (host_secret, epoch) pair, so
    //             the underlying wordlist permutation cache misses every
    //             time.  This is the cost of a rotation that has to build
    //             the wordlist permutation from scratch.
    //   - warm:   each iteration uses the same (host_secret, epoch), so the
    //             permutation hits cache.  This is the cost of a rotation
    //             where the next-epoch permutation has been pre-built in
    //             background and we are only paying for compound generation
    //             + wrapper render.
    //
    // Cold = the worst-case ceiling.  Warm = what a well-engineered
    // hot-rotate path can actually achieve.

    let mut cold_rebuild = Vec::with_capacity(iterations);
    let mut cold_wrapper = Vec::with_capacity(iterations);
    let mut cold_total = Vec::with_capacity(iterations);

    let mut warm_rebuild = Vec::with_capacity(iterations);
    let mut warm_wrapper = Vec::with_capacity(iterations);
    let mut warm_total = Vec::with_capacity(iterations);

    // Warm path uses a fixed secret + a fixed epoch (1), pre-warmed once.
    let warm_secret = [0xAAu8; 32];
    let warm_mapper = Mapper::new(&warm_secret);
    let _ = warm_mapper.build_table(&tracked, 1);

    // Mix the tool-count into the cold-secret key space so configs
    // later in the sweep don't accidentally hit the perm cache built
    // by earlier configs.
    let config_nonce = n as u64;

    for iter in 0..iterations as u64 {
        // ── cold path ──────────────────────────────────────────────
        // Make the (secret, epoch) tuple unique per iteration AND per
        // config so the wordlist permutation cache misses every time.
        let mut cold_secret = [0u8; 32];
        cold_secret[..8].copy_from_slice(&iter.to_le_bytes());
        cold_secret[8..16].copy_from_slice(&config_nonce.to_le_bytes());
        cold_secret[16] = 0xC0;
        let cold_mapper = Mapper::new(&cold_secret);
        let cold_epoch = 1_000_000 + iter; // unused-elsewhere epoch space

        let t_total = Instant::now();
        let t0 = Instant::now();
        let cold_table = cold_mapper.build_table(&tracked, cold_epoch);
        cold_rebuild.push(t0.elapsed());

        if do_wrappers {
            let epoch_dir = wrapper_root.join(format!("cold-{iter}"));
            std::fs::create_dir_all(&epoch_dir).unwrap();
            let t1 = Instant::now();
            for (real, scrambled) in &cold_table.real_to_scrambled {
                let real_path = real_root.join(real);
                write_wrapper(
                    real,
                    scrambled,
                    &real_path,
                    &epoch_dir,
                    &cold_secret,
                    Some(1u64),
                    None,
                )
                .unwrap();
            }
            cold_wrapper.push(t1.elapsed());
            std::fs::remove_dir_all(&epoch_dir).ok();
        }
        cold_total.push(t_total.elapsed());

        // ── warm path ──────────────────────────────────────────────
        // Reuse the pre-warmed permutation; only compound generation +
        // wrapper render costs charge here.
        let t_total = Instant::now();
        let t0 = Instant::now();
        let warm_table = warm_mapper.build_table(&tracked, 1);
        warm_rebuild.push(t0.elapsed());

        if do_wrappers {
            let epoch_dir = wrapper_root.join(format!("warm-{iter}"));
            std::fs::create_dir_all(&epoch_dir).unwrap();
            let t1 = Instant::now();
            for (real, scrambled) in &warm_table.real_to_scrambled {
                let real_path = real_root.join(real);
                write_wrapper(
                    real,
                    scrambled,
                    &real_path,
                    &epoch_dir,
                    &warm_secret,
                    Some(1u64),
                    None,
                )
                .unwrap();
            }
            warm_wrapper.push(t1.elapsed());
            std::fs::remove_dir_all(&epoch_dir).ok();
        }
        warm_total.push(t_total.elapsed());
    }

    println!("  -- cold path (wordlist perm not yet built) --");
    Stats::from(cold_rebuild).print("mapping rebuild");
    if do_wrappers {
        Stats::from(cold_wrapper).print("wrapper regen");
        Stats::from(cold_total).print("total rotation");
    }
    println!("  -- warm path (perm precomputed in background) --");
    Stats::from(warm_rebuild).print("mapping rebuild");
    if do_wrappers {
        Stats::from(warm_wrapper).print("wrapper regen");
        Stats::from(warm_total).print("total rotation");
    }
}

fn main() {
    let args = Args::parse();

    println!("Babbleon rotation-cost microbenchmark");
    println!("  iterations / config: {}", args.iterations);
    println!("  wrappers regenerated: {}", !args.no_wrappers);
    println!("  tool counts:         {:?}", args.tool_counts);
    println!(
        "\nReminder: this measures only the userspace rotation cost \
         (mapping rebuild + wrapper render).  Kernel-side bind-mount \
         swap is NOT measured here; per RESEARCH T9 expect ~50 ms per \
         200 bind-mounts on a typical kernel.  Vault re-seal is \
         excluded — that is the cold path."
    );

    // Global warmup.  Two things to pay for here:
    //   1. One-time wordlist load (`words.txt` is ~3 MB; first
    //      `.lines().collect()` is ~18 ms).
    //   2. CPU frequency ramp on laptops with aggressive idle scaling;
    //      without sustained work the first config charges the slow
    //      P-state to its median.
    // 200 iterations of a 100-tool build_table is enough to clear both.
    {
        let warm = make_tools(100);
        let mapper = Mapper::new(&[0u8; 32]);
        for ep in 0..200 {
            std::hint::black_box(mapper.build_table(&warm, ep));
        }
    }

    let counts: Vec<usize> = args.tool_counts.clone();
    for n in counts {
        run_one_config(n, args.iterations, !args.no_wrappers);
    }

    println!("\nReport these numbers in PLAN.md or threat-model.md only with the");
    println!("tool count, iterations, kernel, and CPU that produced them.");
}
