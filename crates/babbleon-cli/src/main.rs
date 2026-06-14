//! `babbleon` command-line interface.

use anyhow::{Context, Result};
use babbleon::enforcement::{SimulatedDriver, View};
use babbleon::events::Event;
use babbleon::manifest::DEFAULT_TRACKED;
use babbleon::session::Session;
use babbleon::storage::vault_path;
use clap::{Parser, Subcommand};
use std::collections::HashSet;

#[derive(Parser)]
#[command(name = "babbleon", version, about = "Per-host randomized namespace obfuscation")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault.
    Init,
    /// Show vault epoch + tool count without printing the mapping.
    Unlock,
    /// Bump epoch; reseal with a fresh mapping + honey set.
    Rotate,
    /// Print the trusted view (real names).
    Trusted,
    /// Print the untrusted view (scrambled names).
    Untrusted,
    /// Show vault state without unlocking.
    Status,
    /// Run a self-contained sandbox demo (no system changes).
    Demo,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => cmd_init(),
        Cmd::Unlock => cmd_unlock(),
        Cmd::Rotate => cmd_rotate(),
        Cmd::Trusted => cmd_trusted(),
        Cmd::Untrusted => cmd_untrusted(),
        Cmd::Status => cmd_status(),
        Cmd::Demo => cmd_demo(),
    }
}

fn read_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("password prompt failed")
}

fn cmd_init() -> Result<()> {
    let pw = read_password("choose passphrase: ")?;
    let s = Session::initialize(&pw, None, None)?;
    println!("vault created at {}", s.vault_file().display());
    if let Some(sample) = s.tracked.first() {
        if let Some(scrambled) = s.mapping.scramble(sample) {
            println!("sample mapping: {sample} -> {scrambled}");
        }
    }
    Ok(())
}

fn cmd_unlock() -> Result<()> {
    let pw = read_password("passphrase: ")?;
    let s = Session::unlock(&pw, None, None)?;
    println!("epoch: {}", s.payload.epoch);
    println!("tools tracked: {}", s.tracked.len());
    println!("honey tripwires: {}", s.payload.honey_names.len());
    Ok(())
}

fn cmd_rotate() -> Result<()> {
    let pw = read_password("passphrase: ")?;
    let mut s = Session::unlock(&pw, None, None)?;
    let old = s.payload.epoch;
    let new = s.rotate(&pw)?;
    println!("rotated epoch {old} -> {new}");
    Ok(())
}

fn cmd_trusted() -> Result<()> {
    let pw = read_password("passphrase: ")?;
    let s = Session::unlock(&pw, None, None)?;
    let mut names = s.tracked.clone();
    names.sort();
    for n in names {
        println!("{n}");
    }
    Ok(())
}

fn cmd_untrusted() -> Result<()> {
    let pw = read_password("passphrase: ")?;
    let s = Session::unlock(&pw, None, None)?;
    let mut names = s.tracked.clone();
    names.sort();
    for n in names {
        if let Some(scrambled) = s.mapping.scramble(&n) {
            println!("{scrambled}  (was: {n})");
        }
    }
    Ok(())
}

fn cmd_status() -> Result<()> {
    let vp = vault_path();
    if !vp.exists() {
        println!("no vault present; run `babbleon init`");
        std::process::exit(1);
    }
    let meta = std::fs::metadata(&vp)?;
    println!("vault: {} ({} bytes)", vp.display(), meta.len());
    Ok(())
}

fn cmd_demo() -> Result<()> {
    use babbleon::enforcement::driver::EnforcementDriver;

    println!("=== BABBLEON SANDBOX DEMO ===\n");

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin)?;
    for name in DEFAULT_TRACKED {
        let p = bin.join(name);
        std::fs::write(&p, format!("#!/bin/sh\necho '{} stub'\n", name))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    let vault_file = root.join("vault.age");
    let password = "demo-passphrase";

    println!("[1] Initializing vault (Argon2id + age)...");
    let mut s = Session::initialize(password, None, Some(vault_file.clone()))?;
    println!("    vault at {}\n", s.vault_file().display());

    let trusted = View::trusted(&s.tracked, &bin);
    let untrusted = View::untrusted(&s.mapping, &bin);

    println!("[2] Trusted view (humans see real names):");
    for n in trusted.names().iter().take(5) {
        println!("    {n}");
    }
    println!("    ... ({} total)\n", trusted.entries.len());

    println!("[3] Untrusted view (payloads see scrambled compounds):");
    for n in untrusted.names().iter().take(5) {
        let real = s.mapping.reveal(n).unwrap_or("?");
        println!("    {n}  (was: {real})");
    }
    println!("    ... ({} total)\n", untrusted.entries.len());

    println!("[4] Running attacker simulation against UNTRUSTED view...");
    let visible: HashSet<String> = untrusted.entries.keys().cloned().collect();
    let report = attacker_sim(&visible, &s.payload.honey_names);
    print_report(&report);

    println!("[5] Rotating mapping (epoch 0 -> 1)...");
    let sample = s.tracked.first().cloned().unwrap_or_default();
    let old = s.mapping.scramble(&sample).unwrap_or("?").to_string();
    s.rotate(password)?;
    let new = s.mapping.scramble(&sample).unwrap_or("?").to_string();
    println!("    {sample}: {old}");
    println!("        -> {new}\n");

    let untrusted2 = View::untrusted(&s.mapping, &bin);
    println!("[6] Attacker re-runs against rotated view:");
    let visible2: HashSet<String> = untrusted2.entries.keys().cloned().collect();
    let report2 = attacker_sim(&visible2, &s.payload.honey_names);
    print_report(&report2);

    println!("[7] Attacker probes a HONEY name:");
    let mut visible3 = visible2.clone();
    if let Some(h) = s.payload.honey_names.first() {
        visible3.insert(h.clone());
    }
    let report3 = attacker_sim(&visible3, &s.payload.honey_names);
    print_report(&report3);
    if !report3.honey_triggered.is_empty() {
        s.bus.emit(Event::HoneyTriggered {
            epoch: s.payload.epoch,
            names: report3.honey_triggered.clone(),
            process_hint: "demo".into(),
        });
    }

    // Use the simulated driver once so the dependency is exercised
    let mut driver: Box<dyn EnforcementDriver> = Box::new(SimulatedDriver);
    let _ = driver.present_trusted(&bin, &s.tracked)?;

    println!("=== DEMO COMPLETE ===");
    Ok(())
}

const CANONICAL_BINS: &[&str] = &[
    "curl", "wget", "ssh", "nc", "python3", "bash",
    "aws", "gh", "kubectl", "docker", "terraform", "npm", "pip", "git",
];

struct AttackerReport {
    binaries_found: Vec<String>,
    honey_triggered: Vec<String>,
    total: usize,
}

fn attacker_sim(visible: &HashSet<String>, honey: &[String]) -> AttackerReport {
    let binaries_found: Vec<String> = CANONICAL_BINS
        .iter()
        .filter(|n| visible.contains(**n))
        .map(|s| s.to_string())
        .collect();
    let honey_set: HashSet<&String> = honey.iter().collect();
    let honey_triggered: Vec<String> = visible
        .iter()
        .filter(|n| honey_set.contains(*n))
        .cloned()
        .collect();
    AttackerReport {
        binaries_found,
        honey_triggered,
        total: CANONICAL_BINS.len(),
    }
}

fn print_report(r: &AttackerReport) {
    println!("\n=== ATTACKER SIM REPORT ===");
    let pct = (r.binaries_found.len() as f32 / r.total as f32) * 100.0;
    let verdict = if !r.honey_triggered.is_empty() {
        "DETECTED"
    } else if pct < 10.0 {
        "BLOCKED"
    } else if pct < 60.0 {
        "PARTIAL"
    } else {
        "SUCCESS"
    };
    println!(
        "Binary discovery: {}/{} ({:.0}%) [{}]",
        r.binaries_found.len(),
        r.total,
        pct,
        verdict
    );
    if !r.binaries_found.is_empty() {
        println!("  found: {}", r.binaries_found.join(", "));
    }
    if !r.honey_triggered.is_empty() {
        println!(
            "!! HONEY TRIPWIRES triggered: {} — attacker identified !!",
            r.honey_triggered.len()
        );
    }
    println!("===========================\n");
}
