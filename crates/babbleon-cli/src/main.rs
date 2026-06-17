//! `babbleon` command-line interface.

mod deception;

use anyhow::{Context, Result};
use babbleon::enforcement::{SimulatedDriver, View};
use babbleon::events::Event;
use babbleon::manifest::DEFAULT_TRACKED;
use babbleon::session::Session;
use babbleon::storage::vault_path;
use clap::{Parser, Subcommand};
use std::collections::HashSet;

#[derive(Parser)]
#[command(
    name = "babbleon",
    version,
    about = "Per-host randomized namespace obfuscation"
)]
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
    /// Install systemd service + timer for automatic epoch rotation.
    Install {
        /// Directory to write unit files into (default: /etc/systemd/system).
        #[arg(long, default_value = "/etc/systemd/system")]
        unit_dir: std::path::PathBuf,
        /// How often to rotate (systemd OnCalendar format, default: weekly).
        #[arg(long, default_value = "weekly")]
        schedule: String,
    },
    /// Apply the untrusted (scrambled) view in the current mount namespace.
    /// Requires CAP_SYS_ADMIN or the setuid ns-helper.
    ApplyNs {
        /// Directory containing the real binaries (real $PATH entry).
        #[arg(long, default_value = "/usr/local/bin")]
        real_root: std::path::PathBuf,
    },
    /// Show which credential directories would be gated in untrusted view.
    /// Pass --apply to actually gate them (requires CAP_SYS_ADMIN or ns-helper).
    Credentials {
        /// Home directory to scan (default: $HOME).
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Actually apply tmpfs overlays, not just list (requires mount privileges).
        #[arg(long)]
        apply: bool,
    },
    /// Re-seal the TPM vault after a kernel update changes PCR values.
    /// (DEFERRED M2.5 — currently prints instructions.)
    TpmReseal,
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
        Cmd::Install { unit_dir, schedule } => cmd_install(&unit_dir, &schedule),
        Cmd::ApplyNs { real_root } => cmd_apply_ns(&real_root),
        Cmd::Credentials { home, apply } => cmd_credentials(home, apply),
        Cmd::TpmReseal => cmd_tpm_reseal(),
    }
}

fn cmd_tpm_reseal() -> Result<()> {
    eprintln!("babbleon tpm-reseal: DEFERRED (M2.5)");
    eprintln!();
    eprintln!("Until tss-esapi wiring lands, re-seal manually:");
    eprintln!("  1. Boot the new kernel.");
    eprintln!("  2. babbleon rotate          (rotates epoch; discards old sealed blob)");
    eprintln!("  3. babbleon init --tier tpm (re-seals with new PCR values)");
    eprintln!();
    eprintln!("Longer term: tpm2_policyauthorize lets an admin sign new PCR policies");
    eprintln!("without rotating the host secret. Tracked in TODO.md.");
    std::process::exit(2);
}

fn cmd_credentials(home: Option<std::path::PathBuf>, apply: bool) -> Result<()> {
    let home = home
        .or_else(|| std::env::var_os("HOME").map(std::path::PathBuf::from))
        .context("--home required when $HOME unset")?;
    let found = babbleon::credentials::discover(&home);
    if found.is_empty() {
        println!("no credential directories present under {}", home.display());
        return Ok(());
    }

    if apply {
        #[cfg(target_os = "linux")]
        {
            let gated = babbleon::credentials::apply_untrusted_gate(&home)?;
            println!(
                "gated {} credential directories (tmpfs overlay applied):",
                gated.len()
            );
            for p in &gated {
                println!("  {}", p.display());
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("babbleon credentials --apply: Linux only");
            std::process::exit(2);
        }
    } else {
        println!(
            "would gate {} credential paths under {} (--apply to activate):",
            found.len(),
            home.display()
        );
        for p in &found {
            println!("  {}", p.display());
        }
        println!(
            "\nenv-var scrub list ({} entries):",
            babbleon::credentials::SCRUB_ENV_VARS.len()
        );
        for v in babbleon::credentials::SCRUB_ENV_VARS {
            println!("  {v}");
        }
    }
    Ok(())
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
    use babbleon::enforcement::ebpf;

    let vp = vault_path();
    if !vp.exists() {
        println!("no vault present; run `babbleon init`");
        std::process::exit(1);
    }
    let meta = std::fs::metadata(&vp)?;
    println!("vault:   {} ({} bytes)", vp.display(), meta.len());

    // Kernel feature probes
    #[cfg(target_os = "linux")]
    {
        use babbleon::enforcement::ebpf::BpfLsmStatus;
        match ebpf::probe() {
            BpfLsmStatus::Available => println!("bpf-lsm: available"),
            BpfLsmStatus::PermissionDenied => {
                println!("bpf-lsm: needs CAP_BPF (run as root or grant capability)")
            }
            BpfLsmStatus::Unavailable { reason } => println!("bpf-lsm: unavailable — {reason}"),
        }

        // Landlock availability
        let ll_status = if std::path::Path::new("/sys/kernel/security/lsm").exists() {
            std::fs::read_to_string("/sys/kernel/security/lsm")
                .map(|s| {
                    if s.split(',').any(|l| l.trim() == "landlock") {
                        "active"
                    } else {
                        "not in lsm= list"
                    }
                })
                .unwrap_or("unknown")
        } else {
            "unknown"
        };
        println!("landlock: {ll_status}");

        // Seccomp
        let seccomp = std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail")
            .unwrap_or_else(|_| "not available".into());
        if seccomp.contains("kill") {
            println!("seccomp:  available");
        } else {
            println!("seccomp:  {}", seccomp.trim());
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ebpf::probe();
        println!("bpf-lsm: n/a (not Linux)");
    }

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
            source: babbleon::events::TripwireSource::Honey,
            wrapper_pid: 0,
            triggering_pid: None,
            triggering_pid_start: None,
            process_hint: "demo".into(),
        });
    }

    // Use the simulated driver once so the dependency is exercised
    let mut driver: Box<dyn EnforcementDriver> = Box::new(SimulatedDriver);
    let _ = driver.mount_real_view(&bin, &s.tracked)?;

    println!("=== DEMO COMPLETE ===");
    Ok(())
}

const CANONICAL_BINS: &[&str] = &[
    "curl",
    "wget",
    "ssh",
    "nc",
    "python3",
    "bash",
    "aws",
    "gh",
    "kubectl",
    "docker",
    "terraform",
    "npm",
    "pip",
    "git",
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

fn cmd_install(unit_dir: &std::path::Path, schedule: &str) -> Result<()> {
    std::fs::create_dir_all(unit_dir)
        .with_context(|| format!("create unit dir {}", unit_dir.display()))?;

    let service = r#"[Unit]
Description=Babbleon epoch rotation
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/babbleon rotate
StandardInput=null
Environment=BABBLEON_PASSPHRASE_FILE=/etc/babbleon/passphrase
"#
    .to_string();

    let timer = format!(
        r#"[Unit]
Description=Babbleon epoch rotation timer

[Timer]
OnCalendar={schedule}
Persistent=true

[Install]
WantedBy=timers.target
"#
    );

    let svc_path = unit_dir.join("babbleon-rotate.service");
    let tmr_path = unit_dir.join("babbleon-rotate.timer");
    std::fs::write(&svc_path, service)?;
    std::fs::write(&tmr_path, timer)?;
    println!("wrote {}", svc_path.display());
    println!("wrote {}", tmr_path.display());
    println!("\nEnable with:");
    println!("  systemctl daemon-reload");
    println!("  systemctl enable --now babbleon-rotate.timer");
    Ok(())
}

fn cmd_apply_ns(real_root: &std::path::Path) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("apply-ns is Linux-only");
    }
    #[cfg(target_os = "linux")]
    {
        use babbleon::enforcement::driver::EnforcementDriver;
        use babbleon::enforcement::linux_ns::LinuxNamespaceDriver;
        use babbleon::enforcement::response::{HoneyResponder, ResponsePolicy};
        use babbleon::enforcement::wrapper::{
            write_all, write_honey_list, write_stale_list, write_tripwire_scripts,
            HONEY_FIFO,
        };
        use babbleon::events::{EventBus, HoneyFifoReader, StderrSink};
        use babbleon::mapping::{Mapper, STALE_RETAIN_EPOCHS};

        let pw = read_password("passphrase: ")?;
        let s = babbleon::session::Session::unlock(&pw, None, None)?;

        // Snapshot the *host* mount-NS inode BEFORE we unshare.  Wrapper
        // scripts embed this as their "trusted" inode so they correctly
        // detect when they're being invoked from inside the scrambled NS.
        let host_ns_inode = std::fs::metadata("/proc/self/ns/mnt")
            .ok()
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.ino()
            });
        // Persist it so trusted-tier callers (PAM session, etc.) can read it.
        if let Some(inode) = host_ns_inode {
            let _ = std::fs::create_dir_all("/run/babbleon");
            let _ = std::fs::write("/run/babbleon/trusted-ns-inode", inode.to_string());
        }

        // Generate wrapper scripts with per-host padding + deceptive banners.
        let wrapper_dir = std::path::Path::new("/run/babbleon/wrappers");
        let mapping_pairs: Vec<(String, String)> = s
            .tracked
            .iter()
            .filter_map(|t| {
                s.mapping
                    .scramble(t)
                    .map(|sc| (t.clone(), sc.to_string()))
            })
            .collect();
        let host_secret = hex::decode(&s.payload.host_secret_hex)
            .context("invalid host_secret_hex in vault")?;
        write_all(
            mapping_pairs,
            real_root,
            wrapper_dir,
            &host_secret,
            host_ns_inode,
            deception::deceptive_response,
        )
        .with_context(|| format!("write wrappers to {}", wrapper_dir.display()))?;

        // Honey-name wrappers: every honey name gets a tripwire script that
        // writes to HONEY_FIFO on exec and exits 127.
        write_tripwire_scripts(
            s.payload.honey_names.iter().map(String::as_str),
            wrapper_dir,
            &host_secret,
        )
        .with_context(|| format!("write honey wrappers to {}", wrapper_dir.display()))?;

        // Write the honey list so the unified wrapper template can distinguish
        // honey names from real-tool names at exec time without size differences.
        write_honey_list(s.payload.honey_names.iter().map(String::as_str), None)
            .with_context(|| "write honey.list")?;

        // Compute and write the stale-mapping list: scrambled names that this
        // tracked set received in the previous K epochs.  Any process invoking
        // one of these names is using cached intel from before the last
        // rotation — a high-confidence tripwire.
        let mapper = Mapper::new(&host_secret);
        let stale = mapper.stale_names_for_previous_epochs(
            &s.tracked,
            s.payload.epoch,
            STALE_RETAIN_EPOCHS,
        );
        write_stale_list(stale.iter().map(String::as_str), None)
            .with_context(|| "write stale.list")?;

        // Read honey-response policy from BABBLEON_HONEY_POLICY env var.
        // Defaults to notify-only; operator opt-in to active responses
        // because killing a triggering process can take a user's shell
        // with it if a parent shell typed a stale name by mistake.
        let policy = std::env::var("BABBLEON_HONEY_POLICY")
            .ok()
            .and_then(|s| ResponsePolicy::from_str(&s))
            .unwrap_or_default();

        // Spawn the honey-FIFO reader so trigger events become Event::HoneyTriggered.
        let mut bus = EventBus::new();
        bus.add_sink(Box::new(StderrSink));
        bus.add_sink(Box::new(HoneyResponder::new(policy)));
        let bus_arc = std::sync::Arc::new(bus);
        let _reader = HoneyFifoReader::spawn(bus_arc, s.payload.epoch, HONEY_FIFO.to_string());

        let mut driver = LinuxNamespaceDriver::default().with_wrappers(wrapper_dir.to_path_buf());
        let result = driver.mount_scrambled_view(real_root, &s.mapping)?;
        println!("tier: {}", result.tier);
        for note in &result.notes {
            println!("  {note}");
        }
        println!("{} binaries in untrusted view", result.visible.len());
        Ok(())
    }
}
