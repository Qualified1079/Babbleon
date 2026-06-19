//! End-to-end test: daemon-side build → JSONL → launcher-side read.
//!
//! Exercises the activated-table loop across both crates without
//! needing root privileges (no bind-mount syscalls are made).  This
//! catches drift between the producer (core) and consumer (launcher)
//! that pure unit tests inside one crate would miss.

#![cfg(target_os = "linux")]

use std::io::Write;

use babbleon_core_v2::{
    build_activated_table_from_mapping, ActivatedTable, MappingBuilder,
    PerHostSecret, Wordlist,
};
use v2_babbleon_launch_untrusted::activated_table_input;

fn tracked_set() -> Vec<String> {
    [
        "curl", "ssh", "git", "aws", "docker", "kubectl", "rsync",
        "scp", "psql", "redis-cli",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

#[test]
fn daemon_to_launcher_roundtrip_preserves_every_entry() {
    let secret = PerHostSecret::from_bytes(&[13u8; 32]).unwrap();
    let wl = Wordlist::english_baseline();
    let tracked = tracked_set();

    let mapping = MappingBuilder::new(&secret, wl)
        .build(&tracked, 17)
        .unwrap();
    let table = build_activated_table_from_mapping(
        &mapping,
        std::path::Path::new("/usr/local/libexec/babbleon/wrappers"),
    )
    .unwrap();

    let bytes = table.write_jsonl().unwrap();
    let parsed =
        ActivatedTable::read_jsonl(std::io::Cursor::new(&bytes)).unwrap();
    assert_eq!(parsed, table, "wire roundtrip must be lossless");

    assert_eq!(parsed.epoch, 17);
    assert_eq!(parsed.entries.len(), tracked.len());
    assert_eq!(parsed.honey_names.len(), mapping.honey_names.len());

    // Every tracked tool's scrambled name must appear exactly once.
    for tool in &tracked {
        let scrambled = mapping.scramble(tool).unwrap();
        let hits = parsed
            .entries
            .iter()
            .filter(|e| e.scrambled == scrambled)
            .count();
        assert_eq!(hits, 1, "scrambled name for {tool} appears {hits} times");
    }

    // Every entry's wrapper_path is the wrapper_dir joined with the
    // scrambled name — that's the daemon's wrapper-output layout.
    for e in &parsed.entries {
        let expected =
            std::path::PathBuf::from("/usr/local/libexec/babbleon/wrappers")
                .join(&e.scrambled);
        assert_eq!(e.wrapper_path, expected);
    }
}

#[test]
fn launcher_reads_table_from_path_written_by_core() {
    let secret = PerHostSecret::from_bytes(&[29u8; 32]).unwrap();
    let wl = Wordlist::english_baseline();
    let tracked = vec!["curl".to_string(), "ssh".to_string()];

    let mapping = MappingBuilder::new(&secret, wl)
        .build(&tracked, 1)
        .unwrap();
    let table = build_activated_table_from_mapping(
        &mapping,
        std::path::Path::new("/usr/local/libexec/babbleon/wrappers"),
    )
    .unwrap();
    let bytes = table.write_jsonl().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("activated.jsonl");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&bytes).unwrap();
    }

    let parsed =
        activated_table_input::read_if_present(None, Some(path.as_path()))
            .unwrap()
            .unwrap();
    assert_eq!(parsed, table);
}

#[test]
fn launcher_returns_none_when_no_source_supplied() {
    let parsed =
        activated_table_input::read_if_present(None, None).unwrap();
    assert!(parsed.is_none());
}

#[test]
fn epoch_rotation_invalidates_every_entry() {
    let secret = PerHostSecret::from_bytes(&[3u8; 32]).unwrap();
    let wl = Wordlist::english_baseline();
    let tracked = tracked_set();

    let m0 = MappingBuilder::new(&secret, wl).build(&tracked, 0).unwrap();
    let m1 = MappingBuilder::new(&secret, wl).build(&tracked, 1).unwrap();

    let t0 = build_activated_table_from_mapping(
        &m0,
        std::path::Path::new("/usr/local/libexec/babbleon/wrappers"),
    )
    .unwrap();
    let t1 = build_activated_table_from_mapping(
        &m1,
        std::path::Path::new("/usr/local/libexec/babbleon/wrappers"),
    )
    .unwrap();

    // Every scrambled name from epoch 0 should be absent from epoch 1's
    // entry list — this is the rotation property the launcher relies on
    // for stale-mapping tripwires.
    let names_0: std::collections::HashSet<&str> = t0
        .entries
        .iter()
        .map(|e| e.scrambled.as_str())
        .collect();
    for e in &t1.entries {
        assert!(
            !names_0.contains(e.scrambled.as_str()),
            "epoch 1 scrambled {} also appears in epoch 0",
            e.scrambled,
        );
    }
}
