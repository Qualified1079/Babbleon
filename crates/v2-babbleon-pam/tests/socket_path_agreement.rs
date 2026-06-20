//! Cross-crate agreement: this crate's `DEFAULT_DAEMON_SOCKET_PATH`
//! constant must equal the canonical
//! `v2-babbleon-daemon-protocol::default_socket_path()`.
//!
//! Why a runtime test instead of a compile-time `const`:
//!
//! - This crate intentionally does NOT depend on
//!   `v2-babbleon-daemon-protocol` in `Cargo.toml`'s `[dependencies]`.
//!   The C `build.rs` is the production-relevant build path; pulling
//!   the protocol crate into the build graph would force any host
//!   building the PAM module to also build the daemon protocol
//!   (and transitively `serde_json` + `thiserror`).  The build path
//!   stays as small as possible.
//!
//! - We DO depend on it under `[dev-dependencies]` — that pulls the
//!   crate into the test build only.  Drift between the two
//!   constants is then a `cargo test -p v2-babbleon-pam` failure,
//!   loud and immediate, but does not touch production compilation.

#[test]
fn pam_default_socket_path_agrees_with_protocol_crate() {
    let from_pam =
        std::path::PathBuf::from(babbleon_pam_v2::DEFAULT_DAEMON_SOCKET_PATH);
    let canonical = babbleon_daemon_protocol_v2::default_socket_path();
    assert_eq!(
        from_pam, canonical,
        "v2-babbleon-pam's DEFAULT_DAEMON_SOCKET_PATH must match \
         v2-babbleon-daemon-protocol::default_socket_path(); update \
         both or the C shim probes the wrong socket"
    );
}
