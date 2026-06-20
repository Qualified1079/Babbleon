//! Enterprise extension boundary.
//!
//! Rust doesn't have Python-style entry_points; instead, the community crate
//! exposes traits that the enterprise crate implements. The enterprise crate
//! depends on this one and ships its own binary (or links into a unified
//! `babbleon-enterprise` binary).
//!
//! For runtime-loadable plugins (DEFERRED), `libloading` is the path.

use crate::enforcement::driver::EnforcementDriver;
use crate::events::EventSink;
use crate::vault::backend::KekBackend;
use std::collections::HashMap;

type VaultBackendFactory = Box<dyn Fn() -> Box<dyn KekBackend>>;
type EnforcementDriverFactory = Box<dyn Fn() -> Box<dyn EnforcementDriver>>;

/// Compile-time plugin set. Populated by the enterprise crate's builder
/// before the application starts.
#[derive(Default)]
pub struct PluginRegistry {
    vault_backends: HashMap<String, VaultBackendFactory>,
    event_sinks: Vec<Box<dyn EventSink>>,
    enforcement_drivers: HashMap<String, EnforcementDriverFactory>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_vault_backend(
        &mut self,
        name: impl Into<String>,
        factory: impl Fn() -> Box<dyn KekBackend> + 'static,
    ) {
        self.vault_backends.insert(name.into(), Box::new(factory));
    }

    pub fn register_event_sink(&mut self, sink: Box<dyn EventSink>) {
        self.event_sinks.push(sink);
    }

    pub fn register_enforcement_driver(
        &mut self,
        name: impl Into<String>,
        factory: impl Fn() -> Box<dyn EnforcementDriver> + 'static,
    ) {
        self.enforcement_drivers
            .insert(name.into(), Box::new(factory));
    }

    pub fn vault_backend(&self, name: &str) -> Option<Box<dyn KekBackend>> {
        self.vault_backends.get(name).map(|f| f())
    }

    pub fn enforcement_driver(&self, name: &str) -> Option<Box<dyn EnforcementDriver>> {
        self.enforcement_drivers.get(name).map(|f| f())
    }

    pub fn available_vault_backends(&self) -> Vec<&str> {
        self.vault_backends.keys().map(|s| s.as_str()).collect()
    }

    pub fn available_enforcement_drivers(&self) -> Vec<&str> {
        self.enforcement_drivers
            .keys()
            .map(|s| s.as_str())
            .collect()
    }
}
