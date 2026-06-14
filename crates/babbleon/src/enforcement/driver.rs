use crate::mapping::MappingTable;
use crate::Result;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub tier: String,
    pub visible: HashMap<String, PathBuf>,
    pub notes: Vec<String>,
}

pub trait EnforcementDriver: Send + Sync {
    fn name(&self) -> &'static str;

    fn present_trusted(
        &mut self,
        real_root: &std::path::Path,
        tracked: &[String],
    ) -> Result<EnforcementResult>;

    fn present_untrusted(
        &mut self,
        real_root: &std::path::Path,
        mapping: &MappingTable,
    ) -> Result<EnforcementResult>;

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}
