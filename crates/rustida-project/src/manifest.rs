/// Project manifest for RustIDA
use rustida_core::Architecture;

/// Project manifest
#[derive(Debug, Clone)]
pub struct ProjectManifest {
    /// Project name
    pub name: String,
    /// Target binary format
    pub format: rustida_loader::BinaryFormat,
    /// Target architecture
    pub arch: Architecture,
}
