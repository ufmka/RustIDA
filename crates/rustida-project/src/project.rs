/// RustIDA project.
use rustida_core::Architecture;
use rustida_loader::BinaryFormat;

use crate::manifest::ProjectManifest;

/// RustIDA project
pub struct Project {
    /// Project manifest
    pub manifest: ProjectManifest,
}

impl Project {
    /// Create a new project
    pub fn new(name: String, format: BinaryFormat, arch: Architecture) -> Self {
        Self {
            manifest: ProjectManifest { name, format, arch },
        }
    }
}
