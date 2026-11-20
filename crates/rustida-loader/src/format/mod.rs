//! Binary format front-end: detection and dispatch.

pub mod elf;
pub mod macho;
pub mod pe;

use rustida_core::RustidaError;

use crate::common::{Binary, BinaryKind};

pub use elf::load_elf;
pub use macho::{load_mach_o, load_mach_o_cpu, load_mach_o_thin};
pub use pe::load_pe;

/// Detected container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatKind {
    Elf,
    Pe,
    MachO,
    FatMachO,
}

impl FormatKind {
    /// Common model kind.
    pub const fn binary_kind(self) -> BinaryKind {
        match self {
            FormatKind::Elf => BinaryKind::Elf,
            FormatKind::Pe => BinaryKind::Pe,
            FormatKind::MachO => BinaryKind::MachO,
            FormatKind::FatMachO => BinaryKind::FatMachO,
        }
    }
}

/// Detect the format of `data` from its magic bytes.
///
/// PE detection validates the `e_lfanew` pointer and the `PE\0\0` signature,
/// so a random file starting with `MZ` is not misclassified.
pub fn detect_format(data: &[u8]) -> Option<FormatKind> {
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return Some(FormatKind::Elf);
    }
    if macho::is_fat_macho(data) {
        return Some(FormatKind::FatMachO);
    }
    if macho::is_thin_macho(data) {
        return Some(FormatKind::MachO);
    }
    if looks_like_pe(data) {
        return Some(FormatKind::Pe);
    }
    None
}

fn looks_like_pe(data: &[u8]) -> bool {
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return false;
    }
    let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(e_lfanew..e_lfanew + 4) == Some(&[b'P', b'E', 0, 0])
}

/// Parse any supported binary format from raw bytes.
pub fn load_binary(data: &[u8]) -> Result<Binary, RustidaError> {
    match detect_format(data) {
        Some(FormatKind::Elf) => load_elf(data),
        Some(FormatKind::Pe) => load_pe(data),
        Some(FormatKind::MachO) | Some(FormatKind::FatMachO) => load_mach_o(data),
        None => Err(RustidaError::InvalidFormat(
            "unrecognised binary format (expected ELF, PE or Mach-O)".to_string(),
        )),
    }
}

/// Load a binary from disk.
pub fn load_file(path: impl AsRef<std::path::Path>) -> Result<Binary, RustidaError> {
    let data = std::fs::read(path)?;
    load_binary(&data)
}
