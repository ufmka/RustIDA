//! Format-independent binary model shared by the ELF, PE and Mach-O loaders.

use std::sync::Arc;

use rustida_core::{Address, Architecture, Endianness, Permissions, SymbolKind};

use crate::disasm::DisassembledInstruction;
use crate::format::{elf::ElfInfo, macho::MachOInfo, pe::PeInfo};

/// The container format that was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryKind {
    /// ELF (any bitness).
    Elf,
    /// PE32 or PE32+.
    Pe,
    /// Thin Mach-O (32 or 64 bit).
    MachO,
    /// Fat / universal Mach-O container.
    FatMachO,
}

impl BinaryKind {
    /// Human readable name.
    pub const fn name(self) -> &'static str {
        match self {
            BinaryKind::Elf => "ELF",
            BinaryKind::Pe => "PE",
            BinaryKind::MachO => "Mach-O",
            BinaryKind::FatMachO => "Fat Mach-O",
        }
    }
}

/// Description of a parsed binary format.
#[derive(Debug, Clone)]
pub struct BinaryFormat {
    /// Format name (`ELF`, `PE`, `Mach-O`, ...).
    pub name: String,
    /// Byte order.
    pub endianness: Endianness,
    /// Pointer width in bits.
    pub address_bits: u32,
    /// Machine-readable format kind.
    pub kind: BinaryKind,
}

impl BinaryFormat {
    /// Construct a format description.
    pub fn new(
        name: impl Into<String>,
        endianness: Endianness,
        address_bits: u32,
        kind: BinaryKind,
    ) -> Self {
        BinaryFormat {
            name: name.into(),
            endianness,
            address_bits,
            kind,
        }
    }
}

/// A memory-mapped segment (ELF `PT_LOAD`, Mach-O `LC_SEGMENT*`).
#[derive(Debug, Clone)]
pub struct Segment {
    /// Segment name (Mach-O segment name, ELF `PT_LOAD`).
    pub name: String,
    /// Virtual address of the first byte.
    pub address: Address,
    /// Size in memory.
    pub size: u64,
    /// Offset in the file where the backing bytes start.
    pub file_offset: u64,
    /// Number of file-backed bytes.
    pub file_size: u64,
    /// Access permissions at load time.
    pub permissions: Permissions,
}

/// A section of a binary.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (ELF/SH name, PE short name, Mach-O `seg,sect`).
    pub name: String,
    /// Virtual address of the first byte.
    pub address: Address,
    /// Size in memory.
    pub size: u64,
    /// Offset in the file.
    pub file_offset: u64,
    /// Number of bytes present in the file.
    pub file_size: u64,
    /// Access permissions.
    pub permissions: Permissions,
    /// Whether the section contains executable code.
    pub executable: bool,
}

impl Section {
    /// End address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address.0.saturating_add(self.size)
    }

    /// Whether `va` falls inside this section's virtual range.
    pub fn contains_va(&self, va: u64) -> bool {
        va >= self.address.0 && va < self.end_address()
    }
}

/// A symbol from any format.
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name.
    pub name: String,
    /// Symbol address (virtual).
    pub address: Address,
    /// Symbol size, when known.
    pub size: u64,
    /// Symbol kind.
    pub kind: SymbolKind,
}

/// An imported symbol.
#[derive(Debug, Clone)]
pub struct Import {
    /// Originating library / DLL / dylib.
    pub library: String,
    /// Imported symbol name (`#123` for ordinal-only imports).
    pub name: String,
    /// Address of the import slot (IAT/PLT/GOT) when known.
    pub address: Address,
}

/// An exported symbol.
#[derive(Debug, Clone)]
pub struct Export {
    /// Export name.
    pub name: String,
    /// Address of the exported entity.
    pub address: Address,
    /// Ordinal, when the format has one.
    pub ordinal: Option<u32>,
}

/// Format-specific details kept alongside the common model.
#[derive(Debug, Clone)]
pub enum BinaryInfo {
    /// ELF-specific header information.
    Elf(ElfInfo),
    /// PE-specific header information.
    Pe(PeInfo),
    /// Mach-O-specific header information.
    MachO(Box<MachOInfo>),
}

/// A fully parsed binary.
#[derive(Debug, Clone)]
pub struct Binary {
    /// Format description.
    pub format: BinaryFormat,
    /// Target architecture.
    pub arch: Architecture,
    /// Entry point virtual address (0 when unknown).
    pub entry_point: Address,
    /// Image base used to translate between RVA and VA.
    pub image_base: u64,
    /// Size of the format headers (used to translate header RVAs).
    pub headers_size: u64,
    /// Memory-mapped segments.
    pub segments: Vec<Segment>,
    /// Sections.
    pub sections: Vec<Section>,
    /// Symbols, imports and exports merged where the format provides them.
    pub symbols: Vec<Symbol>,
    /// Imported symbols.
    pub imports: Vec<Import>,
    /// Exported symbols.
    pub exports: Vec<Export>,
    /// Decoded instructions. Empty until [`crate::disasm::disassemble_binary`] runs.
    pub instructions: Vec<DisassembledInstruction>,
    /// Original file bytes (shared, cheap to clone).
    pub bytes: Arc<Vec<u8>>,
    /// Format-specific information.
    pub info: BinaryInfo,
}

impl Binary {
    /// Construct an empty binary with the given format and bytes.
    pub fn empty(
        format: BinaryFormat,
        arch: Architecture,
        bytes: Arc<Vec<u8>>,
        info: BinaryInfo,
    ) -> Self {
        Binary {
            format,
            arch,
            entry_point: Address::new(0),
            image_base: 0,
            headers_size: 0,
            segments: Vec::new(),
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            instructions: Vec::new(),
            bytes,
            info,
        }
    }

    /// Total size of the original file in bytes.
    pub fn file_len(&self) -> usize {
        self.bytes.len()
    }

    /// Find the section whose virtual range contains `va`.
    pub fn section_for_va(&self, va: u64) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_va(va))
    }

    /// Find the section whose file range contains `offset`.
    pub fn section_for_offset(&self, offset: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            s.file_size > 0 && offset >= s.file_offset && offset < s.file_offset + s.file_size
        })
    }

    /// Translate an RVA (relative virtual address) to a file offset.
    ///
    /// Sections are consulted first, then segments, then headers. Returns
    /// `None` for addresses that are not backed by file bytes (e.g. `.bss`).
    pub fn rva_to_offset(&self, rva: u64) -> Option<u64> {
        // Sections and segments store virtual addresses, so translate the RVA
        // through the image base first. For ELF and Mach-O the image base is
        // zero, making RVA == VA.
        let va = self.rva_to_va(rva);
        for section in &self.sections {
            if section.file_size == 0 {
                continue;
            }
            let size = section.size.max(section.file_size);
            if va >= section.address.0 && va < section.address.0.saturating_add(size) {
                let delta = va - section.address.0;
                if delta < section.file_size {
                    let offset = section.file_offset + delta;
                    if offset < self.bytes.len() as u64 {
                        return Some(offset);
                    }
                }
                return None;
            }
        }
        for segment in &self.segments {
            if segment.file_size == 0 {
                continue;
            }
            if va >= segment.address.0
                && va
                    < segment
                        .address
                        .0
                        .saturating_add(segment.size.max(segment.file_size))
            {
                let delta = va - segment.address.0;
                if delta < segment.file_size {
                    let offset = segment.file_offset + delta;
                    if offset < self.bytes.len() as u64 {
                        return Some(offset);
                    }
                }
                return None;
            }
        }
        // PE headers are mapped at RVA 0 and are not covered by a section.
        if self.format.kind == BinaryKind::Pe
            && rva < self.headers_size
            && rva < self.bytes.len() as u64
        {
            return Some(rva);
        }
        None
    }

    /// Translate a file offset to an RVA.
    pub fn offset_to_rva(&self, offset: u64) -> Option<u64> {
        for section in &self.sections {
            if section.file_size == 0 {
                continue;
            }
            if offset >= section.file_offset && offset < section.file_offset + section.file_size {
                let va = section.address.0 + (offset - section.file_offset);
                return va.checked_sub(self.image_base);
            }
        }
        for segment in &self.segments {
            if segment.file_size == 0 {
                continue;
            }
            if offset >= segment.file_offset && offset < segment.file_offset + segment.file_size {
                let va = segment.address.0 + (offset - segment.file_offset);
                return va.checked_sub(self.image_base);
            }
        }
        if self.format.kind == BinaryKind::Pe && offset < self.headers_size {
            return Some(offset);
        }
        None
    }

    /// Translate a virtual address to an RVA.
    pub fn va_to_rva(&self, va: u64) -> Option<u64> {
        va.checked_sub(self.image_base)
    }

    /// Translate an RVA to a virtual address.
    pub fn rva_to_va(&self, rva: u64) -> u64 {
        self.image_base.wrapping_add(rva)
    }

    /// Read file bytes at a file offset.
    pub fn read_at_offset(&self, offset: u64, len: usize) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        self.bytes.get(start..end)
    }

    /// Read file bytes at a virtual address.
    pub fn read_at_va(&self, va: u64, len: usize) -> Option<&[u8]> {
        let rva = self.va_to_rva(va)?;
        let offset = self.rva_to_offset(rva)?;
        self.read_at_offset(offset, len)
    }

    /// Iterate over executable sections.
    pub fn executable_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections
            .iter()
            .filter(|s| s.executable && s.file_size > 0)
    }

    /// Find a symbol by exact address.
    pub fn symbol_at(&self, address: Address) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.address == address)
    }

    /// Look up a name for a virtual address, if a symbol starts there.
    pub fn name_at(&self, address: Address) -> Option<&str> {
        self.symbol_at(address).map(|s| s.name.as_str())
    }
}
