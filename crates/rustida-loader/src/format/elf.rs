//! ELF loader built on `goblin`.
//!
//! Extracts the ELF header, program headers (segments), section headers with
//! real names, both symbol tables and dynamic imports/exports.

use std::collections::HashSet;
use std::sync::Arc;

use goblin::elf::Elf;
use goblin::elf::header::{
    self, EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC, EM_PPC64, EM_RISCV, EM_X86_64,
};
use goblin::elf::program_header::{PF_R, PF_W, PF_X};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};
use goblin::elf::sym::{STT_OBJECT, STT_TLS};
use rustida_core::{Address, Architecture, Endianness, Permissions, RustidaError, SymbolKind};

use crate::common::{
    Binary, BinaryFormat, BinaryInfo, BinaryKind, Export, Import, Section, Segment, Symbol,
};

/// ELF-specific header details retained for the UI / raw header view.
#[derive(Debug, Clone)]
pub struct ElfInfo {
    /// True for ELF64.
    pub is_64: bool,
    /// Raw `e_type` (ET_EXEC, ET_DYN, ET_REL, ...).
    pub elf_type: u16,
    /// Raw `e_machine`.
    pub machine: u16,
    /// Raw `e_flags`.
    pub flags: u32,
    /// Program interpreter, if any.
    pub interpreter: Option<String>,
    /// SONAME, if any.
    pub soname: Option<String>,
    /// Shared libraries this binary needs.
    pub libraries: Vec<String>,
}

fn map_machine(machine: u16) -> (String, u32) {
    match machine {
        EM_X86_64 => ("x86-64".to_string(), 64),
        EM_386 => ("i386".to_string(), 32),
        EM_AARCH64 => ("aarch64".to_string(), 64),
        EM_ARM => ("arm".to_string(), 32),
        EM_RISCV => ("riscv".to_string(), 64),
        EM_PPC => ("ppc".to_string(), 32),
        EM_PPC64 => ("ppc64".to_string(), 64),
        EM_MIPS => ("mips".to_string(), 32),
        other => (format!("machine-{other}"), 0),
    }
}

fn segment_name(p_type: u32) -> &'static str {
    match p_type {
        goblin::elf::program_header::PT_LOAD => "PT_LOAD",
        goblin::elf::program_header::PT_DYNAMIC => "PT_DYNAMIC",
        goblin::elf::program_header::PT_INTERP => "PT_INTERP",
        goblin::elf::program_header::PT_NOTE => "PT_NOTE",
        goblin::elf::program_header::PT_PHDR => "PT_PHDR",
        goblin::elf::program_header::PT_TLS => "PT_TLS",
        _ => "PT_OTHER",
    }
}

/// Parse an ELF file into the common [`Binary`] model.
pub fn load_elf(data: &[u8]) -> Result<Binary, RustidaError> {
    let elf = Elf::parse(data)
        .map_err(|e| RustidaError::InvalidFormat(format!("ELF parse error: {e}")))?;

    let endianness = if elf.little_endian {
        Endianness::LittleEndian
    } else {
        Endianness::BigEndian
    };
    let bits = if elf.is_64 { 64 } else { 32 };
    let (arch_name, machine_bits) = map_machine(elf.header.e_machine);
    let arch = Architecture {
        name: arch_name,
        bits: if machine_bits == 0 {
            bits
        } else {
            machine_bits
        },
        endianness,
    };

    let format = BinaryFormat::new("ELF", endianness, bits, BinaryKind::Elf);

    let info = ElfInfo {
        is_64: elf.is_64,
        elf_type: elf.header.e_type,
        machine: elf.header.e_machine,
        flags: elf.header.e_flags,
        interpreter: elf.interpreter.map(str::to_string),
        soname: elf.soname.map(str::to_string),
        libraries: elf.libraries.iter().map(|s| (*s).to_string()).collect(),
    };

    let mut segments = Vec::new();
    for ph in &elf.program_headers {
        if ph.p_memsz == 0 {
            continue;
        }
        let permissions = Permissions::from_flags(
            ph.p_flags & PF_R != 0,
            ph.p_flags & PF_W != 0,
            ph.p_flags & PF_X != 0,
        );
        segments.push(Segment {
            name: segment_name(ph.p_type).to_string(),
            address: Address::new(ph.p_vaddr),
            size: ph.p_memsz,
            file_offset: ph.p_offset,
            file_size: ph.p_filesz,
            permissions,
        });
    }

    let mut sections = Vec::new();
    for sh in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let file_size = if sh.sh_type == SHT_NOBITS {
            0
        } else {
            sh.sh_size
                .min(data.len().saturating_sub(sh.sh_offset as usize) as u64)
        };
        let permissions = Permissions::from_flags(
            sh.sh_flags & u64::from(SHF_ALLOC) != 0,
            sh.sh_flags & u64::from(SHF_WRITE) != 0,
            sh.sh_flags & u64::from(SHF_EXECINSTR) != 0,
        );
        sections.push(Section {
            name,
            address: Address::new(sh.sh_addr),
            size: sh.sh_size,
            file_offset: sh.sh_offset,
            file_size,
            permissions,
            executable: sh.sh_flags & u64::from(SHF_EXECINSTR) != 0,
        });
    }

    let mut symbols = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut seen: HashSet<(String, u64, SymbolKind)> = HashSet::new();

    // Full symbol table (may be stripped).
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let kind = if sym.is_import() {
            SymbolKind::Import
        } else if sym.is_function() {
            SymbolKind::Function
        } else {
            match sym.st_type() {
                STT_OBJECT => SymbolKind::Variable,
                STT_TLS => SymbolKind::Tls,
                _ => SymbolKind::Label,
            }
        };
        let address = Address::new(if sym.is_import() { 0 } else { sym.st_value });
        if seen.insert((name.to_string(), address.0, kind)) {
            symbols.push(Symbol {
                name: name.to_string(),
                address,
                size: sym.st_size,
                kind,
            });
        }
    }

    // Dynamic symbols: imports and exports.
    for sym in &elf.dynsyms {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if sym.is_import() {
            if seen.insert((name.to_string(), 0, SymbolKind::Import)) {
                symbols.push(Symbol {
                    name: name.to_string(),
                    address: Address::new(0),
                    size: 0,
                    kind: SymbolKind::Import,
                });
                imports.push(Import {
                    library: String::new(),
                    name: name.to_string(),
                    address: Address::new(0),
                });
            }
            continue;
        }
        if sym.st_value != 0
            && seen.insert((name.to_string(), sym.st_value, SymbolKind::Export))
        {
            symbols.push(Symbol {
                name: name.to_string(),
                address: Address::new(sym.st_value),
                size: sym.st_size,
                kind: SymbolKind::Export,
            });
            exports.push(Export {
                name: name.to_string(),
                address: Address::new(sym.st_value),
                ordinal: None,
            });
        }
    }

    // Sort exports/imports for deterministic output.
    imports.sort_by(|a, b| a.name.cmp(&b.name));
    exports.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Binary {
        format,
        arch,
        entry_point: Address::new(elf.entry),
        image_base: 0,
        headers_size: header::SIZEOF_IDENT as u64,
        segments,
        sections,
        symbols,
        imports,
        exports,
        instructions: Vec::new(),
        bytes: Arc::new(data.to_vec()),
        info: BinaryInfo::Elf(info),
    })
}
