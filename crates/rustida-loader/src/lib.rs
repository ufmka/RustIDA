//! **rustida-loader** — binary parsing, disassembly and analysis for RustIDA.
//!
//! # Supported containers
//!
//! * ELF32 / ELF64 (via `goblin`)
//! * PE32 / PE32+
//! * Mach-O 32-bit / 64-bit, both byte orders
//! * Fat / Universal Mach-O with architecture selection
//!
//! Every loader returns the same [`Binary`] model, which keeps the original
//! bytes, segments, sections, symbols, imports, exports, entry point and
//! address-translation helpers. Format-specific headers remain available
//! through [`BinaryInfo`].
//!
//! # Disassembly
//!
//! [`disassemble_binary`] decodes every executable section with `iced-x86` at
//! its real virtual address. [`analyze_binary`] then builds basic blocks, a
//! CFG, cross-references, functions and a call graph.

#![forbid(unsafe_code)]

pub mod analysis;
pub mod common;
pub mod disasm;
pub mod format;

pub use rustida_core::{Address, Architecture, Endianness, Permissions, RustidaError, SymbolKind};

pub use analysis::{
    BasicBlock, BinaryAnalysis, BlockTerminator, CFGEdge, CFGEdgeType, CFGNode, CallGraphEdge,
    CallSite, CrossReference, CrossReferenceType, DisassembledFunction, DisassemblyAnalysis,
    analyze_binary, analyze_disassembly, build_basic_blocks, build_call_graph, build_cfg,
    detect_functions, detect_functions_in_binary, extract_call_sites, extract_xrefs,
};
pub use common::{
    Binary, BinaryFormat, BinaryInfo, BinaryKind, Export, Import, Section, Segment, Symbol,
};
pub use disasm::{
    DisassembledInstruction, InstructionFlow, Operand, disassemble, disassemble_at,
    disassemble_binary, disassemble_binary_in_place,
};
pub use format::{
    FormatKind, detect_format, elf::load_elf, load_binary, load_file, load_mach_o, load_mach_o_cpu,
    load_mach_o_thin, load_pe, macho::parse_fat_macho, macho::parse_macho, pe::PEFormat,
    pe::parse_pe,
};

/// Re-export of the PE parser's detailed structures.
pub mod pe {
    pub use crate::format::pe::{
        PEExport, PEFormat, PEImport, PeImage, SectionHeader, load_pe, parse_pe,
    };
}

/// Re-export of the Mach-O parser's detailed structures.
pub mod macho {
    pub use crate::format::macho::{
        FatArch, FatMachO, MachODylib, MachOHeader, MachOImage, MachOSection, MachOSegment,
        MachOSymbol, is_fat_macho, is_thin_macho, list_fat_architectures, load_mach_o,
        load_mach_o_cpu, load_mach_o_thin, parse_fat_macho, parse_macho,
    };
}

/// Re-export of the ELF parser's detailed structures.
pub mod elf {
    pub use crate::format::elf::{ElfInfo, load_elf};
}
