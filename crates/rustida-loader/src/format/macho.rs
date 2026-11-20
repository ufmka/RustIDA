//! Mach-O and Fat/Universal Mach-O loader.
//!
//! Handles 32-bit and 64-bit thin images in both byte orders, decodes load
//! commands (segments, sections, symbol table, dylibs, `LC_MAIN`,
//! `LC_UNIXTHREAD`) and selects a slice from fat containers.

use std::collections::HashSet;
use std::sync::Arc;

use rustida_core::{Address, Architecture, Endianness, Permissions, RustidaError, SymbolKind};

use crate::common::{
    Binary, BinaryFormat, BinaryInfo, BinaryKind, Export, Import, Section, Segment, Symbol,
};

/// 32-bit Mach-O magic (as stored in the file's own byte order).
pub const MH_MAGIC: u32 = 0xfeed_face;
/// 64-bit Mach-O magic.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// Swapped 32-bit Mach-O magic.
pub const MH_CIGAM: u32 = 0xcefa_edfe;
/// Swapped 64-bit Mach-O magic.
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

/// Fat binary magic.
pub const FAT_MAGIC: u32 = 0xcafe_babe;
/// Swapped fat binary magic.
pub const FAT_CIGAM: u32 = 0xbeba_feca;
/// 64-bit fat binary magic.
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Swapped 64-bit fat binary magic.
pub const FAT_CIGAM_64: u32 = 0xbfba_feca;

pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub const CPU_TYPE_POWERPC: u32 = 18;
pub const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;

pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1b;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
pub const LC_MAIN: u32 = 0x8000_0028;

const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_UNDF: u8 = 0x0;
const N_ABS: u8 = 0x2;
const N_SECT: u8 = 0xe;
const N_INDR: u8 = 0xa;
const N_PBUD: u8 = 0xc;

const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

/// Mach-O header.
#[derive(Debug, Clone)]
pub struct MachOHeader {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: Option<u32>,
    pub is_64: bool,
    pub endianness: Endianness,
}

/// Mach-O section.
#[derive(Debug, Clone)]
pub struct MachOSection {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub flags: u32,
    pub executable: bool,
    pub file_backed: bool,
}

/// Mach-O segment.
#[derive(Debug, Clone)]
pub struct MachOSegment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: i32,
    pub initprot: i32,
    pub flags: u32,
    pub sections: Vec<MachOSection>,
}

impl MachOSegment {
    /// Permissions from the segment's initial protection.
    pub fn permissions(&self) -> Permissions {
        Permissions::from_flags(
            self.initprot & 1 != 0,
            self.initprot & 2 != 0,
            self.initprot & 4 != 0,
        )
    }
}

/// Mach-O symbol (`nlist`).
#[derive(Debug, Clone)]
pub struct MachOSymbol {
    pub name: String,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub value: u64,
    pub external: bool,
}

/// Referenced dynamic library.
#[derive(Debug, Clone)]
pub struct MachODylib {
    pub name: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    /// True for `LC_ID_DYLIB` (the library itself, not a dependency).
    pub is_self: bool,
}

/// One architecture entry in a fat header.
#[derive(Debug, Clone)]
pub struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

/// A fat / universal Mach-O container.
#[derive(Debug, Clone)]
pub struct FatMachO {
    pub archs: Vec<FatArch>,
    /// True when the container used the 64-bit `fat_arch_64` layout.
    pub is_64_bit_table: bool,
    /// True when multi-architecture entries were big-endian.
    pub big_endian: bool,
}

/// Everything parsed from a thin Mach-O image.
#[derive(Debug, Clone)]
pub struct MachOImage {
    pub header: MachOHeader,
    pub segments: Vec<MachOSegment>,
    pub symbols: Vec<MachOSymbol>,
    pub dylibs: Vec<MachODylib>,
    pub uuid: Option<[u8; 16]>,
    /// Entry point virtual address (0 if unknown).
    pub entry_point: u64,
    /// Raw `LC_MAIN.entryoff`, when present.
    pub entry_file_offset: Option<u64>,
    pub fat_archs: Vec<FatArch>,
}

/// Summary of Mach-O-specific details retained in the common [`Binary`].
#[derive(Debug, Clone)]
pub struct MachOInfo {
    pub is_64: bool,
    pub endianness: Endianness,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub flags: u32,
    pub dylibs: Vec<MachODylib>,
    pub uuid: Option<[u8; 16]>,
    pub entry_file_offset: Option<u64>,
    pub fat_archs: Vec<FatArch>,
}

impl MachOInfo {
    /// Whether the image came from a fat container.
    pub fn is_fat(&self) -> bool {
        !self.fat_archs.is_empty()
    }
}

struct Reader<'a> {
    data: &'a [u8],
    endianness: Endianness,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], endianness: Endianness) -> Self {
        Reader { data, endianness }
    }

    fn u16(&self, offset: usize) -> Result<u16, RustidaError> {
        let b = self
            .data
            .get(offset..offset + 2)
            .ok_or_else(|| RustidaError::truncated(offset, 2, self.data.len()))?;
        Ok(match self.endianness {
            Endianness::LittleEndian => u16::from_le_bytes([b[0], b[1]]),
            Endianness::BigEndian => u16::from_be_bytes([b[0], b[1]]),
        })
    }

    fn u32(&self, offset: usize) -> Result<u32, RustidaError> {
        let b = self
            .data
            .get(offset..offset + 4)
            .ok_or_else(|| RustidaError::truncated(offset, 4, self.data.len()))?;
        Ok(match self.endianness {
            Endianness::LittleEndian => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Endianness::BigEndian => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        })
    }

    fn u64(&self, offset: usize) -> Result<u64, RustidaError> {
        let b = self
            .data
            .get(offset..offset + 8)
            .ok_or_else(|| RustidaError::truncated(offset, 8, self.data.len()))?;
        Ok(match self.endianness {
            Endianness::LittleEndian => {
                u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
            Endianness::BigEndian => {
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
            }
        })
    }

    fn fixed_str(&self, offset: usize, len: usize) -> String {
        let Some(bytes) = self.data.get(offset..offset + len) else {
            return String::new();
        };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(len);
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn cstr(&self, offset: usize, max_len: usize) -> Option<String> {
        let slice = self.data.get(offset..)?;
        let end = slice
            .iter()
            .take(max_len)
            .position(|&b| b == 0)
            .unwrap_or_else(|| slice.len().min(max_len));
        if end == 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&slice[..end]).into_owned())
    }
}

fn arch_for_cpu(cputype: u32, endianness: Endianness) -> Architecture {
    match cputype {
        CPU_TYPE_X86_64 => Architecture::new("x86-64", 64, endianness),
        CPU_TYPE_X86 => Architecture::new("i386", 32, endianness),
        CPU_TYPE_ARM64 => Architecture::new("aarch64", 64, endianness),
        CPU_TYPE_ARM => Architecture::new("arm", 32, endianness),
        CPU_TYPE_POWERPC => Architecture::new("ppc", 32, endianness),
        CPU_TYPE_POWERPC64 => Architecture::new("ppc64", 64, endianness),
        other => Architecture::new(
            format!("cputype-{other:#x}"),
            if cputype & 0x0100_0000 != 0 { 64 } else { 32 },
            endianness,
        ),
    }
}

fn cpu_name(cputype: u32) -> &'static str {
    match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_X86 => "i386",
        CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_ARM => "arm",
        CPU_TYPE_POWERPC => "ppc",
        CPU_TYPE_POWERPC64 => "ppc64",
        _ => "unknown",
    }
}

/// Detect whether `data` starts with a fat Mach-O header.
pub fn is_fat_macho(data: &[u8]) -> bool {
    matches!(
        data.get(0..4),
        Some([0xca, 0xfe, 0xba, 0xbe])
            | Some([0xbe, 0xba, 0xfe, 0xca])
            | Some([0xca, 0xfe, 0xba, 0xbf])
            | Some([0xbf, 0xba, 0xfe, 0xca])
    )
}

/// Detect whether `data` starts with a thin Mach-O header.
pub fn is_thin_macho(data: &[u8]) -> bool {
    matches!(
        data.get(0..4),
        Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
    )
}

/// Parse a fat header.
pub fn parse_fat_macho(data: &[u8]) -> Result<FatMachO, RustidaError> {
    let magic = data
        .get(0..4)
        .ok_or_else(|| RustidaError::truncated(0, 4, data.len()))?;
    let (big_endian, is_64_bit_table) = match magic {
        [0xca, 0xfe, 0xba, 0xbe] => (true, false),
        [0xbe, 0xba, 0xfe, 0xca] => (false, false),
        [0xca, 0xfe, 0xba, 0xbf] => (true, true),
        [0xbf, 0xba, 0xfe, 0xca] => (false, true),
        _ => {
            return Err(RustidaError::InvalidFormat(
                "not a fat Mach-O container".to_string(),
            ));
        }
    };

    let reader = Reader::new(
        data,
        if big_endian {
            Endianness::BigEndian
        } else {
            Endianness::LittleEndian
        },
    );
    let count = reader.u32(4)? as usize;
    if count == 0 || count > 128 {
        return Err(RustidaError::malformed(format!(
            "implausible fat architecture count {count}"
        )));
    }
    let entry_size = if is_64_bit_table { 32 } else { 20 };
    let table_end = 8 + count * entry_size;
    if table_end > data.len() {
        return Err(RustidaError::truncated(8, count * entry_size, data.len()));
    }

    let mut archs = Vec::with_capacity(count);
    for index in 0..count {
        let base = 8 + index * entry_size;
        let (cputype, cpusubtype, offset, size, align) = if is_64_bit_table {
            (
                reader.u32(base)?,
                reader.u32(base + 4)?,
                reader.u64(base + 8)?,
                reader.u64(base + 16)?,
                reader.u32(base + 24)?,
            )
        } else {
            (
                reader.u32(base)?,
                reader.u32(base + 4)?,
                u64::from(reader.u32(base + 8)?),
                u64::from(reader.u32(base + 12)?),
                reader.u32(base + 16)?,
            )
        };
        if size == 0 {
            return Err(RustidaError::malformed("fat slice has zero size"));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| RustidaError::malformed("fat slice offset overflow"))?;
        if offset < table_end as u64 || end > data.len() as u64 {
            return Err(RustidaError::malformed(format!(
                "fat slice {index} out of bounds (offset {offset:#x}, size {size:#x})"
            )));
        }
        archs.push(FatArch {
            cputype,
            cpusubtype,
            offset,
            size,
            align,
        });
    }

    Ok(FatMachO {
        archs,
        is_64_bit_table,
        big_endian,
    })
}

impl FatMachO {
    /// Return the raw slice for an architecture entry.
    pub fn slice<'a>(&self, data: &'a [u8], arch: &FatArch) -> Result<&'a [u8], RustidaError> {
        let start = usize::try_from(arch.offset)
            .map_err(|_| RustidaError::malformed("fat slice offset too large"))?;
        let end = usize::try_from(arch.offset + arch.size)
            .map_err(|_| RustidaError::malformed("fat slice end too large"))?;
        data.get(start..end)
            .ok_or_else(|| RustidaError::malformed("fat slice outside file"))
    }

    /// Choose a slice, preferring x86-64, then arm64, then the first entry.
    pub fn select(&self) -> Option<&FatArch> {
        for preferred in [CPU_TYPE_X86_64, CPU_TYPE_ARM64] {
            if let Some(arch) = self.archs.iter().find(|a| a.cputype == preferred) {
                return Some(arch);
            }
        }
        self.archs.first()
    }

    /// Choose the slice matching `cputype`.
    pub fn select_cpu(&self, cputype: u32) -> Option<&FatArch> {
        self.archs.iter().find(|a| a.cputype == cputype)
    }
}

fn resolve_entry_from_file_offset(segments: &[MachOSegment], entryoff: u64) -> u64 {
    for segment in segments {
        if segment.filesize > 0
            && entryoff >= segment.fileoff
            && entryoff < segment.fileoff.saturating_add(segment.filesize)
        {
            return segment
                .vmaddr
                .wrapping_add(entryoff.wrapping_sub(segment.fileoff));
        }
    }
    entryoff
}

fn parse_entry_thread_state(
    reader: &Reader<'_>,
    cmd_offset: usize,
    cmdsize: u32,
    cputype: u32,
) -> Option<u64> {
    let flavor = reader.u32(cmd_offset + 8).ok()?;
    let count = reader.u32(cmd_offset + 12).ok()?;
    let state = cmd_offset + 16;
    let state_len = (count as usize).saturating_mul(4);
    if cmdsize as usize > state_len {
        return None;
    }
    match cputype {
        CPU_TYPE_X86_64 if flavor == 4 && count >= 21 => reader.u64(state + 16 * 8).ok(),
        CPU_TYPE_X86 if flavor == 1 && count >= 16 => {
            Some(u64::from(reader.u32(state + 10 * 4).ok()?))
        }
        CPU_TYPE_ARM64 if flavor == 6 && count >= 68 => reader.u64(state + 32 * 8).ok(),
        CPU_TYPE_ARM if flavor == 1 && count >= 17 => {
            Some(u64::from(reader.u32(state + 15 * 4).ok()?))
        }
        _ => None,
    }
}

fn parse_thin(data: &[u8], fat_archs: Vec<FatArch>) -> Result<MachOImage, RustidaError> {
    let magic_bytes = data
        .get(0..4)
        .ok_or_else(|| RustidaError::truncated(0, 4, data.len()))?;
    let (is_64, endianness) = match magic_bytes {
        [0xce, 0xfa, 0xed, 0xfe] => (false, Endianness::LittleEndian),
        [0xcf, 0xfa, 0xed, 0xfe] => (true, Endianness::LittleEndian),
        [0xfe, 0xed, 0xfa, 0xce] => (false, Endianness::BigEndian),
        [0xfe, 0xed, 0xfa, 0xcf] => (true, Endianness::BigEndian),
        _ => {
            return Err(RustidaError::InvalidFormat(
                "not a thin Mach-O image".to_string(),
            ));
        }
    };
    let reader = Reader::new(data, endianness);
    let header_size = if is_64 { 32 } else { 28 };
    if data.len() < header_size {
        return Err(RustidaError::truncated(0, header_size, data.len()));
    }

    let header = MachOHeader {
        magic: reader.u32(0)?,
        cputype: reader.u32(4)?,
        cpusubtype: reader.u32(8)?,
        filetype: reader.u32(12)?,
        ncmds: reader.u32(16)?,
        sizeofcmds: reader.u32(20)?,
        flags: reader.u32(24)?,
        reserved: if is_64 { Some(reader.u32(28)?) } else { None },
        is_64,
        endianness,
    };

    let commands_end = header_size
        .checked_add(header.sizeofcmds as usize)
        .ok_or_else(|| RustidaError::malformed("load-command size overflow"))?;
    if commands_end > data.len() {
        return Err(RustidaError::truncated(
            header_size,
            header.sizeofcmds as usize,
            data.len(),
        ));
    }
    if header.ncmds > 65_536 {
        return Err(RustidaError::malformed(
            "implausible Mach-O load command count",
        ));
    }

    let mut segments: Vec<MachOSegment> = Vec::new();
    let mut symbols: Vec<MachOSymbol> = Vec::new();
    let mut dylibs: Vec<MachODylib> = Vec::new();
    let mut uuid = None;
    let mut entry_file_offset = None;
    let mut entry_from_thread = None;

    let mut offset = header_size;
    for _ in 0..header.ncmds {
        if offset + 8 > commands_end {
            return Err(RustidaError::malformed("load command header out of range"));
        }
        let cmd = reader.u32(offset)?;
        let cmdsize = reader.u32(offset + 4)?;
        if cmdsize < 8 || offset + cmdsize as usize > commands_end {
            return Err(RustidaError::malformed(format!(
                "invalid load command size {cmdsize} at {offset:#x}"
            )));
        }

        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let is_seg64 = cmd == LC_SEGMENT_64;
                if is_seg64 != is_64 {
                    // Mixed segment commands are legal in principle but not
                    // something this loader needs to support.
                }
                let name = reader.fixed_str(offset + 8, 16);
                let (
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    nsects,
                    flags,
                    sections_base,
                    section_size,
                ) = if is_seg64 {
                    (
                        reader.u64(offset + 24)?,
                        reader.u64(offset + 32)?,
                        reader.u64(offset + 40)?,
                        reader.u64(offset + 48)?,
                        reader.u32(offset + 56)? as i32,
                        reader.u32(offset + 60)? as i32,
                        reader.u32(offset + 64)?,
                        reader.u32(offset + 68)?,
                        offset + 72,
                        80usize,
                    )
                } else {
                    (
                        u64::from(reader.u32(offset + 24)?),
                        u64::from(reader.u32(offset + 28)?),
                        u64::from(reader.u32(offset + 32)?),
                        u64::from(reader.u32(offset + 36)?),
                        reader.u32(offset + 40)? as i32,
                        reader.u32(offset + 44)? as i32,
                        reader.u32(offset + 48)?,
                        reader.u32(offset + 52)?,
                        offset + 56,
                        68usize,
                    )
                };
                if nsects > 65_536 {
                    return Err(RustidaError::malformed("implausible Mach-O section count"));
                }
                let needed = (nsects as usize)
                    .checked_mul(section_size)
                    .ok_or_else(|| RustidaError::malformed("section table overflow"))?;
                if sections_base + needed > offset + cmdsize as usize {
                    return Err(RustidaError::malformed(
                        "segment section table exceeds load command",
                    ));
                }

                let section_exec = initprot & 4 != 0;
                let mut sections = Vec::with_capacity(nsects as usize);
                for section_index in 0..nsects as usize {
                    let base = sections_base + section_index * section_size;
                    let sectname = reader.fixed_str(base, 16);
                    let segname = reader.fixed_str(base + 16, 16);
                    let (addr, size, file_offset, align, flags) = if is_seg64 {
                        (
                            reader.u64(base + 32)?,
                            reader.u64(base + 40)?,
                            reader.u32(base + 48)?,
                            reader.u32(base + 52)?,
                            reader.u32(base + 64)?,
                        )
                    } else {
                        (
                            u64::from(reader.u32(base + 32)?),
                            u64::from(reader.u32(base + 36)?),
                            reader.u32(base + 40)?,
                            reader.u32(base + 44)?,
                            reader.u32(base + 56)?,
                        )
                    };
                    let section_type = flags & 0xff;
                    let file_backed = !matches!(
                        section_type,
                        S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
                    );
                    let executable = section_exec
                        || flags & S_ATTR_PURE_INSTRUCTIONS != 0
                        || flags & S_ATTR_SOME_INSTRUCTIONS != 0
                        || (segname == "__TEXT" && sectname == "__text");
                    sections.push(MachOSection {
                        sectname,
                        segname,
                        addr,
                        size,
                        offset: file_offset,
                        align,
                        flags,
                        executable,
                        file_backed,
                    });
                }

                segments.push(MachOSegment {
                    name,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    maxprot,
                    initprot,
                    flags,
                    sections,
                });
            }
            LC_SYMTAB => {
                let symoff = reader.u32(offset + 8)? as usize;
                let nsyms = reader.u32(offset + 12)? as usize;
                let stroff = reader.u32(offset + 16)? as usize;
                let strsize = reader.u32(offset + 20)? as usize;
                if nsyms > 0 {
                    if nsyms > 1_000_000 {
                        return Err(RustidaError::malformed("implausible Mach-O symbol count"));
                    }
                    let entry_size = if is_64 { 16 } else { 12 };
                    let sym_end = symoff
                        .checked_add(nsyms * entry_size)
                        .ok_or_else(|| RustidaError::malformed("symbol table overflow"))?;
                    let str_end = stroff
                        .checked_add(strsize)
                        .ok_or_else(|| RustidaError::malformed("string table overflow"))?;
                    if sym_end > data.len() || str_end > data.len() {
                        return Err(RustidaError::malformed("symbol table outside file"));
                    }
                    for index in 0..nsyms {
                        let base = symoff + index * entry_size;
                        let strx = reader.u32(base)? as usize;
                        let n_type = *data
                            .get(base + 4)
                            .ok_or_else(|| RustidaError::truncated(base + 4, 1, data.len()))?;
                        let n_sect = *data
                            .get(base + 5)
                            .ok_or_else(|| RustidaError::truncated(base + 5, 1, data.len()))?;
                        let n_desc = reader.u16(base + 6)?;
                        let value = if is_64 {
                            reader.u64(base + 8)?
                        } else {
                            u64::from(reader.u32(base + 8)?)
                        };
                        let name = reader
                            .cstr(stroff + strx, strsize.saturating_sub(strx))
                            .unwrap_or_default();
                        if name.is_empty() || n_type & N_STAB != 0 {
                            continue;
                        }
                        symbols.push(MachOSymbol {
                            name,
                            n_type,
                            n_sect,
                            n_desc,
                            value,
                            external: n_type & N_EXT != 0,
                        });
                    }
                }
            }
            LC_LOAD_DYLIB | LC_ID_DYLIB | LC_LAZY_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB
            | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                let name_offset = reader.u32(offset + 8)? as usize;
                let name = reader
                    .cstr(offset + name_offset, cmdsize as usize - name_offset)
                    .unwrap_or_default();
                dylibs.push(MachODylib {
                    name,
                    current_version: reader.u32(offset + 12)?,
                    compatibility_version: reader.u32(offset + 16)?,
                    is_self: cmd == LC_ID_DYLIB,
                });
            }
            LC_MAIN => {
                entry_file_offset = Some(reader.u64(offset + 8)?);
            }
            LC_UNIXTHREAD => {
                if entry_from_thread.is_none() {
                    entry_from_thread =
                        parse_entry_thread_state(&reader, offset, cmdsize, header.cputype);
                }
            }
            LC_UUID => {
                if let Some(bytes) = data.get(offset + 8..offset + 24) {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(bytes);
                    uuid = Some(id);
                }
            }
            LC_LOAD_DYLINKER => {
                // The dynamic linker path is interesting for display but not
                // required for analysis; kept out of the common model.
            }
            _ => {}
        }

        offset += cmdsize as usize;
    }

    let entry_point = if let Some(entryoff) = entry_file_offset {
        resolve_entry_from_file_offset(&segments, entryoff)
    } else if let Some(entry) = entry_from_thread {
        entry
    } else {
        segments
            .iter()
            .flat_map(|s| s.sections.iter())
            .find(|s| s.executable)
            .map(|s| s.addr)
            .unwrap_or(0)
    };

    Ok(MachOImage {
        header,
        segments,
        symbols,
        dylibs,
        uuid,
        entry_point,
        entry_file_offset,
        fat_archs,
    })
}

/// Parse a thin Mach-O image.
pub fn parse_macho(data: &[u8]) -> Result<MachOImage, RustidaError> {
    if is_fat_macho(data) {
        return Err(RustidaError::InvalidFormat(
            "fat Mach-O passed to thin parser".to_string(),
        ));
    }
    parse_thin(data, Vec::new())
}

/// Convert a parsed thin image into the common model.
fn image_to_binary(
    data: &[u8],
    image: MachOImage,
    kind: BinaryKind,
    format_name: &str,
) -> Result<Binary, RustidaError> {
    let endianness = image.header.endianness;
    let arch = arch_for_cpu(image.header.cputype, endianness);
    let bits = if image.header.is_64 { 64 } else { 32 };
    let format = BinaryFormat::new(format_name, endianness, bits, kind);

    let mut segments = Vec::new();
    let mut sections = Vec::new();
    for segment in &image.segments {
        segments.push(Segment {
            name: segment.name.clone(),
            address: Address::new(segment.vmaddr),
            size: segment.vmsize,
            file_offset: segment.fileoff,
            file_size: segment
                .filesize
                .min(data.len().saturating_sub(segment.fileoff as usize) as u64),
            permissions: segment.permissions(),
        });
        for section in &segment.sections {
            let file_size = if section.file_backed {
                section
                    .size
                    .min(data.len().saturating_sub(section.offset as usize) as u64)
            } else {
                0
            };
            sections.push(Section {
                name: format!("{},{}", section.segname, section.sectname),
                address: Address::new(section.addr),
                size: section.size,
                file_offset: u64::from(section.offset),
                file_size,
                permissions: segment.permissions(),
                executable: section.executable,
            });
        }
    }

    let mut all_sections = Vec::new();
    for segment in &image.segments {
        all_sections.extend(segment.sections.iter().cloned());
    }

    let mut symbol_model = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut seen: HashSet<(String, u64, SymbolKind)> = HashSet::new();
    for sym in &image.symbols {
        let type_bits = sym.n_type & N_TYPE;
        if type_bits == N_UNDF || type_bits == N_PBUD {
            if seen.insert((sym.name.clone(), 0, SymbolKind::Import)) {
                symbol_model.push(Symbol {
                    name: sym.name.clone(),
                    address: Address::new(0),
                    size: 0,
                    kind: SymbolKind::Import,
                });
                imports.push(Import {
                    library: String::new(),
                    name: sym.name.clone(),
                    address: Address::new(0),
                });
            }
            continue;
        }
        let section = if sym.n_sect > 0 {
            all_sections.get(sym.n_sect as usize - 1)
        } else {
            None
        };
        let kind = match type_bits {
            N_SECT => {
                if section.is_some_and(|s| s.executable) {
                    SymbolKind::Function
                } else {
                    SymbolKind::Variable
                }
            }
            N_ABS => SymbolKind::Variable,
            N_INDR => SymbolKind::Label,
            _ => SymbolKind::Label,
        };
        if seen.insert((sym.name.clone(), sym.value, kind)) {
            symbol_model.push(Symbol {
                name: sym.name.clone(),
                address: Address::new(sym.value),
                size: 0,
                kind,
            });
        }
        if sym.external && sym.value != 0 && kind == SymbolKind::Function {
            exports.push(Export {
                name: sym.name.clone(),
                address: Address::new(sym.value),
                ordinal: None,
            });
        }
    }
    imports.sort_by(|a, b| a.name.cmp(&b.name));
    exports.sort_by(|a, b| a.name.cmp(&b.name));

    let info = MachOInfo {
        is_64: image.header.is_64,
        endianness,
        cputype: image.header.cputype,
        cpusubtype: image.header.cpusubtype,
        filetype: image.header.filetype,
        flags: image.header.flags,
        dylibs: image.dylibs.clone(),
        uuid: image.uuid,
        entry_file_offset: image.entry_file_offset,
        fat_archs: image.fat_archs.clone(),
    };

    Ok(Binary {
        format,
        arch,
        entry_point: Address::new(image.entry_point),
        image_base: 0,
        headers_size: 0,
        segments,
        sections,
        symbols: symbol_model,
        imports,
        exports,
        instructions: Vec::new(),
        bytes: Arc::new(data.to_vec()),
        info: BinaryInfo::MachO(Box::new(info)),
    })
}

/// Load a thin Mach-O file.
pub fn load_mach_o_thin(data: &[u8]) -> Result<Binary, RustidaError> {
    let image = parse_macho(data)?;
    let name = if image.header.is_64 {
        "Mach-O 64"
    } else {
        "Mach-O 32"
    };
    image_to_binary(data, image, BinaryKind::MachO, name)
}

/// Load a Mach-O file, transparently handling fat containers.
///
/// For fat files the x86-64 slice is preferred, then arm64, then the first
/// architecture. Use [`load_mach_o_cpu`] to select a specific slice.
pub fn load_mach_o(data: &[u8]) -> Result<Binary, RustidaError> {
    if is_fat_macho(data) {
        let fat = parse_fat_macho(data)?;
        let arch = fat
            .select()
            .ok_or_else(|| RustidaError::malformed("fat Mach-O has no slices"))?
            .clone();
        return load_mach_o_cpu_from_fat(data, &fat, &arch);
    }
    load_mach_o_thin(data)
}

/// Load a specific CPU slice from a fat container.
pub fn load_mach_o_cpu(data: &[u8], cputype: u32) -> Result<Binary, RustidaError> {
    let fat = parse_fat_macho(data)?;
    let arch = fat
        .select_cpu(cputype)
        .ok_or_else(|| {
            RustidaError::UnsupportedArchitecture(format!(
                "fat Mach-O has no slice for {} ({cputype:#x})",
                cpu_name(cputype)
            ))
        })?
        .clone();
    load_mach_o_cpu_from_fat(data, &fat, &arch)
}

fn load_mach_o_cpu_from_fat(
    data: &[u8],
    fat: &FatMachO,
    arch: &FatArch,
) -> Result<Binary, RustidaError> {
    let slice = fat.slice(data, arch)?;
    let image = parse_thin(slice, fat.archs.clone())?;
    let name = format!("Fat Mach-O ({})", cpu_name(arch.cputype));
    image_to_binary(slice, image, BinaryKind::FatMachO, &name)
}

/// List the architectures available in a fat container without loading a slice.
pub fn list_fat_architectures(data: &[u8]) -> Result<Vec<FatArch>, RustidaError> {
    Ok(parse_fat_macho(data)?.archs)
}
