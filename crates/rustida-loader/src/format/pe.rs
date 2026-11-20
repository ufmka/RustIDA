//! PE32 / PE32+ loader.
//!
//! The parser is written directly against the on-disk structures so that every
//! field is actually validated and extracted. All reads are bounds-checked and
//! malformed input produces a structured error instead of a panic.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use rustida_core::{Address, Architecture, Endianness, Permissions, RustidaError, SymbolKind};

use crate::common::{
    Binary, BinaryFormat, BinaryInfo, BinaryKind, Export, Import, Section, Segment, Symbol,
};

/// PE flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PEFormat {
    /// PE32 (32-bit optional header).
    Pe32,
    /// PE32+ (64-bit optional header).
    Pe32Plus,
}

/// COFF file header.
#[derive(Debug, Clone)]
pub struct COFFHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// One optional-header data directory.
#[derive(Debug, Clone)]
pub struct DataDirectory {
    /// Directory index (0 = export, 1 = import, ...).
    pub index: usize,
    /// Human-readable directory name.
    pub name: &'static str,
    /// RVA of the directory.
    pub virtual_address: u32,
    /// Size in bytes.
    pub size: u32,
}

/// Parsed optional header (common subset for PE32 and PE32+).
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub number_of_rva_and_sizes: u32,
    pub data_directories: Vec<DataDirectory>,
}

/// Section header.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
    pub permissions: Permissions,
    pub executable: bool,
}

/// Imported function.
#[derive(Debug, Clone)]
pub struct PEImport {
    /// DLL name.
    pub library: String,
    /// Function name or `#ordinal`.
    pub name: String,
    /// Ordinal, when imported by ordinal.
    pub ordinal: Option<u16>,
    /// RVA of the IAT slot.
    pub iat_rva: u32,
}

/// Exported function.
#[derive(Debug, Clone)]
pub struct PEExport {
    pub name: String,
    pub rva: u32,
    pub ordinal: u32,
    pub forwarder: Option<String>,
}

/// Everything parsed from a PE file.
#[derive(Debug, Clone)]
pub struct PeImage {
    pub format: PEFormat,
    pub coff: COFFHeader,
    pub optional: OptionalHeader,
    pub sections: Vec<SectionHeader>,
    pub imports: Vec<PEImport>,
    pub exports: Vec<PEExport>,
    /// Entry point RVA (convenience copy of `optional.entry_point`).
    pub entry_point_rva: u32,
    /// True when the COFF characteristics mark a DLL.
    pub is_dll: bool,
}

const PE_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x010b;
const PE32_PLUS_MAGIC: u16 = 0x020b;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const DIRECTORY_NAMES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "base-relocation",
    "debug",
    "architecture",
    "global-pointer",
    "tls",
    "load-config",
    "bound-import",
    "iat",
    "delay-import",
    "clr",
    "reserved",
];

fn read_u16(data: &[u8], offset: usize) -> Result<u16, RustidaError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| RustidaError::truncated(offset, 2, data.len()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, RustidaError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or_else(|| RustidaError::truncated(offset, 4, data.len()))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, RustidaError> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or_else(|| RustidaError::truncated(offset, 8, data.len()))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_u8(data: &[u8], offset: usize) -> Result<u8, RustidaError> {
    data.get(offset)
        .copied()
        .ok_or_else(|| RustidaError::truncated(offset, 1, data.len()))
}

fn read_cstr(data: &[u8], offset: usize, max_len: usize) -> Option<String> {
    let slice = data.get(offset..)?;
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

fn arch_for_machine(machine: u16, is_64: bool) -> Architecture {
    let (name, bits) = match machine {
        0x8664 => ("x86-64", 64),
        0x014c => ("i386", 32),
        0xaa64 => ("aarch64", 64),
        0x01c0 | 0x01c4 => ("arm", 32),
        0x0200 => ("ia64", 64),
        0x5032 => ("riscv32", 32),
        0x5064 => ("riscv64", 64),
        other => {
            return Architecture::new(
                format!("machine-{other:#x}"),
                if is_64 { 64 } else { 32 },
                Endianness::LittleEndian,
            );
        }
    };
    Architecture::new(name, bits, Endianness::LittleEndian)
}

/// Translate an RVA inside a PE image to a file offset using the section table.
fn rva_to_offset(rva: u32, sections: &[SectionHeader], headers_size: u32) -> Option<usize> {
    if rva < headers_size {
        return Some(rva as usize);
    }
    for section in sections {
        let span = section.virtual_size.max(section.size_of_raw_data);
        if rva >= section.virtual_address && rva < section.virtual_address.saturating_add(span) {
            let delta = rva - section.virtual_address;
            if delta >= section.size_of_raw_data {
                return None;
            }
            return Some(section.pointer_to_raw_data as usize + delta as usize);
        }
    }
    None
}

fn parse_sections(
    data: &[u8],
    table_offset: usize,
    count: u16,
    size_of_optional_header: u16,
    optional_offset: usize,
) -> Result<Vec<SectionHeader>, RustidaError> {
    let _ = size_of_optional_header;
    let _ = optional_offset;
    let mut sections = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let base = table_offset + index * 40;
        let name_bytes = data
            .get(base..base + 8)
            .ok_or_else(|| RustidaError::truncated(base, 8, data.len()))?;
        let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
        let virtual_size = read_u32(data, base + 8)?;
        let virtual_address = read_u32(data, base + 12)?;
        let size_of_raw_data = read_u32(data, base + 16)?;
        let pointer_to_raw_data = read_u32(data, base + 20)?;
        let characteristics = read_u32(data, base + 36)?;

        // A section that claims file-backed bytes past EOF means the file is
        // truncated; report it instead of silently returning a short section.
        if size_of_raw_data > 0 {
            let raw_end = (pointer_to_raw_data as usize)
                .checked_add(size_of_raw_data as usize)
                .ok_or_else(|| RustidaError::malformed("section raw-data range overflow"))?;
            if raw_end > data.len() {
                return Err(RustidaError::truncated(
                    pointer_to_raw_data as usize,
                    size_of_raw_data as usize,
                    data.len(),
                ));
            }
        }

        let executable = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
        let readable = characteristics & IMAGE_SCN_MEM_READ != 0 || !executable;
        let writable = characteristics & IMAGE_SCN_MEM_WRITE != 0;
        let permissions = Permissions::from_flags(readable, writable, executable);

        sections.push(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            characteristics,
            permissions,
            executable,
        });
    }
    Ok(sections)
}

fn parse_imports(
    data: &[u8],
    directory: &DataDirectory,
    sections: &[SectionHeader],
    headers_size: u32,
    is_64: bool,
) -> Result<Vec<PEImport>, RustidaError> {
    if directory.virtual_address == 0 {
        return Ok(Vec::new());
    }
    let Some(desc_offset) = rva_to_offset(directory.virtual_address, sections, headers_size) else {
        return Ok(Vec::new());
    };

    let mut imports = Vec::new();
    let thunk_size = if is_64 { 8u32 } else { 4u32 };
    let ordinal_flag: u64 = if is_64 { 1u64 << 63 } else { 1u64 << 31 };

    for descriptor_index in 0..512usize {
        let base = desc_offset + descriptor_index * 20;
        if base + 20 > data.len() {
            break;
        }
        let original_first_thunk = read_u32(data, base)?;
        let name_rva = read_u32(data, base + 12)?;
        let first_thunk = read_u32(data, base + 16)?;
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let library = rva_to_offset(name_rva, sections, headers_size)
            .and_then(|off| read_cstr(data, off, 512))
            .unwrap_or_default();
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let Some(thunk_offset) = rva_to_offset(thunk_rva, sections, headers_size) else {
            continue;
        };

        for slot in 0..65_536u32 {
            let entry_offset = thunk_offset + (slot as usize) * thunk_size as usize;
            let entry = if is_64 {
                match read_u64(data, entry_offset) {
                    Ok(v) => v,
                    Err(_) => break,
                }
            } else {
                match read_u32(data, entry_offset) {
                    Ok(v) => u64::from(v),
                    Err(_) => break,
                }
            };
            if entry == 0 {
                break;
            }
            let iat_rva = first_thunk.wrapping_add(slot.wrapping_mul(thunk_size));
            if entry & ordinal_flag != 0 {
                let ordinal = (entry & 0xffff) as u16;
                imports.push(PEImport {
                    library: library.clone(),
                    name: format!("#{ordinal}"),
                    ordinal: Some(ordinal),
                    iat_rva,
                });
            } else {
                let hint_name_rva = (entry & 0x7fff_ffff) as u32;
                let name = rva_to_offset(hint_name_rva, sections, headers_size)
                    .and_then(|off| read_cstr(data, off + 2, 512))
                    .unwrap_or_else(|| format!("<bad-import@{hint_name_rva:#x}>"));
                imports.push(PEImport {
                    library: library.clone(),
                    name,
                    ordinal: None,
                    iat_rva,
                });
            }
        }
    }

    imports.sort_by(|a, b| (&a.library, &a.name).cmp(&(&b.library, &b.name)));
    Ok(imports)
}

fn parse_exports(
    data: &[u8],
    directory: &DataDirectory,
    sections: &[SectionHeader],
    headers_size: u32,
) -> Result<Vec<PEExport>, RustidaError> {
    if directory.virtual_address == 0 {
        return Ok(Vec::new());
    }
    let Some(dir_offset) = rva_to_offset(directory.virtual_address, sections, headers_size) else {
        return Ok(Vec::new());
    };
    if dir_offset + 40 > data.len() {
        return Ok(Vec::new());
    }

    let base_ordinal = read_u32(data, dir_offset + 16)?;
    let number_of_functions = read_u32(data, dir_offset + 20)?;
    let number_of_names = read_u32(data, dir_offset + 24)?;
    let address_of_functions = read_u32(data, dir_offset + 28)?;
    let address_of_names = read_u32(data, dir_offset + 32)?;
    let address_of_name_ordinals = read_u32(data, dir_offset + 36)?;

    if number_of_functions > 1_000_000 || number_of_names > 1_000_000 {
        return Err(RustidaError::malformed("absurd PE export count"));
    }

    let Some(functions_offset) = rva_to_offset(address_of_functions, sections, headers_size) else {
        return Ok(Vec::new());
    };
    let Some(names_offset) = rva_to_offset(address_of_names, sections, headers_size) else {
        return Ok(Vec::new());
    };
    let Some(ordinals_offset) = rva_to_offset(address_of_name_ordinals, sections, headers_size)
    else {
        return Ok(Vec::new());
    };

    let mut name_by_ordinal: HashMap<u16, String> = HashMap::new();
    for index in 0..number_of_names as usize {
        let name_rva = match read_u32(data, names_offset + index * 4) {
            Ok(v) => v,
            Err(_) => break,
        };
        let ordinal_index = match read_u16(data, ordinals_offset + index * 2) {
            Ok(v) => v,
            Err(_) => break,
        };
        if let Some(name) = rva_to_offset(name_rva, sections, headers_size)
            .and_then(|off| read_cstr(data, off, 4096))
        {
            name_by_ordinal.insert(ordinal_index, name);
        }
    }

    let mut exports = Vec::new();
    for index in 0..number_of_functions as usize {
        let function_rva = match read_u32(data, functions_offset + index * 4) {
            Ok(v) => v,
            Err(_) => break,
        };
        if function_rva == 0 {
            continue;
        }
        let ordinal_index = index as u16;
        let name = name_by_ordinal
            .get(&ordinal_index)
            .cloned()
            .unwrap_or_else(|| format!("#{}", base_ordinal.wrapping_add(index as u32)));
        let forwarder = if function_rva >= directory.virtual_address
            && function_rva < directory.virtual_address.saturating_add(directory.size)
        {
            rva_to_offset(function_rva, sections, headers_size)
                .and_then(|off| read_cstr(data, off, 512))
        } else {
            None
        };
        exports.push(PEExport {
            name,
            rva: function_rva,
            ordinal: base_ordinal.wrapping_add(index as u32),
            forwarder,
        });
    }

    exports.sort_by_key(|e| e.ordinal);
    Ok(exports)
}

struct CoffSymbol {
    name: String,
    value: u32,
    section_number: i16,
    symbol_type: u16,
    storage_class: u8,
}

fn parse_coff_symbols(
    data: &[u8],
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
) -> Vec<CoffSymbol> {
    if pointer_to_symbol_table == 0 || number_of_symbols == 0 || number_of_symbols > 1_000_000 {
        return Vec::new();
    }
    let table = pointer_to_symbol_table as usize;
    let string_table = table + (number_of_symbols as usize) * 18;
    let mut symbols = Vec::new();
    let mut index = 0usize;
    while index < number_of_symbols as usize {
        let base = table + index * 18;
        if base + 18 > data.len() {
            break;
        }
        let name_bytes = &data[base..base + 8];
        let name = if name_bytes[..4] == [0, 0, 0, 0] {
            let offset =
                u32::from_le_bytes([name_bytes[4], name_bytes[5], name_bytes[6], name_bytes[7]])
                    as usize;
            read_cstr(data, string_table + offset, 4096).unwrap_or_default()
        } else {
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).into_owned()
        };
        let value = read_u32(data, base + 8).unwrap_or(0);
        let section_number = i16::from_le_bytes([data[base + 12], data[base + 13]]);
        let symbol_type = u16::from_le_bytes([data[base + 14], data[base + 15]]);
        let storage_class = data[base + 16];
        let aux_count = data[base + 17] as usize;
        if !name.is_empty() {
            symbols.push(CoffSymbol {
                name,
                value,
                section_number,
                symbol_type,
                storage_class,
            });
        }
        index += 1 + aux_count;
    }
    symbols
}

/// Parse a PE image.
pub fn parse_pe(data: &[u8]) -> Result<PeImage, RustidaError> {
    if data.len() < 0x40 {
        return Err(RustidaError::truncated(0, 0x40, data.len()));
    }
    if &data[0..2] != b"MZ" {
        return Err(RustidaError::InvalidFormat(
            "missing DOS 'MZ' signature".to_string(),
        ));
    }

    let e_lfanew = read_u32(data, 0x3c)? as usize;
    if e_lfanew + 4 + 20 > data.len() {
        return Err(RustidaError::truncated(e_lfanew, 24, data.len()));
    }
    if read_u32(data, e_lfanew)? != PE_SIGNATURE {
        return Err(RustidaError::InvalidFormat(
            "missing PE signature".to_string(),
        ));
    }

    let coff_offset = e_lfanew + 4;
    let coff = COFFHeader {
        machine: read_u16(data, coff_offset)?,
        number_of_sections: read_u16(data, coff_offset + 2)?,
        time_date_stamp: read_u32(data, coff_offset + 4)?,
        pointer_to_symbol_table: read_u32(data, coff_offset + 8)?,
        number_of_symbols: read_u32(data, coff_offset + 12)?,
        size_of_optional_header: read_u16(data, coff_offset + 16)?,
        characteristics: read_u16(data, coff_offset + 18)?,
    };

    let optional_offset = coff_offset + 20;
    if coff.size_of_optional_header < 2 {
        return Err(RustidaError::malformed("PE has no optional header"));
    }
    if optional_offset + coff.size_of_optional_header as usize > data.len() {
        return Err(RustidaError::truncated(
            optional_offset,
            coff.size_of_optional_header as usize,
            data.len(),
        ));
    }
    let magic = read_u16(data, optional_offset)?;
    let (format, is_64) = match magic {
        PE32_MAGIC => (PEFormat::Pe32, false),
        PE32_PLUS_MAGIC => (PEFormat::Pe32Plus, true),
        other => {
            return Err(RustidaError::InvalidFormat(format!(
                "unsupported PE optional-header magic {other:#x}"
            )));
        }
    };

    let (
        image_base,
        base_of_data,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        number_of_rva_and_sizes,
        directories_offset,
    ) = if is_64 {
        (
            read_u64(data, optional_offset + 24)?,
            None,
            read_u64(data, optional_offset + 72)?,
            read_u64(data, optional_offset + 80)?,
            read_u64(data, optional_offset + 88)?,
            read_u64(data, optional_offset + 96)?,
            read_u32(data, optional_offset + 108)?,
            112usize,
        )
    } else {
        (
            u64::from(read_u32(data, optional_offset + 28)?),
            Some(read_u32(data, optional_offset + 24)?),
            u64::from(read_u32(data, optional_offset + 72)?),
            u64::from(read_u32(data, optional_offset + 76)?),
            u64::from(read_u32(data, optional_offset + 80)?),
            u64::from(read_u32(data, optional_offset + 84)?),
            read_u32(data, optional_offset + 92)?,
            96usize,
        )
    };

    let available_dirs =
        (coff.size_of_optional_header as usize).saturating_sub(directories_offset) / 8;
    let dir_count = (number_of_rva_and_sizes as usize)
        .min(available_dirs)
        .min(16);
    let mut data_directories = Vec::with_capacity(dir_count);
    for (index, name) in DIRECTORY_NAMES.iter().enumerate().take(dir_count) {
        let base = optional_offset + directories_offset + index * 8;
        data_directories.push(DataDirectory {
            index,
            name,
            virtual_address: read_u32(data, base)?,
            size: read_u32(data, base + 4)?,
        });
    }

    let optional = OptionalHeader {
        magic,
        major_linker_version: read_u8(data, optional_offset + 2)?,
        minor_linker_version: read_u8(data, optional_offset + 3)?,
        size_of_code: read_u32(data, optional_offset + 4)?,
        size_of_initialized_data: read_u32(data, optional_offset + 8)?,
        size_of_uninitialized_data: read_u32(data, optional_offset + 12)?,
        entry_point: read_u32(data, optional_offset + 16)?,
        base_of_code: read_u32(data, optional_offset + 20)?,
        base_of_data,
        image_base,
        section_alignment: read_u32(data, optional_offset + 32)?,
        file_alignment: read_u32(data, optional_offset + 36)?,
        major_operating_system_version: read_u16(data, optional_offset + 40)?,
        minor_operating_system_version: read_u16(data, optional_offset + 42)?,
        major_image_version: read_u16(data, optional_offset + 44)?,
        minor_image_version: read_u16(data, optional_offset + 46)?,
        major_subsystem_version: read_u16(data, optional_offset + 48)?,
        minor_subsystem_version: read_u16(data, optional_offset + 50)?,
        size_of_image: read_u32(data, optional_offset + 56)?,
        size_of_headers: read_u32(data, optional_offset + 60)?,
        checksum: read_u32(data, optional_offset + 64)?,
        subsystem: read_u16(data, optional_offset + 68)?,
        dll_characteristics: read_u16(data, optional_offset + 70)?,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        number_of_rva_and_sizes,
        data_directories,
    };

    let section_table = optional_offset + coff.size_of_optional_header as usize;
    let sections = parse_sections(
        data,
        section_table,
        coff.number_of_sections,
        coff.size_of_optional_header,
        optional_offset,
    )?;

    let import_dir = optional
        .data_directories
        .iter()
        .find(|d| d.index == 1)
        .cloned();
    let export_dir = optional
        .data_directories
        .iter()
        .find(|d| d.index == 0)
        .cloned();

    let imports = match &import_dir {
        Some(dir) => parse_imports(data, dir, &sections, optional.size_of_headers, is_64)?,
        None => Vec::new(),
    };
    let exports = match &export_dir {
        Some(dir) => parse_exports(data, dir, &sections, optional.size_of_headers)?,
        None => Vec::new(),
    };

    let is_dll = coff.characteristics & 0x2000 != 0;

    Ok(PeImage {
        format,
        coff,
        optional: optional.clone(),
        sections,
        imports,
        exports,
        entry_point_rva: optional.entry_point,
        is_dll,
    })
}

/// Load a PE32 / PE32+ file into the common [`Binary`] model.
pub fn load_pe(data: &[u8]) -> Result<Binary, RustidaError> {
    let image = parse_pe(data)?;
    let is_64 = image.format == PEFormat::Pe32Plus;
    let arch = arch_for_machine(image.coff.machine, is_64);
    let format = BinaryFormat::new(
        if is_64 { "PE32+" } else { "PE32" },
        Endianness::LittleEndian,
        if is_64 { 64 } else { 32 },
        BinaryKind::Pe,
    );

    let image_base = image.optional.image_base;
    let mut sections = Vec::with_capacity(image.sections.len());
    let mut segments = Vec::with_capacity(image.sections.len());
    for section in &image.sections {
        let file_size = if section.pointer_to_raw_data as usize >= data.len() {
            0
        } else {
            u64::from(section.size_of_raw_data).min(
                data.len()
                    .saturating_sub(section.pointer_to_raw_data as usize) as u64,
            )
        };
        let size = u64::from(section.virtual_size.max(section.size_of_raw_data));
        sections.push(Section {
            name: section.name.clone(),
            address: Address::new(image_base.wrapping_add(u64::from(section.virtual_address))),
            size,
            file_offset: u64::from(section.pointer_to_raw_data),
            file_size,
            permissions: section.permissions,
            executable: section.executable,
        });
        segments.push(Segment {
            name: section.name.clone(),
            address: Address::new(image_base.wrapping_add(u64::from(section.virtual_address))),
            size,
            file_offset: u64::from(section.pointer_to_raw_data),
            file_size,
            permissions: section.permissions,
        });
    }

    let mut symbols = Vec::new();
    let mut seen = HashSet::new();
    for export in &image.exports {
        if seen.insert((export.name.clone(), export.rva)) {
            symbols.push(Symbol {
                name: export.name.clone(),
                address: Address::new(image_base.wrapping_add(u64::from(export.rva))),
                size: 0,
                kind: SymbolKind::Export,
            });
        }
    }
    for import in &image.imports {
        let address = Address::new(image_base.wrapping_add(u64::from(import.iat_rva)));
        if seen.insert((import.name.clone(), import.iat_rva)) {
            symbols.push(Symbol {
                name: import.name.clone(),
                address,
                size: 0,
                kind: SymbolKind::Import,
            });
        }
    }
    for coff_symbol in parse_coff_symbols(
        data,
        image.coff.pointer_to_symbol_table,
        image.coff.number_of_symbols,
    ) {
        let address = if coff_symbol.section_number > 0 {
            let section_index = (coff_symbol.section_number - 1) as usize;
            image
                .sections
                .get(section_index)
                .map(|s| {
                    image_base
                        .wrapping_add(u64::from(s.virtual_address))
                        .wrapping_add(u64::from(coff_symbol.value))
                })
                .unwrap_or(image_base)
        } else {
            image_base
        };
        let kind = if coff_symbol.symbol_type & 0x20 != 0 || coff_symbol.storage_class == 2 {
            SymbolKind::Function
        } else {
            SymbolKind::Variable
        };
        symbols.push(Symbol {
            name: coff_symbol.name,
            address: Address::new(address),
            size: 0,
            kind,
        });
    }

    let imports: Vec<Import> = image
        .imports
        .iter()
        .map(|import| Import {
            library: import.library.clone(),
            name: import.name.clone(),
            address: Address::new(image_base.wrapping_add(u64::from(import.iat_rva))),
        })
        .collect();
    let exports: Vec<Export> = image
        .exports
        .iter()
        .map(|export| Export {
            name: export.name.clone(),
            address: Address::new(image_base.wrapping_add(u64::from(export.rva))),
            ordinal: Some(export.ordinal),
        })
        .collect();

    let info = PeInfo {
        is_64,
        is_dll: image.is_dll,
        machine: image.coff.machine,
        time_date_stamp: image.coff.time_date_stamp,
        characteristics: image.coff.characteristics,
        image_base,
        entry_point_rva: image.entry_point_rva,
        section_alignment: image.optional.section_alignment,
        file_alignment: image.optional.file_alignment,
        size_of_image: image.optional.size_of_image,
        size_of_headers: image.optional.size_of_headers,
        subsystem: image.optional.subsystem,
        dll_characteristics: image.optional.dll_characteristics,
        checksum: image.optional.checksum,
        import_libraries: {
            let mut libs: Vec<String> = image.imports.iter().map(|i| i.library.clone()).collect();
            libs.sort();
            libs.dedup();
            libs
        },
        data_directories: image.optional.data_directories.clone(),
    };

    Ok(Binary {
        format,
        arch,
        entry_point: Address::new(image_base.wrapping_add(u64::from(image.entry_point_rva))),
        image_base,
        headers_size: u64::from(image.optional.size_of_headers),
        segments,
        sections,
        symbols,
        imports,
        exports,
        instructions: Vec::new(),
        bytes: Arc::new(data.to_vec()),
        info: BinaryInfo::Pe(info),
    })
}

/// Summary of PE-specific header fields.
#[derive(Debug, Clone)]
pub struct PeInfo {
    pub is_64: bool,
    pub is_dll: bool,
    pub machine: u16,
    pub time_date_stamp: u32,
    pub characteristics: u16,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub checksum: u32,
    pub import_libraries: Vec<String>,
    pub data_directories: Vec<DataDirectory>,
}
