//! Loader integration tests with real binaries and asserted values.

mod common;

use rustida_loader::{
    BinaryInfo, BinaryKind, FormatKind, PEFormat, SymbolKind, detect_format, load_binary, load_elf,
    load_mach_o, load_mach_o_cpu, load_pe, parse_fat_macho, parse_macho, parse_pe,
};

#[test]
fn test_elf_real_binary_from_current_exe() {
    #[cfg(target_os = "linux")]
    {
        let path = std::env::current_exe().expect("current test executable");
        let data = std::fs::read(&path).expect("read test executable");
        assert_eq!(detect_format(&data), Some(FormatKind::Elf));

        let binary = load_elf(&data).expect("parse the real ELF test executable");
        assert_eq!(binary.format.kind, BinaryKind::Elf);
        assert_eq!(binary.format.name, "ELF");
        assert_eq!(binary.format.address_bits, 64);
        assert_eq!(binary.arch.bits, 64);
        assert!(binary.arch.is_x86());
        assert!(!binary.sections.is_empty(), "expected sections");
        assert!(!binary.segments.is_empty(), "expected PT_LOAD segments");
        assert!(binary.entry_point.0 != 0, "ELF entry point must be set");
        assert_eq!(binary.bytes.len(), data.len());
        assert!(matches!(binary.info, BinaryInfo::Elf(_)));

        // Real section names must be recovered.
        let named = binary
            .sections
            .iter()
            .filter(|s| !s.name.is_empty())
            .count();
        assert!(named > 0, "expected named sections");

        // At least one executable section backed by file bytes.
        let text = binary
            .sections
            .iter()
            .find(|s| s.executable && s.file_size > 0)
            .expect("an executable file-backed section");
        assert!(!text.name.is_empty());

        // Real symbol names, not empty placeholders.
        assert!(
            binary.symbols.iter().any(|s| !s.name.is_empty()),
            "expected symbol names"
        );
    }
}

#[test]
fn test_elf_address_translation() {
    #[cfg(target_os = "linux")]
    {
        let path = std::env::current_exe().expect("current test executable");
        let data = std::fs::read(path).expect("read test executable");
        let binary = load_elf(&data).expect("parse ELF");

        let text = binary
            .sections
            .iter()
            .find(|s| s.name == ".text" && s.file_size > 0)
            .or_else(|| {
                binary
                    .sections
                    .iter()
                    .find(|s| s.executable && s.file_size > 0)
            })
            .expect(".text or executable section");

        assert_eq!(
            binary.rva_to_offset(text.address.0),
            Some(text.file_offset),
            "VA -> file offset"
        );
        assert_eq!(
            binary.offset_to_rva(text.file_offset),
            Some(text.address.0),
            "file offset -> RVA"
        );
        assert_eq!(binary.va_to_rva(text.address.0), Some(text.address.0));

        // One byte inside the section translates by +1.
        assert_eq!(
            binary.rva_to_offset(text.address.0 + 0x10),
            Some(text.file_offset + 0x10)
        );
    }
}

#[test]
fn test_elf_invalid_and_truncated() {
    assert!(load_elf(b"").is_err());
    assert!(load_elf(b"\x7fELF").is_err());
    assert!(load_elf(b"not an elf file at all").is_err());
    assert!(load_binary(b"garbage").is_err());
}

#[test]
fn test_parse_pe32() {
    let data = common::build_pe32();
    assert_eq!(detect_format(&data), Some(FormatKind::Pe));

    let image = parse_pe(&data).expect("parse PE32");
    assert_eq!(image.format, PEFormat::Pe32);
    assert!(!image.is_dll);
    assert_eq!(image.coff.machine, 0x014c);
    assert_eq!(image.coff.number_of_sections, 1);
    assert_eq!(image.optional.image_base, 0x0040_0000);
    assert_eq!(image.optional.entry_point, 0x1000);
    assert_eq!(image.optional.section_alignment, 0x1000);
    assert_eq!(image.optional.file_alignment, 0x200);
    assert_eq!(image.optional.size_of_headers, 0x200);
    assert_eq!(image.optional.data_directories.len(), 16);

    assert_eq!(image.sections.len(), 1);
    let text = &image.sections[0];
    assert_eq!(text.name, ".text");
    assert_eq!(text.virtual_address, 0x1000);
    assert_eq!(text.pointer_to_raw_data, 0x200);
    assert!(text.executable);
    assert!(text.permissions.executable());
    assert!(text.permissions.readable());

    assert_eq!(image.exports.len(), 1);
    let export = &image.exports[0];
    assert_eq!(export.name, "exported_func");
    assert_eq!(export.rva, 0x1000);
    assert_eq!(export.ordinal, 1);
    assert!(export.forwarder.is_none());

    assert_eq!(image.imports.len(), 1);
    let import = &image.imports[0];
    assert_eq!(import.library, "KERNEL32.dll");
    assert_eq!(import.name, "ExitProcess");
    assert_eq!(import.iat_rva, 0x1250);
    assert_eq!(import.ordinal, None);
}

#[test]
fn test_parse_pe32plus() {
    let data = common::build_pe32plus();
    let image = parse_pe(&data).expect("parse PE32+");
    assert_eq!(image.format, PEFormat::Pe32Plus);
    assert_eq!(image.coff.machine, 0x8664);
    assert_eq!(image.optional.image_base, 0x1_4000_0000);
    assert_eq!(image.optional.entry_point, 0x1000);
    assert_eq!(image.imports.len(), 1);
    assert_eq!(image.imports[0].name, "ExitProcess");
    assert_eq!(image.imports[0].library, "KERNEL32.dll");
    assert_eq!(image.exports.len(), 1);
    assert_eq!(image.exports[0].name, "exported_func");
}

#[test]
fn test_load_pe_common_model_and_translation() {
    for (data, is_64) in [
        (common::build_pe32(), false),
        (common::build_pe32plus(), true),
    ] {
        let binary = load_pe(&data).expect("load PE");
        assert_eq!(binary.format.kind, BinaryKind::Pe);
        assert!(matches!(binary.info, BinaryInfo::Pe(_)));
        assert_eq!(binary.format.address_bits, if is_64 { 64 } else { 32 });
        assert_eq!(binary.arch.name, if is_64 { "x86-64" } else { "i386" });
        assert!(binary.arch.is_x86());

        let image_base = if is_64 { 0x1_4000_0000 } else { 0x0040_0000 };
        assert_eq!(binary.image_base, image_base);
        assert_eq!(binary.entry_point.0, image_base + 0x1000);

        let text = binary
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .expect(".text");
        assert!(text.executable);
        assert_eq!(text.address.0, image_base + 0x1000);
        assert_eq!(text.file_offset, 0x200);

        // RVA -> file offset (uses image base internally).
        assert_eq!(binary.rva_to_offset(0x1000), Some(0x200));
        assert_eq!(binary.rva_to_offset(0x1010), Some(0x210));
        // File offset -> RVA.
        assert_eq!(binary.offset_to_rva(0x200), Some(0x1000));
        // VA -> RVA.
        assert_eq!(binary.va_to_rva(image_base + 0x1000), Some(0x1000));

        // Imports/exports in the common model.
        assert!(binary.imports.iter().any(|i| i.name == "ExitProcess"));
        assert!(
            binary
                .exports
                .iter()
                .any(|e| e.name == "exported_func" && e.address.0 == image_base + 0x1000)
        );
        assert!(
            binary
                .symbols
                .iter()
                .any(|s| s.name == "exported_func" && s.kind == SymbolKind::Export)
        );
    }
}

#[test]
fn test_pe_invalid_and_truncated() {
    assert!(load_pe(b"").is_err());
    assert!(load_pe(b"MZ").is_err());
    assert!(load_pe(b"MZ\0\0\0\0").is_err());

    let mut data = common::build_pe32();
    data[0x80] = b'X'; // corrupt PE signature
    assert!(load_pe(&data).is_err());

    let valid = common::build_pe32();
    for truncated_len in [0x10, 0x40, 0x84, 0x100, 0x1a0, 0x300] {
        let truncated = &valid[..truncated_len.min(valid.len())];
        assert!(
            load_pe(truncated).is_err(),
            "truncated PE ({truncated_len:#x}) must fail cleanly"
        );
    }
}

#[test]
fn test_parse_macho64() {
    let data = common::build_macho64_x86_64();
    assert_eq!(detect_format(&data), Some(FormatKind::MachO));

    let image = parse_macho(&data).expect("parse Mach-O 64");
    assert!(image.header.is_64);
    assert_eq!(image.header.cputype, 0x0100_0007);
    assert_eq!(image.header.filetype, 2);
    assert_eq!(image.entry_point, 0x1_0000_0200);
    assert_eq!(image.entry_file_offset, Some(0x200));
    assert_eq!(image.segments.len(), 1);
    assert_eq!(image.segments[0].name, "__TEXT");
    assert_eq!(image.segments[0].vmaddr, 0x1_0000_0000);
    assert_eq!(image.segments[0].sections.len(), 1);
    let section = &image.segments[0].sections[0];
    assert_eq!(section.sectname, "__text");
    assert_eq!(section.addr, 0x1_0000_0200);
    assert!(section.executable);

    assert_eq!(image.dylibs.len(), 1);
    assert_eq!(image.dylibs[0].name, "/usr/lib/libSystem.B.dylib");

    assert!(image.symbols.iter().any(|s| s.name == "_main"));
    assert!(image.symbols.iter().any(|s| s.name == "_printf"));
}

#[test]
fn test_load_macho64_common_model() {
    let data = common::build_macho64_x86_64();
    let binary = load_mach_o(&data).expect("load Mach-O");
    assert_eq!(binary.format.kind, BinaryKind::MachO);
    assert_eq!(binary.arch.name, "x86-64");
    assert_eq!(binary.arch.bits, 64);
    assert_eq!(binary.entry_point.0, 0x1_0000_0200);
    assert!(matches!(binary.info, BinaryInfo::MachO(_)));

    let text = binary
        .sections
        .iter()
        .find(|s| s.name == "__TEXT,__text")
        .expect("__TEXT,__text");
    assert!(text.executable);
    assert_eq!(text.file_offset, 0x200);

    assert_eq!(binary.rva_to_offset(0x1_0000_0200), Some(0x200));
    assert_eq!(binary.offset_to_rva(0x200), Some(0x1_0000_0200));

    assert!(
        binary
            .symbols
            .iter()
            .any(|s| s.name == "_main" && s.kind == SymbolKind::Function)
    );
    assert!(binary.imports.iter().any(|i| i.name == "_printf"));
    assert!(
        binary
            .exports
            .iter()
            .any(|e| e.name == "_main" && e.address.0 == 0x1_0000_0200)
    );
}

#[test]
fn test_macho32_and_thread_entry_point() {
    let data = common::build_macho32();
    let image = parse_macho(&data).expect("parse Mach-O 32");
    assert!(!image.header.is_64);
    assert_eq!(image.header.cputype, 7);
    assert_eq!(image.entry_point, 0x1000, "entry from LC_UNIXTHREAD");
    assert_eq!(image.entry_file_offset, None);

    let binary = load_mach_o(&data).expect("load Mach-O 32");
    assert_eq!(binary.arch.name, "i386");
    assert_eq!(binary.arch.bits, 32);
    assert!(binary.arch.is_x86());
    assert_eq!(binary.entry_point.0, 0x1000);
    assert!(binary.symbols.iter().any(|s| s.name == "_main"));
}

#[test]
fn test_fat_macho_architecture_selection() {
    let data = common::build_fat_macho();
    assert_eq!(detect_format(&data), Some(FormatKind::FatMachO));

    let fat = parse_fat_macho(&data).expect("parse fat header");
    assert_eq!(fat.archs.len(), 2);
    assert!(!fat.is_64_bit_table);
    assert_eq!(fat.archs[0].cputype, 0x0100_0007);
    assert_eq!(fat.archs[0].offset, 0x1000);
    assert_eq!(fat.archs[0].size, 0x400);
    assert_eq!(fat.archs[1].cputype, 0x0100_000c);
    assert_eq!(fat.archs[1].offset, 0x2000);
    assert_eq!(fat.select().map(|a| a.cputype), Some(0x0100_0007));

    // Default load prefers x86-64.
    let binary = load_mach_o(&data).expect("load fat Mach-O");
    assert_eq!(binary.format.kind, BinaryKind::FatMachO);
    assert_eq!(binary.arch.name, "x86-64");
    assert_eq!(binary.entry_point.0, 0x1_0000_0200);
    assert!(
        binary
            .symbols
            .iter()
            .any(|s| s.name == "_main" && s.kind == SymbolKind::Function)
    );

    // Explicit arm64 selection.
    let arm = load_mach_o_cpu(&data, 0x0100_000c).expect("load arm64 slice");
    assert_eq!(arm.arch.name, "aarch64");
    assert_eq!(arm.arch.bits, 64);
    assert!(!arm.arch.is_x86());
    assert_eq!(arm.entry_point.0, 0x1_0000_0200);
    assert_eq!(detect_format(arm.bytes.as_slice()), Some(FormatKind::MachO));

    // Requesting an absent architecture is a structured error.
    assert!(load_mach_o_cpu(&data, 0x0100_000b).is_err());
}

#[test]
fn test_fat_macho64_table() {
    let data = common::build_fat_macho64_table();
    let fat = parse_fat_macho(&data).expect("parse 64-bit fat header");
    assert!(fat.is_64_bit_table);
    assert_eq!(fat.archs.len(), 2);
    assert_eq!(fat.archs[0].offset, 0x1000);
    assert_eq!(fat.archs[0].size, 0x400);
    assert_eq!(fat.archs[1].cputype, 0x0100_000c);

    let binary = load_mach_o_cpu(&data, 0x0100_000c).expect("arm64 slice");
    assert_eq!(binary.arch.name, "aarch64");
}

#[test]
fn test_macho_invalid_and_truncated() {
    assert!(load_mach_o(b"").is_err());
    assert!(load_mach_o(b"\xcf\xfa\xed\xfe").is_err());
    assert!(load_mach_o(b"not macho").is_err());

    let valid = common::build_macho64_x86_64();
    for truncated_len in [0x4, 0x10, 0x1c, 0x20, 0x40, 0x100, 0x1ff] {
        let truncated = &valid[..truncated_len.min(valid.len())];
        assert!(
            load_mach_o(truncated).is_err(),
            "truncated Mach-O ({truncated_len:#x}) must fail cleanly"
        );
    }

    // Fat header advertising an out-of-bounds slice.
    let mut fat = common::build_fat_macho();
    fat[16..20].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
    assert!(parse_fat_macho(&fat).is_err());
}

#[test]
fn test_detect_format_all() {
    assert_eq!(detect_format(&common::build_pe32()), Some(FormatKind::Pe));
    assert_eq!(
        detect_format(&common::build_pe32plus()),
        Some(FormatKind::Pe)
    );
    assert_eq!(
        detect_format(&common::build_macho64_arm64()),
        Some(FormatKind::MachO)
    );
    assert_eq!(
        detect_format(&common::build_fat_macho()),
        Some(FormatKind::FatMachO)
    );
    assert_eq!(detect_format(b"plain text"), None);
}

#[test]
fn test_load_binary_dispatches_all_formats() {
    let pe = load_binary(&common::build_pe32plus()).expect("PE via load_binary");
    assert_eq!(pe.format.kind, BinaryKind::Pe);
    let macho = load_binary(&common::build_macho32()).expect("Mach-O via load_binary");
    assert_eq!(macho.format.kind, BinaryKind::MachO);
    let fat = load_binary(&common::build_fat_macho()).expect("fat via load_binary");
    assert_eq!(fat.format.kind, BinaryKind::FatMachO);
}
