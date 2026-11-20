//! Programmatically built binary fixtures.
//!
//! These are *valid* PE32, PE32+, Mach-O and fat Mach-O images with real
//! headers, a `.text` section, an import table, an export table, symbols and
//! executable code. Tests assert the exact parsed values rather than merely
//! "the call returned something".

#![allow(dead_code)]

pub const PE_CODE32: &[u8] = &[
    0x55, // push ebp
    0x89, 0xe5, // mov ebp, esp
    0x83, 0xec, 0x10, // sub esp, 0x10
    0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 0x2a
    0xc3, // ret
];

pub const PE_CODE64: &[u8] = &[
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0x48, 0x83, 0xec, 0x10, // sub rsp, 0x10
    0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 0x2a
    0xc3, // ret
];

pub const MACHO_CODE64: &[u8] = &[
    0x55, // push rbp
    0x48, 0x89, 0xe5, // mov rbp, rsp
    0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 0x2a
    0xc3, // ret
];

pub const MACHO_CODE32: &[u8] = &[
    0x55, // push ebp
    0x89, 0xe5, // mov ebp, esp
    0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 0x2a
    0xc3, // ret
];

fn put_u16_le(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64_le(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_be(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64_be(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn write_cstr(buf: &mut [u8], offset: usize, value: &str) {
    let bytes = value.as_bytes();
    buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    buf[offset + bytes.len()] = 0;
}

/// Build a complete PE32 or PE32+ fixture.
pub fn build_pe(is_64: bool) -> Vec<u8> {
    let mut b = vec![0u8; 0x600];
    b[0] = b'M';
    b[1] = b'Z';
    put_u32_le(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");

    let coff = 0x84usize;
    let opt = coff + 20;
    put_u16_le(&mut b, coff, if is_64 { 0x8664 } else { 0x014c });
    put_u16_le(&mut b, coff + 2, 1);
    put_u32_le(&mut b, coff + 4, 0x6543_2100);
    put_u32_le(&mut b, coff + 8, 0);
    put_u32_le(&mut b, coff + 12, 0);
    put_u16_le(&mut b, coff + 16, if is_64 { 240 } else { 224 });
    put_u16_le(&mut b, coff + 18, if is_64 { 0x0022 } else { 0x0102 });

    put_u16_le(&mut b, opt, if is_64 { 0x020b } else { 0x010b });
    b[opt + 2] = 14;
    b[opt + 3] = 0;
    put_u32_le(&mut b, opt + 4, 0x400);
    put_u32_le(&mut b, opt + 8, 0);
    put_u32_le(&mut b, opt + 12, 0);
    put_u32_le(&mut b, opt + 16, 0x1000);
    put_u32_le(&mut b, opt + 20, 0x1000);

    let directories_offset = if is_64 {
        put_u64_le(&mut b, opt + 24, 0x1_4000_0000);
        put_u64_le(&mut b, opt + 72, 0x10_0000);
        put_u64_le(&mut b, opt + 80, 0x1000);
        put_u64_le(&mut b, opt + 88, 0x10_0000);
        put_u64_le(&mut b, opt + 96, 0x1000);
        put_u32_le(&mut b, opt + 104, 0);
        put_u32_le(&mut b, opt + 108, 16);
        112
    } else {
        put_u32_le(&mut b, opt + 24, 0x2000);
        put_u32_le(&mut b, opt + 28, 0x0040_0000);
        put_u32_le(&mut b, opt + 72, 0x10_0000);
        put_u32_le(&mut b, opt + 76, 0x1000);
        put_u32_le(&mut b, opt + 80, 0x10_0000);
        put_u32_le(&mut b, opt + 84, 0x1000);
        put_u32_le(&mut b, opt + 88, 0);
        put_u32_le(&mut b, opt + 92, 16);
        96
    };

    put_u32_le(&mut b, opt + 32, 0x1000);
    put_u32_le(&mut b, opt + 36, 0x200);
    put_u16_le(&mut b, opt + 40, 6);
    put_u16_le(&mut b, opt + 42, 0);
    put_u16_le(&mut b, opt + 44, 0);
    put_u16_le(&mut b, opt + 46, 0);
    put_u16_le(&mut b, opt + 48, 6);
    put_u16_le(&mut b, opt + 50, 0);
    put_u32_le(&mut b, opt + 56, 0x2000);
    put_u32_le(&mut b, opt + 60, 0x200);
    put_u32_le(&mut b, opt + 64, 0);
    put_u16_le(&mut b, opt + 68, 3);
    put_u16_le(&mut b, opt + 70, 0);

    let directory = opt + directories_offset;
    put_u32_le(&mut b, directory, 0x1100);
    put_u32_le(&mut b, directory + 4, 0x100);
    put_u32_le(&mut b, directory + 8, 0x1200);
    put_u32_le(&mut b, directory + 12, 0x100);

    let section_table = opt + if is_64 { 240 } else { 224 };
    b[section_table..section_table + 8].copy_from_slice(b".text\0\0\0");
    put_u32_le(&mut b, section_table + 8, 0x400);
    put_u32_le(&mut b, section_table + 12, 0x1000);
    put_u32_le(&mut b, section_table + 16, 0x400);
    put_u32_le(&mut b, section_table + 20, 0x200);
    put_u32_le(&mut b, section_table + 36, 0x6000_0020);

    let code = if is_64 { PE_CODE64 } else { PE_CODE32 };
    b[0x200..0x200 + code.len()].copy_from_slice(code);

    // Export directory (RVA 0x1100 -> file offset 0x300).
    let export = 0x300usize;
    put_u32_le(&mut b, export + 12, 0x1160); // DLL name RVA
    put_u32_le(&mut b, export + 16, 1); // ordinal base
    put_u32_le(&mut b, export + 20, 1); // functions
    put_u32_le(&mut b, export + 24, 1); // names
    put_u32_le(&mut b, export + 28, 0x1130); // functions array
    put_u32_le(&mut b, export + 32, 0x1138); // names array
    put_u32_le(&mut b, export + 36, 0x113c); // ordinals array
    put_u32_le(&mut b, 0x330, 0x1000); // exported function RVA
    put_u32_le(&mut b, 0x338, 0x1150); // name RVA
    put_u16_le(&mut b, 0x33c, 0); // name -> function index
    write_cstr(&mut b, 0x350, "exported_func");
    write_cstr(&mut b, 0x360, "fixture.dll");

    // Import directory (RVA 0x1200 -> file offset 0x400).
    let import = 0x400usize;
    put_u32_le(&mut b, import, 0x1240); // OriginalFirstThunk
    put_u32_le(&mut b, import + 12, 0x1260); // DLL name
    put_u32_le(&mut b, import + 16, 0x1250); // FirstThunk
    // Descriptor terminator at 0x414 is already zero.

    if is_64 {
        put_u64_le(&mut b, 0x440, 0x1280);
        put_u64_le(&mut b, 0x448, 0);
        put_u64_le(&mut b, 0x450, 0x1280);
        put_u64_le(&mut b, 0x458, 0);
    } else {
        put_u32_le(&mut b, 0x440, 0x1280);
        put_u32_le(&mut b, 0x444, 0);
        put_u32_le(&mut b, 0x450, 0x1280);
        put_u32_le(&mut b, 0x454, 0);
    }
    write_cstr(&mut b, 0x460, "KERNEL32.dll");
    put_u16_le(&mut b, 0x480, 0);
    write_cstr(&mut b, 0x482, "ExitProcess");

    b
}

pub fn build_pe32() -> Vec<u8> {
    build_pe(false)
}

pub fn build_pe32plus() -> Vec<u8> {
    build_pe(true)
}

/// Build a thin 64-bit little-endian Mach-O executable.
pub fn build_macho64(cputype: u32) -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    put_u32_le(&mut b, 0, 0xfeed_facf);
    put_u32_le(&mut b, 4, cputype);
    put_u32_le(&mut b, 8, 3);
    put_u32_le(&mut b, 12, 2); // MH_EXECUTE
    put_u32_le(&mut b, 16, 4); // ncmds
    put_u32_le(&mut b, 20, 0x100); // sizeofcmds
    put_u32_le(&mut b, 24, 0x0020_0085);
    put_u32_le(&mut b, 28, 0);

    // LC_SEGMENT_64
    let segment = 32usize;
    put_u32_le(&mut b, segment, 0x19);
    put_u32_le(&mut b, segment + 4, 152);
    b[segment + 8..segment + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put_u64_le(&mut b, segment + 24, 0x1_0000_0000);
    put_u64_le(&mut b, segment + 32, 0x1000);
    put_u64_le(&mut b, segment + 40, 0);
    put_u64_le(&mut b, segment + 48, 0x400);
    put_u32_le(&mut b, segment + 56, 7);
    put_u32_le(&mut b, segment + 60, 5);
    put_u32_le(&mut b, segment + 64, 1);
    put_u32_le(&mut b, segment + 68, 0);
    let section = segment + 72;
    b[section..section + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    b[section + 16..section + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put_u64_le(&mut b, section + 32, 0x1_0000_0200);
    put_u64_le(&mut b, section + 40, 0x20);
    put_u32_le(&mut b, section + 48, 0x200);
    put_u32_le(&mut b, section + 52, 4);
    put_u32_le(&mut b, section + 64, 0x8000_0400);

    // LC_SYMTAB
    let symtab = 32 + 152;
    put_u32_le(&mut b, symtab, 0x2);
    put_u32_le(&mut b, symtab + 4, 24);
    put_u32_le(&mut b, symtab + 8, 0x300);
    put_u32_le(&mut b, symtab + 12, 2);
    put_u32_le(&mut b, symtab + 16, 0x320);
    put_u32_le(&mut b, symtab + 20, 15);

    // LC_LOAD_DYLIB
    let dylib = symtab + 24;
    put_u32_le(&mut b, dylib, 0x0c);
    put_u32_le(&mut b, dylib + 4, 56);
    put_u32_le(&mut b, dylib + 8, 24);
    put_u32_le(&mut b, dylib + 12, 0);
    put_u32_le(&mut b, dylib + 16, 0x1_0000);
    put_u32_le(&mut b, dylib + 20, 0x1_0000);
    write_cstr(&mut b, dylib + 24, "/usr/lib/libSystem.B.dylib");

    // LC_MAIN
    let main = dylib + 56;
    put_u32_le(&mut b, main, 0x8000_0028);
    put_u32_le(&mut b, main + 4, 24);
    put_u64_le(&mut b, main + 8, 0x200);
    put_u64_le(&mut b, main + 16, 0);

    b[0x200..0x200 + MACHO_CODE64.len()].copy_from_slice(MACHO_CODE64);

    // nlist_64 entries.
    put_u32_le(&mut b, 0x300, 1);
    b[0x304] = 0x0f; // N_SECT | N_EXT
    b[0x305] = 1;
    put_u16_le(&mut b, 0x306, 0);
    put_u64_le(&mut b, 0x308, 0x1_0000_0200);

    put_u32_le(&mut b, 0x310, 7);
    b[0x314] = 0x01; // N_UNDF | N_EXT
    b[0x315] = 0;
    put_u16_le(&mut b, 0x316, 0);
    put_u64_le(&mut b, 0x318, 0);

    let strings: &[u8] = b"\0_main\0_printf\0";
    b[0x320..0x320 + strings.len()].copy_from_slice(strings);
    b
}

pub fn build_macho64_x86_64() -> Vec<u8> {
    build_macho64(0x0100_0007)
}

pub fn build_macho64_arm64() -> Vec<u8> {
    build_macho64(0x0100_000c)
}

/// Build a thin 32-bit little-endian Mach-O executable using LC_UNIXTHREAD.
pub fn build_macho32() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    put_u32_le(&mut b, 0, 0xfeed_face);
    put_u32_le(&mut b, 4, 7); // CPU_TYPE_X86
    put_u32_le(&mut b, 8, 3);
    put_u32_le(&mut b, 12, 2);
    put_u32_le(&mut b, 16, 3);
    put_u32_le(&mut b, 20, 228);
    put_u32_le(&mut b, 24, 0x0000_0085);

    // LC_SEGMENT
    let segment = 28usize;
    put_u32_le(&mut b, segment, 0x1);
    put_u32_le(&mut b, segment + 4, 124);
    b[segment + 8..segment + 24].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put_u32_le(&mut b, segment + 24, 0x1000);
    put_u32_le(&mut b, segment + 28, 0x1000);
    put_u32_le(&mut b, segment + 32, 0);
    put_u32_le(&mut b, segment + 36, 0x400);
    put_u32_le(&mut b, segment + 40, 7);
    put_u32_le(&mut b, segment + 44, 5);
    put_u32_le(&mut b, segment + 48, 1);
    put_u32_le(&mut b, segment + 52, 0);
    let section = segment + 56;
    b[section..section + 16].copy_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
    b[section + 16..section + 32].copy_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    put_u32_le(&mut b, section + 32, 0x1000);
    put_u32_le(&mut b, section + 36, 0x20);
    put_u32_le(&mut b, section + 40, 0x200);
    put_u32_le(&mut b, section + 44, 4);
    put_u32_le(&mut b, section + 56, 0x8000_0400);

    // LC_SYMTAB
    let symtab = 28 + 124;
    put_u32_le(&mut b, symtab, 0x2);
    put_u32_le(&mut b, symtab + 4, 24);
    put_u32_le(&mut b, symtab + 8, 0x300);
    put_u32_le(&mut b, symtab + 12, 1);
    put_u32_le(&mut b, symtab + 16, 0x30c);
    put_u32_le(&mut b, symtab + 20, 7);

    // LC_UNIXTHREAD: x86_THREAD_STATE32, eip = 0x1000.
    let thread = symtab + 24;
    put_u32_le(&mut b, thread, 0x5);
    put_u32_le(&mut b, thread + 4, 80);
    put_u32_le(&mut b, thread + 8, 1);
    put_u32_le(&mut b, thread + 12, 16);
    put_u32_le(&mut b, thread + 16 + 10 * 4, 0x1000);

    b[0x200..0x200 + MACHO_CODE32.len()].copy_from_slice(MACHO_CODE32);

    // nlist (32-bit): n_strx, n_type, n_sect, n_desc, n_value.
    put_u32_le(&mut b, 0x300, 1);
    b[0x304] = 0x0f;
    b[0x305] = 1;
    put_u16_le(&mut b, 0x306, 0);
    put_u32_le(&mut b, 0x308, 0x1000);

    let strings: &[u8] = b"\0_main\0";
    b[0x30c..0x30c + strings.len()].copy_from_slice(strings);
    b
}

/// Build a 32-bit fat table containing x86_64 and arm64 slices.
pub fn build_fat_macho() -> Vec<u8> {
    let x86_64 = build_macho64_x86_64();
    let arm64 = build_macho64_arm64();
    let mut b = vec![0u8; 0x2400];

    // FAT_MAGIC (big-endian), two entries.
    put_u32_be(&mut b, 0, 0xcafe_babe);
    put_u32_be(&mut b, 4, 2);

    put_u32_be(&mut b, 8, 0x0100_0007);
    put_u32_be(&mut b, 12, 3);
    put_u32_be(&mut b, 16, 0x1000);
    put_u32_be(&mut b, 20, x86_64.len() as u32);
    put_u32_be(&mut b, 24, 12);

    put_u32_be(&mut b, 28, 0x0100_000c);
    put_u32_be(&mut b, 32, 3);
    put_u32_be(&mut b, 36, 0x2000);
    put_u32_be(&mut b, 40, arm64.len() as u32);
    put_u32_be(&mut b, 44, 12);

    b[0x1000..0x1000 + x86_64.len()].copy_from_slice(&x86_64);
    b[0x2000..0x2000 + arm64.len()].copy_from_slice(&arm64);
    b
}

/// Build a 64-bit fat table variant.
pub fn build_fat_macho64_table() -> Vec<u8> {
    let x86_64 = build_macho64_x86_64();
    let arm64 = build_macho64_arm64();
    let mut b = vec![0u8; 0x2400];

    put_u32_be(&mut b, 0, 0xcafe_babf);
    put_u32_be(&mut b, 4, 2);

    put_u32_be(&mut b, 8, 0x0100_0007);
    put_u32_be(&mut b, 12, 3);
    put_u64_be(&mut b, 16, 0x1000);
    put_u64_be(&mut b, 24, x86_64.len() as u64);
    put_u32_be(&mut b, 32, 12);
    put_u32_be(&mut b, 36, 0);

    put_u32_be(&mut b, 40, 0x0100_000c);
    put_u32_be(&mut b, 44, 3);
    put_u64_be(&mut b, 48, 0x2000);
    put_u64_be(&mut b, 56, arm64.len() as u64);
    put_u32_be(&mut b, 64, 12);
    put_u32_be(&mut b, 68, 0);

    b[0x1000..0x1000 + x86_64.len()].copy_from_slice(&x86_64);
    b[0x2000..0x2000 + arm64.len()].copy_from_slice(&arm64);
    b
}

/// x86-64 code used by analysis tests:
///
/// ```text
/// 1000: push rbp
/// 1001: mov  rbp, rsp
/// 1004: cmp  eax, 0
/// 1007: je   100e
/// 1009: call 1014
/// 100e: mov  eax, 1
/// 1013: ret
/// 1014: ret
/// ```
pub const ANALYSIS_CODE: &[u8] = &[
    0x55, // 1000 push rbp
    0x48, 0x89, 0xe5, // 1001 mov rbp, rsp
    0x83, 0xf8, 0x00, // 1004 cmp eax, 0
    0x74, 0x05, // 1007 je 100e
    0xe8, 0x06, 0x00, 0x00, 0x00, // 1009 call 1014
    0xb8, 0x01, 0x00, 0x00, 0x00, // 100e mov eax, 1
    0xc3, // 1013 ret
    0xc3, // 1014 ret (call target)
];

pub const ANALYSIS_BASE: u64 = 0x1000;

/// Code with only indirect control flow (must not invent targets).
pub const INDIRECT_CODE: &[u8] = &[
    0xff, 0xe0, // jmp rax
    0xff, 0xd0, // call rax
    0xc3, // ret
];

/// A reachable indirect call followed by a return.
pub const INDIRECT_CALL_CODE: &[u8] = &[
    0x90, // nop
    0xff, 0xd0, // call rax
    0xc3, // ret
];
