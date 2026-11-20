use rustida_project::Project;

#[test]
fn test_project_creation() {
    let proj = Project::new(
        "test project".to_string(),
        rustida_loader::BinaryFormat {
            name: "ELF".to_string(),
            endianness: rustida_core::Endianness::LittleEndian,
            address_bits: 64,
            kind: rustida_loader::BinaryKind::Elf,
        },
        rustida_core::Architecture {
            name: "x86-64".to_string(),
            bits: 64,
            endianness: rustida_core::Endianness::LittleEndian,
        },
    );
    assert_eq!(proj.manifest.name, "test project");
}
