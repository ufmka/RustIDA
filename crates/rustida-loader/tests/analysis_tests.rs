//! Tests for the disassembler and the analysis engine.
//!
//! The instruction bytes are real x86-64 encodings, and every assertion checks
//! concrete addresses, flows, edges or names produced by the pipeline.

mod common;

use rustida_core::Address;
use rustida_loader::{
    BlockTerminator, CFGEdgeType, CrossReferenceType, InstructionFlow, SymbolKind, analyze_binary,
    analyze_disassembly, build_basic_blocks, build_call_graph, build_cfg, detect_functions,
    disassemble_at, disassemble_binary, extract_xrefs, load_mach_o, load_pe,
};

const BASE: u64 = 0x1000;

fn decode_analysis() -> Vec<rustida_loader::DisassembledInstruction> {
    disassemble_at(
        common::ANALYSIS_CODE,
        Address::new(BASE),
        64,
        rustida_core::Endianness::LittleEndian,
    )
}

#[test]
fn test_disassemble_preserves_bytes_lengths_and_targets() {
    let instructions = decode_analysis();
    assert_eq!(instructions.len(), 8, "all instructions decoded");

    let addresses: Vec<u64> = instructions.iter().map(|i| i.address.0).collect();
    assert_eq!(
        addresses,
        vec![
            0x1000, 0x1001, 0x1004, 0x1007, 0x1009, 0x100e, 0x1013, 0x1014
        ]
    );

    let lengths: Vec<usize> = instructions.iter().map(|i| i.length).collect();
    assert_eq!(lengths, vec![1, 3, 3, 2, 5, 5, 1, 1]);

    assert_eq!(instructions[0].mnemonic, "PUSH");
    assert_eq!(instructions[0].bytes, vec![0x55]);
    assert_eq!(instructions[1].mnemonic, "MOV");
    assert_eq!(instructions[1].bytes, vec![0x48, 0x89, 0xe5]);
    assert_eq!(instructions[3].mnemonic, "JE");
    assert_eq!(instructions[3].target, Some(Address::new(0x100e)));
    assert_eq!(instructions[3].flow, InstructionFlow::ConditionalJump);
    assert_eq!(instructions[4].mnemonic, "CALL");
    assert_eq!(instructions[4].bytes, vec![0xe8, 0x06, 0x00, 0x00, 0x00]);
    assert_eq!(instructions[4].target, Some(Address::new(0x1014)));
    assert_eq!(instructions[4].flow, InstructionFlow::Call);
    assert_eq!(instructions[6].flow, InstructionFlow::Return);
    assert!(instructions.iter().all(|i| i.valid));

    // Every instruction's length matches the stored byte count.
    for instruction in &instructions {
        assert_eq!(instruction.bytes.len(), instruction.length);
        assert_eq!(
            instruction.end_address(),
            instruction.address.0 + instruction.length as u64
        );
    }

    // Text rendering contains the real operand.
    assert!(instructions[4].text().starts_with("CALL"));
    assert!(instructions[6].hex() == "c3");
}

#[test]
fn test_disassemble_handles_invalid_and_indirect_instructions() {
    // 0x06 is invalid in 64-bit mode.
    let invalid = disassemble_at(
        &[0x06],
        Address::new(0x2000),
        64,
        rustida_core::Endianness::LittleEndian,
    );
    assert_eq!(invalid.len(), 1);
    assert!(!invalid[0].valid);
    assert_eq!(invalid[0].length, 1);

    let indirect = disassemble_at(
        common::INDIRECT_CODE,
        Address::new(BASE),
        64,
        rustida_core::Endianness::LittleEndian,
    );
    assert_eq!(indirect[0].flow, InstructionFlow::IndirectJump);
    assert_eq!(indirect[0].target, None);
    assert_eq!(indirect[1].flow, InstructionFlow::IndirectCall);
    assert_eq!(indirect[1].target, None);
    assert_eq!(indirect[2].flow, InstructionFlow::Return);
}

#[test]
fn test_build_basic_blocks_exact_partition() {
    let instructions = decode_analysis();
    let blocks = build_basic_blocks(&instructions);

    assert_eq!(blocks.len(), 4);
    assert_eq!(blocks[0].address, Address::new(0x1000));
    assert_eq!(blocks[0].size, 9);
    assert_eq!(blocks[0].instructions.len(), 4);
    assert_eq!(
        blocks[0].terminator,
        BlockTerminator::ConditionalBranch {
            address: Some(Address::new(0x100e)),
            condition: "JE".to_string()
        }
    );

    assert_eq!(blocks[1].address, Address::new(0x1009));
    assert_eq!(blocks[1].size, 5);
    assert_eq!(
        blocks[1].terminator,
        BlockTerminator::Call(Some(Address::new(0x1014)))
    );

    assert_eq!(blocks[2].address, Address::new(0x100e));
    assert_eq!(blocks[2].size, 6);
    assert_eq!(blocks[2].terminator, BlockTerminator::Return);

    assert_eq!(blocks[3].address, Address::new(0x1014));
    assert_eq!(blocks[3].size, 1);
    assert_eq!(blocks[3].terminator, BlockTerminator::Return);

    // Blocks must tile the listing without overlap.
    let mut expected = 0x1000;
    for block in &blocks {
        assert_eq!(block.address.0, expected);
        expected = block.end_address();
    }
    assert_eq!(expected, 0x1015);
}

#[test]
fn test_cfg_edges_are_real_and_indirect_targets_are_not_invented() {
    let instructions = decode_analysis();
    let blocks = build_basic_blocks(&instructions);
    let (nodes, edges) = build_cfg(&blocks);

    assert_eq!(nodes.len(), 4);
    assert_eq!(edges.len(), 5);

    let node_1000 = nodes.iter().find(|n| n.address.0 == 0x1000).unwrap();
    assert_eq!(node_1000.edges.len(), 2);
    assert_eq!(
        node_1000.edges[0],
        rustida_loader::CFGEdge {
            target: Some(Address::new(0x100e)),
            edge_type: CFGEdgeType::Conditional
        }
    );
    assert_eq!(
        node_1000.edges[1],
        rustida_loader::CFGEdge {
            target: Some(Address::new(0x1009)),
            edge_type: CFGEdgeType::Fallthrough
        }
    );

    // A call falls through to the next instruction.
    let node_1009 = nodes.iter().find(|n| n.address.0 == 0x1009).unwrap();
    assert_eq!(node_1009.edges.len(), 1);
    assert_eq!(node_1009.edges[0].target, Some(Address::new(0x100e)));
    assert_eq!(node_1009.edges[0].edge_type, CFGEdgeType::Fallthrough);

    // Return blocks have a pseudo-edge with no target.
    let node_100e = nodes.iter().find(|n| n.address.0 == 0x100e).unwrap();
    assert_eq!(node_100e.edges.len(), 1);
    assert_eq!(node_100e.edges[0].edge_type, CFGEdgeType::Return);
    assert_eq!(node_100e.edges[0].target, None);

    // Indirect control flow: no made-up target.
    let indirect = disassemble_at(
        common::INDIRECT_CODE,
        Address::new(BASE),
        64,
        rustida_core::Endianness::LittleEndian,
    );
    let indirect_blocks = build_basic_blocks(&indirect);
    let (_, indirect_edges) = build_cfg(&indirect_blocks);
    assert!(
        indirect_edges
            .iter()
            .all(|edge| edge.target.is_none() || edge.edge_type != CFGEdgeType::Indirect)
    );
    assert!(
        indirect_blocks
            .iter()
            .any(|b| matches!(b.terminator, BlockTerminator::IndirectJump(None)))
    );
}

#[test]
fn test_xrefs_cover_calls_branches_and_absolute_data() {
    let instructions = decode_analysis();
    let xrefs = extract_xrefs(&instructions);

    assert!(xrefs.iter().any(|r| r.source == Address::new(0x1009)
        && r.destination == Address::new(0x1014)
        && r.ref_type == CrossReferenceType::Call));
    assert!(xrefs.iter().any(|r| r.source == Address::new(0x1007)
        && r.destination == Address::new(0x100e)
        && r.ref_type == CrossReferenceType::Branch));
    assert_eq!(
        xrefs
            .iter()
            .filter(|r| r.ref_type == CrossReferenceType::Call)
            .count(),
        1
    );

    // `mov eax, dword ptr [0x402000]` (SIB with no base) references
    // absolute data.
    let data = [0x8b, 0x04, 0x25, 0x00, 0x20, 0x40, 0x00];
    let data_instructions = disassemble_at(
        &data,
        Address::new(0x2000),
        64,
        rustida_core::Endianness::LittleEndian,
    );
    let data_xrefs = extract_xrefs(&data_instructions);
    assert_eq!(data_xrefs.len(), 1);
    assert_eq!(data_xrefs[0].destination, Address::new(0x402000));
    assert_eq!(data_xrefs[0].ref_type, CrossReferenceType::Data);
}

#[test]
fn test_function_detection_and_call_graph() {
    let instructions = decode_analysis();
    let functions = detect_functions(&instructions, &[Address::new(0x1000)]);

    assert_eq!(functions.len(), 2, "entry function plus direct callee");
    let main = functions.iter().find(|f| f.address.0 == 0x1000).unwrap();
    assert_eq!(main.name, "sub_1000");
    assert_eq!(main.end_address, Address::new(0x1014));
    assert_eq!(main.blocks.len(), 3);
    assert_eq!(main.calls.len(), 1);
    assert_eq!(main.calls[0].callee, Some(Address::new(0x1014)));
    assert!(main.calls[0].is_direct);

    let callee = functions.iter().find(|f| f.address.0 == 0x1014).unwrap();
    assert_eq!(callee.blocks.len(), 1);
    assert_eq!(callee.size, 1);

    let call_graph = build_call_graph(&instructions, &functions);
    assert_eq!(call_graph.len(), 1);
    assert_eq!(call_graph[0].caller, Address::new(0x1000));
    assert_eq!(call_graph[0].callee, Some(Address::new(0x1014)));

    // An indirect call is recorded without an invented callee.
    let indirect = disassemble_at(
        common::INDIRECT_CALL_CODE,
        Address::new(BASE),
        64,
        rustida_core::Endianness::LittleEndian,
    );
    let functions = detect_functions(&indirect, &[Address::new(BASE)]);
    let graph = build_call_graph(&indirect, &functions);
    assert_eq!(graph.len(), 1);
    assert_eq!(graph[0].callee, None);
    assert!(!graph[0].is_direct);
}

#[test]
fn test_analyze_disassembly_pipeline() {
    let instructions = decode_analysis();
    let analysis = analyze_disassembly(
        &instructions,
        rustida_loader::Architecture {
            name: "x86-64".to_string(),
            bits: 64,
            endianness: rustida_core::Endianness::LittleEndian,
        },
    );

    assert_eq!(analysis.blocks.len(), 4);
    assert_eq!(analysis.cfg_nodes.len(), 4);
    assert_eq!(analysis.cfg_edges.len(), 5);
    assert_eq!(analysis.cross_references.len(), 2);
    assert!(!analysis.functions.is_empty());
    assert!(!analysis.call_graph.is_empty());
    assert!(analysis.function_at(Address::new(0x1001)).is_some());
    assert_eq!(
        analysis.block_at(Address::new(0x1007)).unwrap().address,
        Address::new(0x1000)
    );
}

#[test]
fn test_analyze_pe_binary_uses_real_symbols_and_entry() {
    let binary = load_pe(&common::build_pe32plus()).expect("load PE32+ fixture");
    let analysis = analyze_binary(&binary);

    assert!(!analysis.instructions.is_empty());
    assert_eq!(analysis.instructions[0].address, binary.entry_point);
    assert_eq!(analysis.instructions[0].mnemonic, "PUSH");
    assert!(analysis.analysis.blocks.len() >= 2);
    assert!(!analysis.analysis.cfg_edges.is_empty());

    // The entry point is also an exported symbol, so the detected function
    // must carry its real name.
    let entry_function = analysis
        .analysis
        .functions
        .iter()
        .find(|f| f.address == binary.entry_point)
        .expect("function at the PE entry point");
    assert_eq!(entry_function.name, "exported_func");

    // The return instruction is real and terminates the entry block.
    assert!(analysis
        .instructions
        .iter()
        .any(|i| i.flow == InstructionFlow::Return && i.address.0 < binary.entry_point.0 + 0x20));
}

#[test]
fn test_analyze_macho64_binary() {
    let binary = load_mach_o(&common::build_macho64_x86_64()).expect("load Mach-O fixture");
    let analysis = analyze_binary(&binary);

    assert!(!analysis.instructions.is_empty());
    assert_eq!(analysis.instructions[0].address, binary.entry_point);
    assert!(
        analysis
            .instructions
            .iter()
            .all(|i| i.address.0 >= binary.entry_point.0)
    );

    let main = analysis
        .analysis
        .functions
        .iter()
        .find(|f| f.name == "_main")
        .expect("_main function from the symbol table");
    assert_eq!(main.address, binary.entry_point);
    assert!(
        binary
            .symbols
            .iter()
            .any(|s| s.name == "_main" && s.kind == SymbolKind::Function)
    );
}

#[test]
fn test_non_x86_binary_parses_but_is_not_decoded() {
    let binary = load_mach_o(&common::build_macho64_arm64()).expect("load arm64 Mach-O");
    let analysis = analyze_binary(&binary);

    assert!(analysis.instructions.is_empty());
    assert!(analysis.analysis.blocks.is_empty());
    assert!(analysis.analysis.functions.is_empty());
    // Parsing still produced a usable model.
    assert_eq!(binary.arch.name, "aarch64");
    assert!(!binary.sections.is_empty());
    assert!(!binary.symbols.is_empty());
}

#[test]
fn test_disassemble_binary_real_elf() {
    #[cfg(target_os = "linux")]
    {
        let path = std::env::current_exe().expect("current exe");
        let data = std::fs::read(path).expect("read exe");
        let binary = rustida_loader::load_elf(&data).expect("load ELF");
        let instructions = disassemble_binary(&binary);

        assert!(!instructions.is_empty(), "real ELF must decode");
        assert!(
            instructions
                .windows(2)
                .all(|w| w[0].address.0 <= w[1].address.0)
        );

        // Every instruction address must be inside an executable section.
        for instruction in instructions.iter().take(200) {
            assert!(
                binary
                    .executable_sections()
                    .any(|s| s.contains_va(instruction.address.0)),
                "instruction at {} outside executable sections",
                instruction.address
            );
        }

        let analysis = analyze_binary(&binary);
        assert!(!analysis.analysis.blocks.is_empty());
        assert!(!analysis.analysis.functions.is_empty());
    }
}
