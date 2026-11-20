//! Analysis engine: basic blocks, CFG, cross-references, functions and calls.

pub mod basic_blocks;
pub mod call_graph;
pub mod cfg;
pub mod functions;
pub mod types;
pub mod xrefs;

pub use basic_blocks::build_basic_blocks;
pub use call_graph::{CallSite, build_call_graph, extract_call_sites};
pub use cfg::{build_cfg, successors};
pub use functions::{detect_functions, detect_functions_in_binary};
pub use types::{
    BasicBlock, BlockTerminator, CFGEdge, CFGEdgeType, CFGNode, CallGraphEdge, CrossReference,
    CrossReferenceType, DisassembledFunction, DisassemblyAnalysis,
};
pub use xrefs::{extract_xrefs, xrefs_to};

use rustida_core::{Address, Architecture};

use crate::common::Binary;
use crate::disasm::{DisassembledInstruction, disassemble_binary};

/// Run the complete analysis pipeline over a decoded instruction listing.
///
/// The architecture is accepted for API symmetry and future non-x86 decoders;
/// the current pipeline is architecture-independent because instruction flow
/// is already classified by the decoder.
pub fn analyze_disassembly(
    instructions: &[DisassembledInstruction],
    _architecture: Architecture,
) -> DisassemblyAnalysis {
    if instructions.is_empty() {
        return DisassemblyAnalysis::default();
    }

    let blocks = build_basic_blocks(instructions);
    let (cfg_nodes, cfg_edges) = build_cfg(&blocks);
    let cross_references = extract_xrefs(instructions);

    let entry_points = vec![instructions[0].address];
    let detected = detect_functions(instructions, &entry_points);
    let call_graph = build_call_graph(instructions, &detected);

    DisassemblyAnalysis {
        blocks,
        cfg_nodes,
        cfg_edges,
        cross_references,
        functions: detected,
        call_graph,
    }
}

/// Result of decoding and analysing a loaded binary.
#[derive(Debug, Clone)]
pub struct BinaryAnalysis {
    /// Decoded instructions.
    pub instructions: Vec<DisassembledInstruction>,
    /// Analysis results.
    pub analysis: DisassemblyAnalysis,
}

/// Decode all executable sections of `binary` and analyse the result.
///
/// Function names are resolved from the binary's symbols and exports.
pub fn analyze_binary(binary: &Binary) -> BinaryAnalysis {
    let instructions = disassemble_binary(binary);
    let mut analysis = analyze_disassembly(&instructions, binary.arch.clone());

    let functions = detect_functions_in_binary(binary, &instructions);
    if !functions.is_empty() {
        analysis.call_graph = build_call_graph(&instructions, &functions);
        analysis.functions = functions;
    }

    BinaryAnalysis {
        instructions,
        analysis,
    }
}

/// Convenience wrapper: address of the function entry containing `address`.
pub fn containing_function(
    analysis: &DisassemblyAnalysis,
    address: Address,
) -> Option<&DisassembledFunction> {
    analysis.function_at(address)
}
