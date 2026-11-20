//! Analysis data model.

use rustida_core::Address;

use crate::disasm::DisassembledInstruction;

/// A basic block: a maximal straight-line instruction sequence with one entry
/// and one exit.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Address of the first instruction.
    pub address: Address,
    /// Size in bytes (last instruction end - first instruction start).
    pub size: u64,
    /// Indices into the analysed instruction slice.
    pub instructions: Vec<usize>,
    /// How control leaves the block.
    pub terminator: BlockTerminator,
}

impl BasicBlock {
    /// Address just past the last byte of the block.
    pub fn end_address(&self) -> u64 {
        self.address.0.saturating_add(self.size)
    }

    /// Whether the block contains `address`.
    pub fn contains(&self, address: Address) -> bool {
        address.0 >= self.address.0 && address.0 < self.end_address()
    }
}

/// How control leaves a basic block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockTerminator {
    /// Falls through to the next block.
    Fallthrough,
    /// Direct unconditional jump.
    UnconditionalJump(Address),
    /// Conditional branch with its direct target and condition mnemonic.
    ConditionalBranch {
        address: Option<Address>,
        condition: String,
    },
    /// Direct call (the block falls through afterwards).
    Call(Option<Address>),
    /// Indirect call (target unknown).
    IndirectCall,
    /// Function return.
    Return,
    /// Indirect jump (target unknown or computed at runtime).
    IndirectJump(Option<Address>),
    /// Interrupt / trap.
    Interrupt,
    /// Invalid or faulting instruction.
    Invalid,
}

impl BlockTerminator {
    /// Whether the terminator has a statically known target.
    pub fn target(&self) -> Option<Address> {
        match self {
            BlockTerminator::UnconditionalJump(a) => Some(*a),
            BlockTerminator::ConditionalBranch { address, .. } => *address,
            BlockTerminator::Call(a) => *a,
            BlockTerminator::IndirectJump(a) => *a,
            _ => None,
        }
    }
}

/// A node in the control-flow graph.
#[derive(Debug, Clone)]
pub struct CFGNode {
    /// Basic block start address.
    pub address: Address,
    /// The block itself.
    pub block: BasicBlock,
    /// Outgoing edges.
    pub edges: Vec<CFGEdge>,
}

/// A directed edge between two basic blocks or to a branch target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CFGEdge {
    /// Destination address. `None` for a return pseudo-edge.
    pub target: Option<Address>,
    /// Kind of edge.
    pub edge_type: CFGEdgeType,
}

/// Edge classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CFGEdgeType {
    /// Sequential flow.
    Fallthrough,
    /// Taken conditional branch.
    Conditional,
    /// Unconditional branch.
    Unconditional,
    /// Return from the function.
    Return,
    /// Computed / indirect branch.
    Indirect,
}

/// One cross-reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossReference {
    /// Address of the referring instruction.
    pub source: Address,
    /// Referenced address.
    pub destination: Address,
    /// Reference kind.
    pub ref_type: CrossReferenceType,
}

/// Cross-reference classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrossReferenceType {
    /// Execution flows to the destination (direct call/jump/branch).
    Code,
    /// Direct call.
    Call,
    /// Direct branch.
    Branch,
    /// Data reference (absolute memory operand).
    Data,
}

/// An edge in the call graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallGraphEdge {
    /// Address of the calling function.
    pub caller: Address,
    /// Address of the callee; `None` for an indirect call.
    pub callee: Option<Address>,
    /// Whether the call instruction had a direct target.
    pub is_direct: bool,
}

/// A detected function.
#[derive(Debug, Clone)]
pub struct DisassembledFunction {
    /// Best known name (`main`, `sub_401000`, ...).
    pub name: String,
    /// Start address.
    pub address: Address,
    /// End address (exclusive).
    pub end_address: Address,
    /// Size in bytes.
    pub size: u64,
    /// Blocks belonging to the function.
    pub blocks: Vec<BasicBlock>,
    /// Outgoing calls.
    pub calls: Vec<CallGraphEdge>,
}

impl DisassembledFunction {
    /// Whether `address` lies inside this function.
    pub fn contains(&self, address: Address) -> bool {
        address.0 >= self.address.0 && address.0 < self.end_address.0
    }
}

/// Result of analysing a decoded instruction listing.
#[derive(Debug, Clone, Default)]
pub struct DisassemblyAnalysis {
    /// Basic blocks.
    pub blocks: Vec<BasicBlock>,
    /// Control-flow graph nodes.
    pub cfg_nodes: Vec<CFGNode>,
    /// Flat list of all CFG edges (mirrors the edges stored in nodes).
    pub cfg_edges: Vec<CFGEdge>,
    /// Cross-references.
    pub cross_references: Vec<CrossReference>,
    /// Detected functions.
    pub functions: Vec<DisassembledFunction>,
    /// Call graph edges.
    pub call_graph: Vec<CallGraphEdge>,
}

impl DisassemblyAnalysis {
    /// Find the function containing `address`.
    pub fn function_at(&self, address: Address) -> Option<&DisassembledFunction> {
        self.functions.iter().find(|f| f.contains(address))
    }

    /// Find the block containing `address`.
    pub fn block_at(&self, address: Address) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.contains(address))
    }

    /// Unused-instruction helper retained for API stability.
    pub fn instruction_count(instructions: &[DisassembledInstruction]) -> usize {
        instructions.len()
    }
}
