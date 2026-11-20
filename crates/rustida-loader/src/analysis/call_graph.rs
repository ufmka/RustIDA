//! Call-graph construction from decoded instructions.

use std::collections::HashSet;

use rustida_core::Address;

use crate::disasm::{DisassembledInstruction, InstructionFlow};

use super::types::{CallGraphEdge, DisassembledFunction};

/// A call instruction and its static target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallSite {
    /// Address of the call instruction.
    pub address: Address,
    /// Direct target, if any.
    pub target: Option<Address>,
    /// Whether the target was encoded in the instruction.
    pub is_direct: bool,
}

/// Extract every call site from an instruction listing.
pub fn extract_call_sites(instructions: &[DisassembledInstruction]) -> Vec<CallSite> {
    instructions
        .iter()
        .filter_map(|instruction| match instruction.flow {
            InstructionFlow::Call => Some(CallSite {
                address: instruction.address,
                target: instruction.target,
                is_direct: true,
            }),
            InstructionFlow::IndirectCall => Some(CallSite {
                address: instruction.address,
                target: None,
                is_direct: false,
            }),
            _ => None,
        })
        .collect()
}

/// Build caller/callee edges by attributing each call site to the function
/// whose address range contains it.
///
/// Calls outside any detected function are omitted. Indirect calls keep a
/// `None` callee; no target is invented.
pub fn build_call_graph(
    instructions: &[DisassembledInstruction],
    functions: &[DisassembledFunction],
) -> Vec<CallGraphEdge> {
    let mut edges = Vec::new();
    let mut seen: HashSet<(u64, Option<u64>, bool)> = HashSet::new();

    for site in extract_call_sites(instructions) {
        let Some(caller) = functions.iter().find(|f| f.contains(site.address)) else {
            continue;
        };
        let key = (caller.address.0, site.target.map(|a| a.0), site.is_direct);
        if seen.insert(key) {
            edges.push(CallGraphEdge {
                caller: caller.address,
                callee: site.target,
                is_direct: site.is_direct,
            });
        }
    }

    edges.sort_by_key(|e| (e.caller.0, e.callee.map(|a| a.0)));
    edges
}
