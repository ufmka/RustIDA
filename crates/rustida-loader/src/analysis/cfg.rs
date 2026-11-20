//! Control-flow-graph construction.

use std::collections::HashMap;

use rustida_core::Address;

use super::types::{BasicBlock, BlockTerminator, CFGEdge, CFGEdgeType, CFGNode};

fn next_block_index(blocks: &[BasicBlock], end: u64, map: &HashMap<u64, usize>) -> Option<usize> {
    map.get(&end)
        .copied()
        .or_else(|| blocks.iter().position(|b| b.address.0 == end))
}

/// Build CFG nodes and a flat edge list from basic blocks.
///
/// Branch targets that do not correspond to an analysed block are preserved as
/// edges to that address, so the GUI can display unresolved/external targets.
/// Indirect branches never receive an invented target.
pub fn build_cfg(blocks: &[BasicBlock]) -> (Vec<CFGNode>, Vec<CFGEdge>) {
    let mut map: HashMap<u64, usize> = HashMap::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        map.entry(block.address.0).or_insert(index);
    }

    let mut nodes = Vec::with_capacity(blocks.len());
    let mut all_edges = Vec::new();

    for block in blocks {
        let end = block.end_address();
        let mut edges = Vec::new();

        match &block.terminator {
            BlockTerminator::Fallthrough => {
                if next_block_index(blocks, end, &map).is_some() {
                    edges.push(CFGEdge {
                        target: Some(Address::new(end)),
                        edge_type: CFGEdgeType::Fallthrough,
                    });
                }
            }
            BlockTerminator::Call(_) | BlockTerminator::IndirectCall => {
                // A call returns to the next instruction: that is the
                // intraprocedural successor. The callee is recorded in the
                // call graph, not here.
                if next_block_index(blocks, end, &map).is_some() {
                    edges.push(CFGEdge {
                        target: Some(Address::new(end)),
                        edge_type: CFGEdgeType::Fallthrough,
                    });
                }
            }
            BlockTerminator::ConditionalBranch { address, .. } => {
                if let Some(target) = address {
                    edges.push(CFGEdge {
                        target: Some(*target),
                        edge_type: CFGEdgeType::Conditional,
                    });
                }
                if next_block_index(blocks, end, &map).is_some() {
                    edges.push(CFGEdge {
                        target: Some(Address::new(end)),
                        edge_type: CFGEdgeType::Fallthrough,
                    });
                }
            }
            BlockTerminator::UnconditionalJump(target) => {
                edges.push(CFGEdge {
                    target: Some(*target),
                    edge_type: CFGEdgeType::Unconditional,
                });
            }
            BlockTerminator::IndirectJump(target) => {
                edges.push(CFGEdge {
                    target: *target,
                    edge_type: CFGEdgeType::Indirect,
                });
            }
            BlockTerminator::Return => {
                edges.push(CFGEdge {
                    target: None,
                    edge_type: CFGEdgeType::Return,
                });
            }
            BlockTerminator::Interrupt | BlockTerminator::Invalid => {}
        }

        all_edges.extend(edges.iter().cloned());
        nodes.push(CFGNode {
            address: block.address,
            block: block.clone(),
            edges,
        });
    }

    (nodes, all_edges)
}

/// Compute intraprocedural successor block addresses for a block.
///
/// Used by function detection. Calls fall through; returns and indirect jumps
/// have no successors.
pub fn successors(block: &BasicBlock) -> Vec<Address> {
    match &block.terminator {
        BlockTerminator::Fallthrough | BlockTerminator::Call(_) | BlockTerminator::IndirectCall => {
            vec![Address::new(block.end_address())]
        }
        BlockTerminator::ConditionalBranch { address, .. } => {
            let mut result = Vec::new();
            if let Some(target) = address {
                result.push(*target);
            }
            result.push(Address::new(block.end_address()));
            result
        }
        BlockTerminator::UnconditionalJump(target) => vec![*target],
        BlockTerminator::IndirectJump(target) => target.iter().copied().collect(),
        BlockTerminator::Return | BlockTerminator::Interrupt | BlockTerminator::Invalid => {
            Vec::new()
        }
    }
}
