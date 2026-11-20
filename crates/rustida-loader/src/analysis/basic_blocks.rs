//! Basic-block partitioning.
//!
//! The algorithm is the classic leader-based construction:
//!
//! * the first instruction is a leader;
//! * every direct branch/call target is a leader;
//! * the instruction after any control-flow instruction is a leader;
//! * the first instruction after an address gap is a leader.
//!
//! Blocks then run from one leader to the instruction before the next leader.

use std::collections::HashMap;

use rustida_core::Address;

use crate::disasm::{DisassembledInstruction, InstructionFlow};

use super::types::{BasicBlock, BlockTerminator};

/// Compute the leader bitmap for an instruction listing.
fn leaders(instructions: &[DisassembledInstruction]) -> Vec<bool> {
    let count = instructions.len();
    let mut is_leader = vec![false; count];
    if count == 0 {
        return is_leader;
    }
    is_leader[0] = true;

    let mut address_to_index: HashMap<u64, usize> = HashMap::with_capacity(count);
    for (index, instruction) in instructions.iter().enumerate() {
        address_to_index
            .entry(instruction.address.0)
            .or_insert(index);
    }

    for index in 0..count {
        let instruction = &instructions[index];
        if instruction.flow.is_direct_branch()
            && let Some(target) = instruction.target
            && let Some(&target_index) = address_to_index.get(&target.0)
        {
            is_leader[target_index] = true;
        }
        if instruction.flow.ends_block() && index + 1 < count {
            is_leader[index + 1] = true;
        }
        if index > 0 && instruction.address.0 != instructions[index - 1].end_address() {
            is_leader[index] = true;
        }
    }

    is_leader
}

fn terminator_for(instruction: &DisassembledInstruction) -> BlockTerminator {
    match instruction.flow {
        InstructionFlow::Next => BlockTerminator::Fallthrough,
        InstructionFlow::Jump => match instruction.target {
            Some(target) => BlockTerminator::UnconditionalJump(target),
            None => BlockTerminator::IndirectJump(None),
        },
        InstructionFlow::ConditionalJump => BlockTerminator::ConditionalBranch {
            address: instruction.target,
            condition: instruction.mnemonic.clone(),
        },
        InstructionFlow::Call => BlockTerminator::Call(instruction.target),
        InstructionFlow::IndirectCall => BlockTerminator::IndirectCall,
        InstructionFlow::Return => BlockTerminator::Return,
        InstructionFlow::IndirectJump => BlockTerminator::IndirectJump(instruction.target),
        InstructionFlow::Interrupt => BlockTerminator::Interrupt,
        InstructionFlow::Exception => BlockTerminator::Invalid,
    }
}

/// Partition a sorted instruction listing into basic blocks.
///
/// Instructions are expected to be ordered by address. Gaps are tolerated and
/// start a new block; overlaps are resolved by address lookup.
pub fn build_basic_blocks(instructions: &[DisassembledInstruction]) -> Vec<BasicBlock> {
    if instructions.is_empty() {
        return Vec::new();
    }

    let is_leader = leaders(instructions);
    let leader_indices: Vec<usize> = is_leader
        .iter()
        .enumerate()
        .filter_map(|(index, &leader)| if leader { Some(index) } else { None })
        .collect();

    let mut blocks = Vec::with_capacity(leader_indices.len());
    for (position, &start) in leader_indices.iter().enumerate() {
        let end = leader_indices
            .get(position + 1)
            .copied()
            .unwrap_or(instructions.len());
        if start >= end {
            continue;
        }
        let first = &instructions[start];
        let last = &instructions[end - 1];
        let block_end = last.end_address();
        let size = block_end.saturating_sub(first.address.0);
        blocks.push(BasicBlock {
            address: Address::new(first.address.0),
            size,
            instructions: (start..end).collect(),
            terminator: terminator_for(last),
        });
    }

    blocks
}
