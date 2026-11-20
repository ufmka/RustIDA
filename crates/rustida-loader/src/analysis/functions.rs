//! Function detection from decoded code and the intraprocedural CFG.
//!
//! Heuristics (documented limitations):
//!
//! * A function starts at the binary entry point, at known/exported function
//!   symbols, and at direct call targets.
//! * Its body is the set of basic blocks reachable from that start without
//!   entering another known function start.
//! * Blocks reachable through indirect jumps are not followed, because the
//!   target is not statically known.
//! * Tail calls and `noreturn` functions can therefore be split; this is
//!   inherent to static analysis without full data-flow.

use std::collections::{HashMap, HashSet, VecDeque};

use rustida_core::{Address, SymbolKind};

use crate::analysis::basic_blocks::build_basic_blocks;
use crate::analysis::call_graph::extract_call_sites;
use crate::analysis::cfg::successors;
use crate::analysis::types::{BasicBlock, CallGraphEdge, DisassembledFunction};
use crate::common::Binary;
use crate::disasm::DisassembledInstruction;

/// Collect candidate function starts from explicit entries and direct calls.
fn candidate_starts(
    instructions: &[DisassembledInstruction],
    entry_points: &[Address],
) -> Vec<u64> {
    let mut candidates: Vec<u64> = entry_points
        .iter()
        .map(|a| a.0)
        .filter(|&a| a != 0)
        .collect();

    for site in extract_call_sites(instructions) {
        if let Some(target) = site.target.filter(|t| t.0 != 0) {
            candidates.push(target.0);
        }
    }

    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn block_index_by_address(blocks: &[BasicBlock]) -> HashMap<u64, usize> {
    let mut map = HashMap::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        map.entry(block.address.0).or_insert(index);
    }
    map
}

fn function_name(address: Address, names: &HashMap<u64, String>) -> String {
    names
        .get(&address.0)
        .cloned()
        .unwrap_or_else(|| format!("sub_{:x}", address.0))
}

/// Detect functions using entry points and direct call targets.
pub fn detect_functions(
    instructions: &[DisassembledInstruction],
    entry_points: &[Address],
) -> Vec<DisassembledFunction> {
    detect_functions_with_names(instructions, entry_points, &HashMap::new())
}

/// Detect functions and assign names from a symbol address map.
pub(crate) fn detect_functions_with_names(
    instructions: &[DisassembledInstruction],
    entry_points: &[Address],
    names: &HashMap<u64, String>,
) -> Vec<DisassembledFunction> {
    if instructions.is_empty() {
        return Vec::new();
    }

    let blocks = build_basic_blocks(instructions);
    if blocks.is_empty() {
        return Vec::new();
    }
    let index_by_address = block_index_by_address(&blocks);

    let mut candidates = candidate_starts(instructions, entry_points);
    // Keep only candidates that are the start of a real block.
    candidates.retain(|address| index_by_address.contains_key(address));
    let known_starts: HashSet<u64> = candidates.iter().copied().collect();

    let call_sites = extract_call_sites(instructions);
    let mut functions = Vec::new();
    let mut claimed: Vec<(u64, u64)> = Vec::new();

    for &start in &candidates {
        if claimed
            .iter()
            .any(|&(range_start, range_end)| start > range_start && start < range_end)
        {
            continue;
        }
        let Some(&start_block) = index_by_address.get(&start) else {
            continue;
        };

        let mut visited: HashSet<usize> = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(start_block);
        visited.insert(start_block);

        while let Some(block_index) = queue.pop_front() {
            let block = &blocks[block_index];
            for successor in successors(block) {
                if successor.0 != start && known_starts.contains(&successor.0) {
                    continue;
                }
                if let Some(successor_index) = index_by_address.get(&successor.0)
                && visited.insert(*successor_index)
            {
                queue.push_back(*successor_index);
            }
            }
        }

        let mut body: Vec<usize> = visited.into_iter().collect();
        body.sort_unstable();
        let function_blocks: Vec<BasicBlock> =
            body.iter().map(|&index| blocks[index].clone()).collect();
        let end_address = function_blocks
            .iter()
            .map(BasicBlock::end_address)
            .max()
            .unwrap_or(start);

        let mut calls = Vec::new();
        let mut seen_calls: HashSet<(Option<u64>, bool)> = HashSet::new();
        for site in &call_sites {
            if site.address.0 >= start && site.address.0 < end_address {
                let key = (site.target.map(|a| a.0), site.is_direct);
                if seen_calls.insert(key) {
                    calls.push(CallGraphEdge {
                        caller: Address::new(start),
                        callee: site.target,
                        is_direct: site.is_direct,
                    });
                }
            }
        }
        calls.sort_by_key(|c| (c.callee.map(|a| a.0), c.is_direct));

        functions.push(DisassembledFunction {
            name: function_name(Address::new(start), names),
            address: Address::new(start),
            end_address: Address::new(end_address),
            size: end_address.saturating_sub(start),
            blocks: function_blocks,
            calls,
        });
        claimed.push((start, end_address));
    }

    functions.sort_by_key(|f| f.address.0);
    functions
}

/// Detect functions using all information available in a loaded binary.
pub fn detect_functions_in_binary(
    binary: &Binary,
    instructions: &[DisassembledInstruction],
) -> Vec<DisassembledFunction> {
    let mut entry_points = Vec::new();
    let mut names: HashMap<u64, String> = HashMap::new();

    if binary.entry_point.0 != 0 {
        entry_points.push(binary.entry_point);
    }
    for symbol in &binary.symbols {
        if symbol.address.0 == 0 {
            continue;
        }
        match symbol.kind {
            SymbolKind::Function | SymbolKind::Export => {
                entry_points.push(symbol.address);
                names
                    .entry(symbol.address.0)
                    .or_insert_with(|| symbol.name.clone());
            }
            _ => {
                names
                    .entry(symbol.address.0)
                    .or_insert_with(|| symbol.name.clone());
            }
        }
    }
    for export in &binary.exports {
        if export.address.0 != 0 {
            entry_points.push(export.address);
            names
                .entry(export.address.0)
                .or_insert_with(|| export.name.clone());
        }
    }

    detect_functions_with_names(instructions, &entry_points, &names)
}
