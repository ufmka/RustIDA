//! Cross-reference extraction.

use std::collections::HashSet;

use rustida_core::Address;

use crate::disasm::{DisassembledInstruction, InstructionFlow, Operand};

use super::types::{CrossReference, CrossReferenceType};

/// Extract direct code and data cross-references.
///
/// * direct calls become [`CrossReferenceType::Call`];
/// * direct jumps and conditional branches become [`CrossReferenceType::Branch`];
/// * absolute memory operands become [`CrossReferenceType::Data`].
///
/// Indirect branches and calls never produce a reference because their target
/// is not known statically.
pub fn extract_xrefs(instructions: &[DisassembledInstruction]) -> Vec<CrossReference> {
    let mut refs = Vec::new();
    let mut seen: HashSet<(u64, u64, CrossReferenceType)> = HashSet::new();

    for instruction in instructions {
        let mut push = |destination: Address, ref_type: CrossReferenceType| {
            let key = (instruction.address.0, destination.0, ref_type);
            if seen.insert(key) {
                refs.push(CrossReference {
                    source: instruction.address,
                    destination,
                    ref_type,
                });
            }
        };

        match instruction.flow {
            InstructionFlow::Call => {
                if let Some(target) = instruction.target {
                    push(target, CrossReferenceType::Call);
                }
            }
            InstructionFlow::Jump | InstructionFlow::ConditionalJump => {
                if let Some(target) = instruction.target {
                    push(target, CrossReferenceType::Branch);
                }
            }
            InstructionFlow::IndirectCall
            | InstructionFlow::IndirectJump
            | InstructionFlow::Return
            | InstructionFlow::Interrupt
            | InstructionFlow::Exception
            | InstructionFlow::Next => {}
        }

        // Absolute memory operands (`mov eax, [0x401000]`) are data xrefs.
        for operand in &instruction.operands {
            if let Operand::Memory {
                base: None,
                index: None,
                disp,
                ..
            } = operand
                && *disp > 0
            {
                push(Address::new(*disp as u64), CrossReferenceType::Data);
            }
        }
    }

    refs
}

/// All references that point at `target`.
pub fn xrefs_to(instructions: &[DisassembledInstruction], target: Address) -> Vec<CrossReference> {
    extract_xrefs(instructions)
        .into_iter()
        .filter(|r| r.destination == target)
        .collect()
}
