//! x86 / x86-64 disassembly built on `iced-x86`.
//!
//! The decoder produces a format-independent [`DisassembledInstruction`] that
//! carries the exact bytes, the control-flow class and (for direct branches)
//! the resolved target. This is what the analysis engine and the GUI consume.

use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind, Register};
use rustida_core::{Address, Endianness};

use crate::common::Binary;

/// Classification of an instruction's effect on control flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionFlow {
    /// Falls through to the next instruction.
    Next,
    /// Direct call.
    Call,
    /// Indirect call through a register or memory.
    IndirectCall,
    /// Return from a function.
    Return,
    /// Direct unconditional jump.
    Jump,
    /// Indirect unconditional jump.
    IndirectJump,
    /// Conditional jump.
    ConditionalJump,
    /// Interrupt / system call style instruction.
    Interrupt,
    /// Invalid or faulting instruction.
    Exception,
}

impl InstructionFlow {
    /// Whether this instruction ends a basic block.
    pub const fn ends_block(self) -> bool {
        !matches!(self, InstructionFlow::Next)
    }

    /// Whether this instruction transfers control to a direct target.
    pub const fn is_direct_branch(self) -> bool {
        matches!(
            self,
            InstructionFlow::Call | InstructionFlow::Jump | InstructionFlow::ConditionalJump
        )
    }
}

/// An operand of a decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// Immediate constant.
    Immediate(u64),
    /// Register name (e.g. `RAX`).
    Register(String),
    /// Memory reference.
    Memory {
        /// Base register, if any.
        base: Option<String>,
        /// Index register, if any.
        index: Option<String>,
        /// Index scale (1, 2, 4, 8).
        scale: u8,
        /// Displacement.
        disp: i64,
    },
    /// A direct branch target.
    Branch(Address),
    /// A symbolic label (kept for callers that attach names later).
    Label(String),
}

impl Operand {
    /// Format the operand the way a disassembly listing normally shows it.
    pub fn format(&self) -> String {
        match self {
            Operand::Immediate(v) => format!("{v:#x}"),
            Operand::Register(r) => r.clone(),
            Operand::Memory {
                base,
                index,
                scale,
                disp,
            } => {
                let mut parts = Vec::new();
                if let Some(b) = base {
                    parts.push(b.clone());
                }
                if let Some(i) = index {
                    if *scale > 1 {
                        parts.push(format!("{i}*{scale}"));
                    } else {
                        parts.push(i.clone());
                    }
                }
                let mut inner = parts.join(" + ");
                if *disp != 0 || inner.is_empty() {
                    if inner.is_empty() {
                        inner = format!("{disp:#x}");
                    } else if *disp > 0 {
                        inner.push_str(&format!(" + {disp:#x}"));
                    } else {
                        inner.push_str(&format!(" - {:#x}", -disp));
                    }
                }
                format!("[{inner}]")
            }
            Operand::Branch(a) => format!("{a}"),
            Operand::Label(l) => l.clone(),
        }
    }
}

/// A decoded instruction.
#[derive(Debug, Clone)]
pub struct DisassembledInstruction {
    /// Virtual address of the instruction.
    pub address: Address,
    /// Instruction length in bytes.
    pub length: usize,
    /// Raw instruction bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic as displayed (upper case).
    pub mnemonic: String,
    /// Decoded operands.
    pub operands: Vec<Operand>,
    /// Control-flow classification.
    pub flow: InstructionFlow,
    /// Resolved direct branch/call target.
    pub target: Option<Address>,
    /// Whether iced-x86 decoded this as a valid instruction.
    pub valid: bool,
}

impl DisassembledInstruction {
    /// Address immediately after this instruction.
    pub fn end_address(&self) -> u64 {
        self.address.0.saturating_add(self.length as u64)
    }

    /// Textual form: `mnemonic op0, op1, ...`.
    pub fn text(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            let ops: Vec<String> = self.operands.iter().map(Operand::format).collect();
            format!("{} {}", self.mnemonic, ops.join(", "))
        }
    }

    /// Number of bytes shown in a hex listing.
    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(self.bytes.len() * 3);
        for b in &self.bytes {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// Convert an `iced-x86` flow class to our own enum.
fn map_flow(flow: FlowControl) -> InstructionFlow {
    match flow {
        FlowControl::Next | FlowControl::XbeginXabortXend => InstructionFlow::Next,
        FlowControl::UnconditionalBranch => InstructionFlow::Jump,
        FlowControl::IndirectBranch => InstructionFlow::IndirectJump,
        FlowControl::ConditionalBranch => InstructionFlow::ConditionalJump,
        FlowControl::Return => InstructionFlow::Return,
        FlowControl::Call => InstructionFlow::Call,
        FlowControl::IndirectCall => InstructionFlow::IndirectCall,
        FlowControl::Interrupt => InstructionFlow::Interrupt,
        FlowControl::Exception => InstructionFlow::Exception,
    }
}

fn operand_from_iced(instruction: &iced_x86::Instruction, index: u32) -> Operand {
    match instruction.op_kind(index) {
        OpKind::Register => {
            Operand::Register(format!("{:?}", instruction.op_register(index)).to_uppercase())
        }
        OpKind::Memory => {
            let base = instruction.memory_base();
            let index_reg = instruction.memory_index();
            let scale = instruction.memory_index_scale();
            Operand::Memory {
                base: if base == Register::None {
                    None
                } else {
                    Some(format!("{base:?}").to_uppercase())
                },
                index: if index_reg == Register::None {
                    None
                } else {
                    Some(format!("{index_reg:?}").to_uppercase())
                },
                scale: u8::try_from(scale).unwrap_or(1),
                disp: instruction.memory_displacement64() as i64,
            }
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Operand::Branch(Address::new(instruction.near_branch_target()))
        }
        OpKind::FarBranch16 => Operand::Immediate(u64::from(instruction.far_branch16())),
        OpKind::FarBranch32 => Operand::Immediate(u64::from(instruction.far_branch32())),
        // `try_immediate` covers every immediate encoding (including the
        // second imm8 of `enter`); anything else is displayed symbolically
        // rather than panicking.
        _ => match instruction.try_immediate(index) {
            Ok(value) => Operand::Immediate(value),
            Err(_) => Operand::Label(format!("{:?}", instruction.op_kind(index))),
        },
    }
}

/// Decode `data` as x86 code located at `base_address`.
///
/// `bits` must be 16, 32 or 64. iced-x86 only supports the x86 family, which is
/// little-endian; a big-endian request returns an empty listing.
pub fn disassemble_at(
    data: &[u8],
    base_address: Address,
    bits: u32,
    endianness: Endianness,
) -> Vec<DisassembledInstruction> {
    if endianness == Endianness::BigEndian || !matches!(bits, 16 | 32 | 64) {
        return Vec::new();
    }

    let mut decoder = Decoder::new(bits, data, DecoderOptions::NONE);
    decoder.set_ip(base_address.0);
    let mut instructions = Vec::new();

    while decoder.can_decode() {
        let position = decoder.position();
        let instruction = decoder.decode();
        let length = instruction.len();

        // A zero-length decode would loop forever on corrupt input.
        if length == 0 {
            break;
        }

        let end = (position + length).min(data.len());
        let bytes = data[position..end].to_vec();

        // iced-x86 asserts when operand accessors are used on an invalid
        // instruction, so invalid decodes deliberately expose no operands.
        let valid = !instruction.is_invalid();
        let flow = if valid {
            map_flow(instruction.flow_control())
        } else {
            InstructionFlow::Exception
        };
        let target = if valid
            && flow.is_direct_branch()
            && matches!(
                instruction.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
            Some(Address::new(instruction.near_branch_target()))
        } else {
            None
        };

        let mut operands = Vec::new();
        if valid {
            operands.reserve(instruction.op_count() as usize);
            for index in 0..instruction.op_count() {
                operands.push(operand_from_iced(&instruction, index));
            }
        }

        instructions.push(DisassembledInstruction {
            address: Address::new(instruction.ip()),
            length,
            bytes,
            mnemonic: format!("{:?}", instruction.mnemonic()).to_uppercase(),
            operands,
            flow,
            target,
            valid,
        });
    }

    instructions
}

/// Decode machine code as 64-bit x86 starting at address 0.
///
/// Kept as the simple entry point used by early callers. New code should use
/// [`disassemble_at`] or [`disassemble_binary`].
pub fn disassemble(data: &[u8], endianness: Endianness) -> Vec<DisassembledInstruction> {
    disassemble_at(data, Address::new(0), 64, endianness)
}

/// Decode every executable section of a loaded binary at its real virtual
/// address. Returns an address-sorted instruction listing.
///
/// Non-x86 binaries yield an empty listing; the caller can still display the
/// hex view and sections. This is the only place architecture dispatch lives,
/// so adding a new decoder later does not touch the GUI.
pub fn disassemble_binary(binary: &Binary) -> Vec<DisassembledInstruction> {
    if !binary.arch.is_x86() {
        return Vec::new();
    }

    let bits = match binary.arch.bits {
        16 | 32 | 64 => binary.arch.bits,
        _ => 64,
    };
    let endianness = binary.format.endianness;

    let mut all = Vec::new();
    for section in binary
        .sections
        .iter()
        .filter(|s| s.executable && s.file_size > 0)
    {
        let Some(bytes) = binary.read_at_offset(
            section.file_offset,
            usize::try_from(section.file_size).unwrap_or(0),
        ) else {
            continue;
        };
        all.extend(disassemble_at(bytes, section.address, bits, endianness));
    }

    all.sort_by_key(|i| i.address.0);
    all.dedup_by_key(|i| i.address.0);
    all
}

/// Decode executable sections and store the result in `binary.instructions`.
pub fn disassemble_binary_in_place(binary: &mut Binary) -> Vec<DisassembledInstruction> {
    let instructions = disassemble_binary(binary);
    binary.instructions = instructions.clone();
    instructions
}
