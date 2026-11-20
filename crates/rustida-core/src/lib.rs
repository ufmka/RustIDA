//! **rustida-core** — fundamental types shared by every RustIDA crate.
//!
//! This crate deliberately has no dependency on any binary format. It only
//! defines the vocabulary used across the application: addresses,
//! architectures, permissions, symbols and structured errors.

use std::fmt;

/// A virtual address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address(pub u64);

impl Address {
    /// Create a new address.
    pub const fn new(value: u64) -> Self {
        Address(value)
    }

    /// Return the raw value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Return the raw value as `usize`, saturating on 32-bit hosts.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Checked addition.
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(v) => Some(Address(v)),
            None => None,
        }
    }

    /// Checked subtraction.
    pub const fn checked_sub(self, rhs: u64) -> Option<Self> {
        match self.0.checked_sub(rhs) {
            Some(v) => Some(Address(v)),
            None => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl From<u64> for Address {
    fn from(value: u64) -> Self {
        Address(value)
    }
}

impl From<Address> for u64 {
    fn from(value: Address) -> Self {
        value.0
    }
}

impl std::ops::Add<u64> for Address {
    type Output = Address;
    fn add(self, rhs: u64) -> Self::Output {
        Address(self.0.wrapping_add(rhs))
    }
}

impl std::ops::Sub<u64> for Address {
    type Output = Address;
    fn sub(self, rhs: u64) -> Self::Output {
        Address(self.0.wrapping_sub(rhs))
    }
}

/// Byte order of a binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    LittleEndian,
    BigEndian,
}

impl Endianness {
    /// Short human-readable name.
    pub const fn name(self) -> &'static str {
        match self {
            Endianness::LittleEndian => "little-endian",
            Endianness::BigEndian => "big-endian",
        }
    }
}

/// Memory access permissions of a segment or section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    /// No access.
    None,
    /// Execute-only.
    Execute,
    /// Read-only.
    Read,
    /// Write-only.
    Write,
    /// Read + execute.
    ReadExecute,
    /// Read + write.
    ReadWrite,
    /// Read + write + execute.
    ReadWriteExecute,
}

impl Permissions {
    /// Whether the region is readable.
    pub const fn readable(self) -> bool {
        matches!(
            self,
            Permissions::Read
                | Permissions::ReadExecute
                | Permissions::ReadWrite
                | Permissions::ReadWriteExecute
        )
    }

    /// Whether the region is writable.
    pub const fn writable(self) -> bool {
        matches!(
            self,
            Permissions::Write | Permissions::ReadWrite | Permissions::ReadWriteExecute
        )
    }

    /// Whether the region is executable.
    pub const fn executable(self) -> bool {
        matches!(
            self,
            Permissions::Execute | Permissions::ReadExecute | Permissions::ReadWriteExecute
        )
    }

    /// Build permissions from independent read/write/execute flags.
    pub const fn from_flags(read: bool, write: bool, execute: bool) -> Self {
        match (read, write, execute) {
            (true, true, true) => Permissions::ReadWriteExecute,
            (true, true, false) => Permissions::ReadWrite,
            (true, false, true) => Permissions::ReadExecute,
            (true, false, false) => Permissions::Read,
            (false, true, true) | (false, true, false) => Permissions::Write,
            (false, false, true) => Permissions::Execute,
            (false, false, false) => Permissions::None,
        }
    }

    /// Classic `rwx` string, e.g. `r-x`.
    pub const fn rwx(self) -> &'static str {
        match self {
            Permissions::None => "---",
            Permissions::Execute => "--x",
            Permissions::Read => "r--",
            Permissions::Write => "-w-",
            Permissions::ReadExecute => "r-x",
            Permissions::ReadWrite => "rw-",
            Permissions::ReadWriteExecute => "rwx",
        }
    }
}

/// A description of the CPU architecture a binary targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Architecture {
    /// Canonical name, e.g. `x86-64`, `i386`, `aarch64`, `arm`.
    pub name: String,
    /// Pointer width in bits.
    pub bits: u32,
    /// Byte order.
    pub endianness: Endianness,
}

impl Architecture {
    /// Create a new architecture description.
    pub fn new(name: impl Into<String>, bits: u32, endianness: Endianness) -> Self {
        Architecture {
            name: name.into(),
            bits,
            endianness,
        }
    }

    /// Whether this is an x86-family architecture that iced-x86 can decode.
    pub fn is_x86(&self) -> bool {
        matches!(self.bits, 16 | 32 | 64)
            && matches!(
                self.name.as_str(),
                "x86-64" | "x86" | "i386" | "i486" | "i586" | "i686" | "x86_16"
            )
    }
}

/// Structured error type shared by RustIDA crates.
#[derive(thiserror::Error, Debug)]
pub enum RustidaError {
    #[error("invalid binary format: {0}")]
    InvalidFormat(String),
    #[error("malformed binary: {0}")]
    Malformed(String),
    #[error("truncated binary: needed {needed} bytes at offset {offset:#x}, file has {available}")]
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(String),
    #[error("unsupported feature: {0}")]
    Unsupported(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("other error: {0}")]
    Other(String),
}

impl RustidaError {
    /// Convenience constructor for malformed-input errors.
    pub fn malformed(msg: impl Into<String>) -> Self {
        RustidaError::Malformed(msg.into())
    }

    /// Convenience constructor for truncation errors.
    pub fn truncated(offset: usize, needed: usize, available: usize) -> Self {
        RustidaError::Truncated {
            offset,
            needed,
            available,
        }
    }
}

/// Kind of a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// A function.
    Function,
    /// A data object / variable.
    Variable,
    /// A named label or section symbol.
    Label,
    /// An imported symbol.
    Import,
    /// An exported symbol.
    Export,
    /// A thread-local object.
    Tls,
}
