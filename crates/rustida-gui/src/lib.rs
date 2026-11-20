//! **rustida-gui** - GUI for RustIDA
//!
//! Provides a graphical interface for binary analysis using egui/eframe.
//!
//! # Dependencies
//! - `goblin` - ELF format parsing
//! - `iced-x86` - x86/x64 instruction decoding
//! - `rustida-core` - Core types (Address, Architecture, etc.)
//! - `rustida-loader` - Binary loading functionality
//! - `eframe` - eframe GUI framework
//! - `egui` - Immediate mode GUI library
//!
//! # Application
//!
//! Main application structure and window management.
pub mod app;
