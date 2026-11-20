//! Main application window.
//!
//! Everything displayed here comes from [`rustida_loader`]: the file browser
//! loads real files, the loader auto-detects the container format, and the
//! section/segment/symbol/instruction/CFG views render parsed data only.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, RichText, Sense, Stroke, Vec2};
use eframe::{App, Frame};
use rustida_core::{Endianness, SymbolKind};
use rustida_loader::{
    BasicBlock, Binary, BinaryAnalysis, BinaryInfo, BlockTerminator, DisassembledInstruction,
    FormatKind, analyze_binary, detect_format, load_binary,
};


/// Which main view is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Sections,
    Segments,
    Symbols,
    Imports,
    Exports,
    Disassembly,
    ControlFlow,
    Hex,
}

impl Tab {
    const ALL: [Tab; 9] = [
        Tab::Overview,
        Tab::Sections,
        Tab::Segments,
        Tab::Symbols,
        Tab::Imports,
        Tab::Exports,
        Tab::Disassembly,
        Tab::ControlFlow,
        Tab::Hex,
    ];

    const fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Sections => "Sections",
            Tab::Segments => "Segments",
            Tab::Symbols => "Symbols",
            Tab::Imports => "Imports",
            Tab::Exports => "Exports",
            Tab::Disassembly => "Disassembly",
            Tab::ControlFlow => "Control flow",
            Tab::Hex => "Hex",
        }
    }
}

/// One entry in the built-in file browser.
struct BrowserEntry {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

/// The application state.
pub struct RustidaApp {
    current_dir: PathBuf,
    path_input: String,
    entries: Vec<BrowserEntry>,
    browser_error: Option<String>,
    show_browser: bool,

    binary: Option<Binary>,
    analysis: Option<BinaryAnalysis>,
    file_path: Option<PathBuf>,
    detected: Option<FormatKind>,

    error: Option<String>,
    status: String,

    tab: Tab,
    symbol_filter: String,
    disasm_filter: String,
    selected_function: Option<usize>,
    hex_section: usize,
    hex_page: usize,
}

impl RustidaApp {
    /// Create the app, optionally loading a binary given on the command line.
    pub fn new(initial: Option<PathBuf>) -> Self {
        let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        let mut app = RustidaApp {
            path_input: current_dir.display().to_string(),
            current_dir,
            entries: Vec::new(),
            browser_error: None,
            show_browser: true,
            binary: None,
            analysis: None,
            file_path: None,
            detected: None,
            error: None,
            status: "Open a binary from the file browser or pass a path on the command line."
                .to_string(),
            tab: Tab::Overview,
            symbol_filter: String::new(),
            disasm_filter: String::new(),
            selected_function: None,
            hex_section: 0,
            hex_page: 0,
        };
        app.refresh_dir();
        if let Some(path) = initial {
            app.load_path(&path);
        }
        app
    }

    // ------------------------------------------------------------------
    // Loading
    // ------------------------------------------------------------------

    fn refresh_dir(&mut self) {
        self.browser_error = None;
        self.path_input = self.current_dir.display().to_string();
        let read = match std::fs::read_dir(&self.current_dir) {
            Ok(read) => read,
            Err(err) => {
                self.browser_error =
                    Some(format!("Cannot read {}: {err}", self.current_dir.display()));
                self.entries.clear();
                return;
            }
        };

        let mut entries = Vec::new();
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                // Hidden files are almost never interesting here; keep the
                // listing focused.
                continue;
            }
            let path = entry.path();
            let metadata = entry.metadata().ok();
            let is_dir = metadata.as_ref().is_some_and(|m| m.is_dir());
            let size = metadata.as_ref().map_or(0, |m| m.len());
            entries.push(BrowserEntry {
                name,
                path,
                is_dir,
                size,
            });
        }
        entries.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        self.entries = entries;
    }

    fn navigate_to(&mut self, path: PathBuf) {
        if path.is_dir() {
            self.current_dir = path;
            self.refresh_dir();
        }
    }

    /// Load and analyse a file. All failures end up in the error modal.
    fn load_path(&mut self, path: &Path) {
        self.error = None;
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(err) => {
                self.error = Some(format!("Cannot read {}: {err}", path.display()));
                return;
            }
        };

        let Some(detected) = detect_format(&data) else {
            self.error = Some(format!(
                "{}: unrecognised binary format (expected ELF, PE or Mach-O)",
                path.display()
            ));
            return;
        };

        match load_binary(&data) {
            Ok(mut binary) => {
                let analysis = analyze_binary(&binary);
                binary.instructions = analysis.instructions.clone();
                let instruction_count = analysis.instructions.len();
                let function_count = analysis.analysis.functions.len();
                let block_count = analysis.analysis.blocks.len();
                self.status = format!(
                    "{} — {} {}, entry {}. {} bytes, {} sections, {} symbols, {} instructions, {} blocks, {} functions, {} xrefs.",
                    path.display(),
                    binary.format.name,
                    binary.arch.name,
                    binary.entry_point,
                    binary.bytes.len(),
                    binary.sections.len(),
                    binary.symbols.len(),
                    instruction_count,
                    block_count,
                    function_count,
                    analysis.analysis.cross_references.len(),
                );
                self.binary = Some(binary);
                self.analysis = Some(analysis);
                self.file_path = Some(path.to_path_buf());
                self.detected = Some(detected);
                self.selected_function = None;
                self.hex_section = 0;
                self.hex_page = 0;
                self.symbol_filter.clear();
                self.disasm_filter.clear();
                if self.tab == Tab::Hex {
                    self.tab = Tab::Overview;
                }
            }
            Err(err) => {
                self.error = Some(format!("{}: {err}", path.display()));
            }
        }
    }

    fn reload(&mut self) {
        if let Some(path) = self.file_path.clone() {
            self.load_path(&path);
        }
    }

    // ------------------------------------------------------------------
    // UI
    // ------------------------------------------------------------------

    fn show_menu(&mut self, ui: &mut egui::Ui) {
        egui::MenuBar::new().ui(ui, |ui| {
            ui.menu_button("File", |ui| {
                if ui.button("Open file browser").clicked() {
                    self.show_browser = true;
                    ui.close();
                }
                if ui
                    .add_enabled(self.file_path.is_some(), egui::Button::new("Reload binary"))
                    .clicked()
                {
                    self.reload();
                    ui.close();
                }
                ui.separator();
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
            });
            ui.menu_button("View", |ui| {
                for tab in Tab::ALL {
                    if ui.selectable_label(self.tab == tab, tab.title()).clicked() {
                        self.tab = tab;
                        ui.close();
                    }
                }
                ui.separator();
                ui.checkbox(&mut self.show_browser, "File browser");
            });
            ui.separator();
            ui.label(self.file_path.as_ref().map_or_else(
                || "No binary loaded".to_string(),
                |p| {
                    p.file_name().map_or_else(
                        || p.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    )
                },
            ));
            if let Some(detected) = self.detected {
                ui.label(RichText::new(detected_name(detected)).weak());
            }
        });
    }

    fn show_browser(&mut self, ui: &mut egui::Ui) {
        ui.heading("Files");
        ui.horizontal(|ui| {
            if ui.button("⬆").on_hover_text("Parent directory").clicked()
                && let Some(parent) = self.current_dir.parent()
            {
                self.navigate_to(parent.to_path_buf());
            }
            if ui.button("⟳").on_hover_text("Refresh").clicked() {
                self.refresh_dir();
            }
            if ui.button("🏠").on_hover_text("Working directory").clicked()
                && let Ok(dir) = std::env::current_dir()
            {
                self.navigate_to(dir);
            }
        });

        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.path_input)
                    .desired_width(f32::INFINITY)
                    .hint_text("/path/to/binary"),
            );
            let submitted = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if submitted {
                let path = PathBuf::from(self.path_input.trim());
                self.navigate_to(path);
            }
        });

        if let Some(error) = &self.browser_error {
            ui.colored_label(Color32::from_rgb(255, 120, 120), error);
        }

        ui.separator();

        let mut open: Option<PathBuf> = None;
        let mut enter: Option<PathBuf> = None;
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, self.entries.len(), |ui, range| {
                for entry in &self.entries[range] {
                    let label = if entry.is_dir {
                        format!("📁 {}", entry.name)
                    } else {
                        format!("📄 {}  ({})", entry.name, format_size(entry.size))
                    };
                    let selected = self.file_path.as_ref().is_some_and(|p| p == &entry.path);
                    let response = ui.add(
                        egui::Button::new(label)
                            .selected(selected)
                            .min_size(Vec2::new(ui.available_width(), row_height - 2.0)),
                    );
                    if response.clicked() {
                        if entry.is_dir {
                            enter = Some(entry.path.clone());
                        } else {
                            open = Some(entry.path.clone());
                        }
                    }
                }
            });

        if let Some(path) = enter {
            self.navigate_to(path);
        }
        if let Some(path) = open {
            self.load_path(&path);
        }
    }

    fn show_status(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if self.error.is_some()
                && ui
                    .colored_label(Color32::from_rgb(255, 120, 120), "⚠ error")
                    .clicked()
            {
                self.error = None;
            }
            ui.label(RichText::new(&self.status).small());
        });
    }

    fn show_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for tab in Tab::ALL {
                ui.selectable_value(&mut self.tab, tab, tab.title());
            }
        });
        ui.separator();
        match self.tab {
            Tab::Overview => self.show_overview(ui),
            Tab::Sections => self.show_sections(ui),
            Tab::Segments => self.show_segments(ui),
            Tab::Symbols => self.show_symbols(ui),
            Tab::Imports => self.show_imports(ui),
            Tab::Exports => self.show_exports(ui),
            Tab::Disassembly => self.show_disassembly(ui),
            Tab::ControlFlow => self.show_control_flow(ui),
            Tab::Hex => self.show_hex(ui),
        }
    }

    fn show_empty(&self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            ui.heading("No binary loaded");
            ui.label("Choose a file in the browser, or start RustIDA with a path.");
            ui.add_space(8.0);
            ui.label(RichText::new("Supported: ELF, PE32/PE32+, Mach-O and Fat Mach-O").weak());
        });
    }

    fn show_overview(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        let analysis = self.analysis.as_ref();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("overview_grid")
                .num_columns(2)
                .spacing([24.0, 6.0])
                .striped(true)
                .show(ui, |ui| {
                    row(ui, "File", &format!("{} bytes", binary.bytes.len()));
                    if let Some(path) = &self.file_path {
                        row(ui, "Path", &path.display().to_string());
                    }
                    row(ui, "Format", &binary.format.name);
                    row(ui, "Architecture", &binary.arch.name);
                    row(ui, "Bitness", &format!("{}-bit", binary.arch.bits));
                    row(ui, "Endianness", endianness_name(binary.format.endianness));
                    row(ui, "Entry point", &binary.entry_point.to_string());
                    row(ui, "Image base", &format!("{:#x}", binary.image_base));
                    row(ui, "Headers size", &format!("{:#x}", binary.headers_size));
                    row(ui, "Sections", &binary.sections.len().to_string());
                    row(ui, "Segments", &binary.segments.len().to_string());
                    row(ui, "Symbols", &binary.symbols.len().to_string());
                    row(ui, "Imports", &binary.imports.len().to_string());
                    row(ui, "Exports", &binary.exports.len().to_string());
                    if let Some(analysis) = analysis {
                        row(ui, "Instructions", &analysis.instructions.len().to_string());
                        row(ui, "Basic blocks", &analysis.analysis.blocks.len().to_string());
                        row(ui, "Functions", &analysis.analysis.functions.len().to_string());
                        row(
                            ui,
                            "Cross-references",
                            &analysis.analysis.cross_references.len().to_string(),
                        );
                    }
                });

            ui.add_space(12.0);
            ui.heading("Format details");
            format_details(ui, &binary.info);

            if binary.arch.bits == 0 {
                ui.add_space(8.0);
                ui.colored_label(
                    Color32::from_rgb(255, 190, 90),
                    "Unknown machine type; disassembly is unavailable.",
                );
            } else if !binary.arch.is_x86() {
                ui.add_space(8.0);
                ui.colored_label(
                    Color32::from_rgb(255, 190, 90),
                    "Parsed successfully. Instruction decoding currently supports the x86 family only.",
                );
            }
        });
    }

    fn show_sections(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("sections_grid")
                    .num_columns(7)
                    .spacing([18.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for header in [
                            "Name",
                            "Address",
                            "Size",
                            "File off",
                            "File size",
                            "Perms",
                            "X",
                        ] {
                            ui.strong(header);
                        }
                        ui.end_row();
                        for section in &binary.sections {
                            ui.monospace(if section.name.is_empty() {
                                "<unnamed>"
                            } else {
                                &section.name
                            });
                            ui.monospace(section.address.to_string());
                            ui.monospace(format!("{:#x}", section.size));
                            ui.monospace(format!("{:#x}", section.file_offset));
                            ui.monospace(format!("{:#x}", section.file_size));
                            ui.monospace(permissions_text(section.permissions));
                            ui.monospace(if section.executable { "yes" } else { "" });
                            ui.end_row();
                        }
                    });
            });
    }

    fn show_segments(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("segments_grid")
                    .num_columns(6)
                    .spacing([18.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for header in ["Name", "Address", "Size", "File off", "File size", "Perms"]
                        {
                            ui.strong(header);
                        }
                        ui.end_row();
                        for segment in &binary.segments {
                            ui.monospace(if segment.name.is_empty() {
                                "<unnamed>"
                            } else {
                                &segment.name
                            });
                            ui.monospace(segment.address.to_string());
                            ui.monospace(format!("{:#x}", segment.size));
                            ui.monospace(format!("{:#x}", segment.file_offset));
                            ui.monospace(format!("{:#x}", segment.file_size));
                            ui.monospace(permissions_text(segment.permissions));
                            ui.end_row();
                        }
                    });
            });
    }

    fn show_symbols(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.symbol_filter)
                    .desired_width(260.0)
                    .hint_text("name or address"),
            );
            ui.label(format!("{} symbols", binary.symbols.len()));
        });

        let filter = self.symbol_filter.to_lowercase();
        let mut indices: Vec<usize> = (0..binary.symbols.len())
            .filter(|&index| {
                filter.is_empty()
                    || binary.symbols[index].name.to_lowercase().contains(&filter)
                    || format!("{:#x}", binary.symbols[index].address.0).contains(&filter)
            })
            .collect();
        indices.sort_by_key(|&index| binary.symbols[index].address.0);

        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, indices.len(), |ui, range| {
                for &index in &indices[range] {
                    let symbol = &binary.symbols[index];
                    ui.monospace(format!(
                        "{}  {:<28} {:<8} size {:#x}",
                        symbol.address,
                        truncate(&symbol.name, 28),
                        symbol_kind(symbol.kind),
                        symbol.size
                    ));
                }
            });
    }

    fn show_imports(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        if binary.imports.is_empty() {
            ui.label("This binary has no imported symbols.");
            return;
        }
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, binary.imports.len(), |ui, range| {
                for import in &binary.imports[range] {
                    ui.monospace(format!(
                        "{}  {:<32} {}",
                        import.address,
                        truncate(&import.name, 32),
                        if import.library.is_empty() {
                            "-"
                        } else {
                            &import.library
                        }
                    ));
                }
            });
    }

    fn show_exports(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        if binary.exports.is_empty() {
            ui.label("This binary has no exported symbols.");
            return;
        }
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, binary.exports.len(), |ui, range| {
                for export in &binary.exports[range] {
                    let ordinal = export
                        .ordinal
                        .map_or_else(|| "-".to_string(), |o| o.to_string());
                    ui.monospace(format!(
                        "{}  {:<32} ordinal {}",
                        export.address,
                        truncate(&export.name, 32),
                        ordinal
                    ));
                }
            });
    }

    fn show_disassembly(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        let Some(analysis) = &self.analysis else {
            self.show_empty(ui);
            return;
        };
        if analysis.instructions.is_empty() {
            ui.colored_label(
                Color32::from_rgb(255, 190, 90),
                "No instructions decoded. The decoder supports x86 only, and this binary has no executable file-backed section.",
            );
            return;
        }

        let functions = &analysis.analysis.functions;
        let mut selected = self.selected_function;
        ui.horizontal(|ui| {
            ui.label("Function:");
            let current = selected.and_then(|index| functions.get(index)).map_or_else(
                || "All instructions".to_string(),
                |f| format!("{} @ {}", f.name, f.address),
            );
            egui::ComboBox::from_id_salt("function_combo")
                .selected_text(current)
                .width(320.0)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_value(&mut selected, None, "All instructions")
                        .clicked()
                    {
                        ui.close();
                    }
                    for (index, function) in functions.iter().enumerate() {
                        ui.selectable_value(
                            &mut selected,
                            Some(index),
                            format!("{} @ {}", function.name, function.address),
                        );
                    }
                });
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.disasm_filter)
                    .desired_width(200.0)
                    .hint_text("mnemonic, operand, address"),
            );
            ui.label(format!("{} instructions", analysis.instructions.len()));
        });
        self.selected_function = selected;

        let range = selected
            .and_then(|index| functions.get(index))
            .map(|f| (f.address.0, f.end_address.0));
        let filter = self.disasm_filter.to_lowercase();
        let indices: Vec<usize> = analysis
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, instruction)| {
                if let Some((start, end)) = range
                    && (instruction.address.0 < start || instruction.address.0 >= end)
                {
                    return false;
                }
                if filter.is_empty() {
                    return true;
                }
                instruction.text().to_lowercase().contains(&filter)
                    || format!("{:#x}", instruction.address.0).contains(&filter)
            })
            .map(|(index, _)| index)
            .collect();

        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 1.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, row_height, indices.len(), |ui, rows| {
                for &index in &indices[rows] {
                    let instruction = &analysis.instructions[index];
                    let text = format!(
                        "{:016x}  {:<26}  {}",
                        instruction.address.0,
                        truncate(&instruction.hex(), 26),
                        instruction.text()
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(text)
                                .monospace()
                                .color(instruction_color(instruction)),
                        )
                        .sense(Sense::hover()),
                    )
                    .on_hover_text(instruction_hint(binary, instruction));
                }
            });
    }

    fn show_control_flow(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        let Some(analysis) = &self.analysis else {
            self.show_empty(ui);
            return;
        };
        let functions = &analysis.analysis.functions;

        // Function selector.
        let mut selected = self.selected_function;
        ui.horizontal(|ui| {
            ui.label("Function:");
            let current = selected.and_then(|index| functions.get(index)).map_or_else(
                || "All blocks".to_string(),
                |f| format!("{} @ {}", f.name, f.address),
            );
            egui::ComboBox::from_id_salt("cfg_function_combo")
                .selected_text(current)
                .width(320.0)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_value(&mut selected, None, "All blocks")
                        .clicked()
                    {
                        ui.close();
                    }
                    for (index, function) in functions.iter().enumerate() {
                        ui.selectable_value(
                            &mut selected,
                            Some(index),
                            format!(
                                "{} @ {} ({} blocks)",
                                function.name,
                                function.address,
                                function.blocks.len()
                            ),
                        );
                    }
                });
        });
        self.selected_function = selected;

        let blocks: Vec<&BasicBlock> = match selected.and_then(|index| functions.get(index)) {
            Some(function) => function.blocks.iter().collect(),
            None => analysis.analysis.blocks.iter().collect(),
        };

        if blocks.is_empty() {
            ui.label("No basic blocks were built for this selection.");
            return;
        }

        let edge_map = cfg_edges_by_source(&analysis.analysis);
        show_control_flow_graph(ui, &blocks, &edge_map, binary, None);
    }

    fn show_hex(&mut self, ui: &mut egui::Ui) {
        let Some(binary) = &self.binary else {
            self.show_empty(ui);
            return;
        };
        let backed: Vec<usize> = binary
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.file_size > 0)
            .map(|(index, _)| index)
            .collect();
        if backed.is_empty() {
            ui.label("No file-backed sections to display.");
            return;
        }
        if !backed.contains(&self.hex_section) {
            self.hex_section = backed[0];
        }

        ui.horizontal(|ui| {
            ui.label("Section:");
            let current = &binary.sections[self.hex_section].name;
            egui::ComboBox::from_id_salt("hex_section_combo")
                .selected_text(if current.is_empty() {
                    "<unnamed>"
                } else {
                    current
                })
                .width(260.0)
                .show_ui(ui, |ui| {
                    for &index in &backed {
                        let name = &binary.sections[index].name;
                        ui.selectable_value(
                            &mut self.hex_section,
                            index,
                            if name.is_empty() { "<unnamed>" } else { name },
                        );
                    }
                });
            let section = &binary.sections[self.hex_section];
            ui.label(format!(
                "{} .. {:#x} ({} bytes)",
                section.address,
                section.address.0 + section.file_size,
                section.file_size
            ));
        });

        const PAGE: u64 = 256;
        let section = &binary.sections[self.hex_section];
        let pages = section.file_size.div_ceil(PAGE).max(1);
        self.hex_page = self.hex_page.min(pages.saturating_sub(1) as usize);
        ui.horizontal(|ui| {
            if ui.button("◀").clicked() {
                self.hex_page = self.hex_page.saturating_sub(1);
            }
            ui.label(format!("page {} / {}", self.hex_page + 1, pages));
            if ui.button("▶").clicked() {
                self.hex_page = (self.hex_page + 1).min(pages.saturating_sub(1) as usize);
            }
            ui.label(RichText::new("16 bytes per row").weak());
        });

        let start = section.file_offset + self.hex_page as u64 * PAGE;
        let wanted = (section.file_size - self.hex_page as u64 * PAGE).min(PAGE);
        let Some(bytes) = binary.read_at_offset(start, wanted as usize) else {
            ui.colored_label(
                Color32::from_rgb(255, 120, 120),
                "Section bytes are outside the file.",
            );
            return;
        };

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (row, chunk) in bytes.chunks(16).enumerate() {
                    let offset =
                        section.address.0 + self.hex_page as u64 * PAGE + (row as u64 * 16);
                    let mut hex = String::new();
                    for index in 0..16 {
                        if let Some(byte) = chunk.get(index) {
                            hex.push_str(&format!("{byte:02x} "));
                        } else {
                            hex.push_str("   ");
                        }
                    }
                    let ascii: String = chunk
                        .iter()
                        .map(|&b| {
                            if (0x20..=0x7e).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    ui.monospace(format!("{offset:016x}  {hex} |{ascii}|"));
                }
            });
    }

    fn show_error_dialog(&mut self, ctx: &egui::Context) {
        let Some(message) = self.error.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new("Error")
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .anchor(Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.colored_label(Color32::from_rgb(255, 120, 120), &message);
                ui.add_space(8.0);
                if ui.button("Close").clicked() {
                    self.error = None;
                }
            });
        if !open {
            self.error = None;
        }
    }
}

impl App for RustidaApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut Frame) {
        egui::Panel::top("menu_bar").show(ui, |ui| self.show_menu(ui));
        egui::Panel::bottom("status_bar").show(ui, |ui| self.show_status(ui));
        if self.show_browser {
            egui::Panel::left("file_browser")
                .resizable(true)
                .default_size(300.0)
                .min_size(220.0)
                .show(ui, |ui| self.show_browser(ui));
        }

        egui::CentralPanel::default().show(ui, |ui| self.show_tabs(ui));

        self.show_error_dialog(ui.ctx());
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

fn row(ui: &mut egui::Ui, key: &str, value: &str) {
    ui.label(RichText::new(key).strong());
    ui.monospace(value);
    ui.end_row();
}

fn format_details(ui: &mut egui::Ui, info: &BinaryInfo) {
    egui::Grid::new("format_details_grid")
        .num_columns(2)
        .spacing([24.0, 4.0])
        .striped(true)
        .show(ui, |ui| match info {
            BinaryInfo::Elf(elf) => {
                row(ui, "ELF class", if elf.is_64 { "ELF64" } else { "ELF32" });
                row(ui, "ELF type", &format!("{:#x}", elf.elf_type));
                row(ui, "Machine", &format!("{:#x}", elf.machine));
                row(ui, "Flags", &format!("{:#x}", elf.flags));
                if let Some(interpreter) = &elf.interpreter {
                    row(ui, "Interpreter", interpreter);
                }
                if let Some(soname) = &elf.soname {
                    row(ui, "SONAME", soname);
                }
                if !elf.libraries.is_empty() {
                    row(ui, "Needed libraries", &elf.libraries.join(", "));
                }
            }
            BinaryInfo::Pe(pe) => {
                row(ui, "PE class", if pe.is_64 { "PE32+" } else { "PE32" });
                row(ui, "DLL", if pe.is_dll { "yes" } else { "no" });
                row(ui, "Machine", &format!("{:#x}", pe.machine));
                row(ui, "Subsystem", &pe.subsystem.to_string());
                row(
                    ui,
                    "Section alignment",
                    &format!("{:#x}", pe.section_alignment),
                );
                row(ui, "File alignment", &format!("{:#x}", pe.file_alignment));
                row(ui, "Size of image", &format!("{:#x}", pe.size_of_image));
                row(ui, "Size of headers", &format!("{:#x}", pe.size_of_headers));
                row(ui, "Checksum", &format!("{:#x}", pe.checksum));
                row(
                    ui,
                    "DLL characteristics",
                    &format!("{:#x}", pe.dll_characteristics),
                );
                row(ui, "Entry RVA", &format!("{:#x}", pe.entry_point_rva));
                if !pe.import_libraries.is_empty() {
                    row(ui, "Import libraries", &pe.import_libraries.join(", "));
                }
                let non_empty: Vec<String> = pe
                    .data_directories
                    .iter()
                    .filter(|d| d.virtual_address != 0 || d.size != 0)
                    .map(|d| format!("{}@{:#x}+{:#x}", d.name, d.virtual_address, d.size))
                    .collect();
                if !non_empty.is_empty() {
                    row(ui, "Data directories", &non_empty.join(", "));
                }
            }
            BinaryInfo::MachO(macho) => {
                row(
                    ui,
                    "Mach-O class",
                    if macho.is_64 { "64-bit" } else { "32-bit" },
                );
                row(ui, "CPU type", &format!("{:#x}", macho.cputype));
                row(ui, "CPU subtype", &format!("{:#x}", macho.cpusubtype));
                row(ui, "File type", &macho.filetype.to_string());
                row(ui, "Flags", &format!("{:#x}", macho.flags));
                row(
                    ui,
                    "Endianness",
                    match macho.endianness {
                        Endianness::LittleEndian => "little-endian",
                        Endianness::BigEndian => "big-endian",
                    },
                );
                if let Some(uuid) = &macho.uuid {
                    let text: Vec<String> = uuid.iter().map(|b| format!("{b:02x}")).collect();
                    row(ui, "UUID", &text.join(""));
                }
                if let Some(entry) = macho.entry_file_offset {
                    row(ui, "LC_MAIN entry offset", &format!("{entry:#x}"));
                }
                row(
                    ui,
                    "Fat container",
                    if macho.is_fat() { "yes" } else { "no" },
                );
                if !macho.fat_archs.is_empty() {
                    let archs: Vec<String> = macho
                        .fat_archs
                        .iter()
                        .map(|a| format!("{:#x}@{:#x}", a.cputype, a.offset))
                        .collect();
                    row(ui, "Fat architectures", &archs.join(", "));
                }
                let dylibs: Vec<String> = macho
                    .dylibs
                    .iter()
                    .map(|d| {
                        if d.is_self {
                            format!("{} (self)", d.name)
                        } else {
                            d.name.clone()
                        }
                    })
                    .collect();
                if !dylibs.is_empty() {
                    row(ui, "Dylibs", &dylibs.join(", "));
                }
            }
        });
}

#[derive(Clone)]
struct CfgLayout {
    positions: HashMap<u64, Pos2>,
    heights: HashMap<u64, f32>,
    block_width: f32,
    canvas_size: Vec2,
    scale: f32,
    offset: Vec2,
}

impl CfgLayout {
    fn new(blocks: &[&BasicBlock], edges: &HashMap<u64, Vec<rustida_loader::CFGEdge>>, binary: &Binary) -> Self {
        let mut positions = HashMap::new();
        let mut heights = HashMap::new();
        let block_width = 240.0;
        
        let mut in_degree: HashMap<u64, usize> = HashMap::new();
        let known: std::collections::HashSet<u64> = blocks.iter().map(|b| b.address.0).collect();
        
        for block in blocks {
            in_degree.entry(block.address.0).or_insert(0);
            // Calculate height: padding + header + instructions * line_height + footer
            let insn_count = block.instructions.len().min(30); // show up to 30 lines
            let height = 24.0 + insn_count as f32 * 14.0 + 16.0;
            heights.insert(block.address.0, height);

            if let Some(block_edges) = edges.get(&block.address.0) {
                for edge in block_edges {
                    if let Some(target) = edge.target {
                        if known.contains(&target.0) {
                            *in_degree.entry(target.0).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        
        let mut queue: VecDeque<u64> = in_degree.iter()
            .filter(|&(_, deg)| *deg == 0)
            .map(|(&addr, _)| addr)
            .collect();
        
        let mut levels: HashMap<u64, usize> = HashMap::new();
        let mut current_level = 0;
        
        while !queue.is_empty() {
            let mut next_queue = VecDeque::new();
            for addr in queue.drain(..) {
                levels.insert(addr, current_level);
                if let Some(block_edges) = edges.get(&addr) {
                    for edge in block_edges {
                        if let Some(target) = edge.target {
                            if known.contains(&target.0) {
                                let deg = in_degree.entry(target.0).or_insert(0);
                                *deg = deg.saturating_sub(1);
                                if *deg == 0 {
                                    next_queue.push_back(target.0);
                                }
                            }
                        }
                    }
                }
            }
            current_level += 1;
            queue = next_queue;
        }
        
        for block in blocks {
            if !levels.contains_key(&block.address.0) {
                levels.insert(block.address.0, current_level);
                current_level += 1;
            }
        }
        
        let mut level_counts: HashMap<usize, usize> = HashMap::new();
        let mut sorted_blocks: Vec<_> = blocks.iter().collect();
        sorted_blocks.sort_by_key(|b| (levels[&b.address.0], b.address.0));
        
        let mut column_y: HashMap<usize, f32> = HashMap::new();
        
        for block in sorted_blocks {
            let level = levels[&block.address.0];
            let y_start = column_y.entry(level).or_insert(50.0);
            
            let x = 50.0 + level as f32 * 320.0;
            let y = *y_start;
            positions.insert(block.address.0, Pos2::new(x, y));
            
            *y_start += heights[&block.address.0] + 40.0;
        }
        
        let max_x = positions.iter().map(|(&addr, p)| p.x + block_width).fold(50.0, f32::max) + 50.0;
        let max_y: f32 = column_y.values().fold(50.0f32, |a, &b| a.max(b)) + 50.0;
        
        Self {
            positions,
            heights,
            block_width,
            canvas_size: Vec2::new(max_x.max(1200.0), max_y.max(800.0)),
            scale: 1.0,
            offset: Vec2::ZERO,
        }
    }
    
    fn world_to_screen(&self, pos: Pos2) -> Pos2 {
        Pos2::new(
            (pos.x - self.offset.x) * self.scale,
            (pos.y - self.offset.y) * self.scale,
        )
    }
    
    fn screen_to_world(&self, pos: Pos2) -> Pos2 {
        Pos2::new(
            pos.x / self.scale + self.offset.x,
            pos.y / self.scale + self.offset.y,
        )
    }
    
    fn draw_with_painter(&self, painter: &egui::Painter, blocks: &[&BasicBlock], edges: &HashMap<u64, Vec<rustida_loader::CFGEdge>>, binary: &Binary, selected: Option<u64>) {
        let canvas_rect = painter.clip_rect();
        
        // Background
        painter.rect_filled(canvas_rect, 0.0, Color32::from_rgb(22, 22, 27));
        
        // Grid lines
        let grid_size = 40.0 * self.scale;
        let grid_color = Color32::from_rgb(32, 32, 40);
        let start_x = (canvas_rect.min.x - self.offset.x * self.scale).rem_euclid(grid_size);
        let start_y = (canvas_rect.min.y - self.offset.y * self.scale).rem_euclid(grid_size);
        
        let mut x = canvas_rect.min.x + start_x;
        while x < canvas_rect.max.x {
            painter.line_segment([
                Pos2::new(x, canvas_rect.min.y),
                Pos2::new(x, canvas_rect.max.y),
            ], Stroke::new(1.0, grid_color));
            x += grid_size;
        }
        
        let mut y = canvas_rect.min.y + start_y;
        while y < canvas_rect.max.y {
            painter.line_segment([
                Pos2::new(canvas_rect.min.x, y),
                Pos2::new(canvas_rect.max.x, y),
            ], Stroke::new(1.0, grid_color));
            y += grid_size;
        }
        
        // Draw edges
        for block in blocks {
            let Some(&pos) = self.positions.get(&block.address.0) else { continue };
            let Some(block_edges) = edges.get(&block.address.0) else { continue };
            let height = self.heights[&block.address.0];
            
            let rect = Rect::from_min_size(canvas_rect.min + self.world_to_screen(pos).to_vec2(), Vec2::new(self.block_width, height) * self.scale);
            let start = rect.right_center();
            
            for edge in block_edges {
                let color = edge_color(edge.edge_type);
                let stroke = Stroke::new(2.0 * self.scale, color);
                
                if let Some(target) = edge.target {
                    if let Some(&target_pos) = self.positions.get(&target.0) {
                        let target_height = self.heights[&target.0];
                        let target_rect = Rect::from_min_size(canvas_rect.min + self.world_to_screen(target_pos).to_vec2(), Vec2::new(self.block_width, target_height) * self.scale);
                        let end = target_rect.left_center();
                        
                        let mid_x = (start.x + end.x) * 0.5;
                        let ctrl1 = Pos2::new(mid_x, start.y);
                        let ctrl2 = Pos2::new(mid_x, end.y);
                        
                        let mut points = vec![start];
                        for t in 1..=20 {
                            let t = t as f32 / 20.0;
                            let inv = 1.0 - t;
                            let px = inv*inv*inv*start.x + 3.0*inv*inv*t*ctrl1.x + 3.0*inv*t*t*ctrl2.x + t*t*t*end.x;
                            let py = inv*inv*inv*start.y + 3.0*inv*inv*t*ctrl1.y + 3.0*inv*t*t*ctrl2.y + t*t*t*end.y;
                            points.push(Pos2::new(px, py));
                        }
                        let last_point = points[points.len() - 2];
                        painter.add(egui::Shape::line(points, stroke));
                        draw_arrow_head(painter, last_point, end, color, self.scale);
                    }
                } else {
                    let end = Pos2::new(start.x + 60.0 * self.scale, start.y);
                    let ctrl1 = Pos2::new(start.x + 20.0 * self.scale, start.y - 40.0 * self.scale);
                    let ctrl2 = Pos2::new(end.x - 20.0 * self.scale, end.y - 40.0 * self.scale);
                    
                    let mut points = vec![start];
                    for t in 1..=20 {
                        let t = t as f32 / 20.0;
                        let inv = 1.0 - t;
                        let px = inv*inv*inv*start.x + 3.0*inv*inv*t*ctrl1.x + 3.0*inv*t*t*ctrl2.x + t*t*t*end.x;
                        let py = inv*inv*inv*start.y + 3.0*inv*inv*t*ctrl1.y + 3.0*inv*t*t*ctrl2.y + t*t*t*end.y;
                        points.push(Pos2::new(px, py));
                    }
                    let last_point = points[points.len() - 2];
                    painter.add(egui::Shape::line(points, stroke));
                    draw_arrow_head(painter, last_point, end, color, self.scale);
                    painter.text(
                        end + Vec2::new(4.0 * self.scale, -6.0 * self.scale),
                        Align2::LEFT_TOP,
                        "ret",
                        FontId::monospace(9.0 * self.scale),
                        color,
                    );
                }
            }
        }
        
        // Draw nodes
        for block in blocks {
            let Some(&pos) = self.positions.get(&block.address.0) else { continue };
            let height = self.heights[&block.address.0];
            let screen_pos = canvas_rect.min + self.world_to_screen(pos).to_vec2();
            let screen_size = Vec2::new(self.block_width, height) * self.scale;
            let rect = Rect::from_min_size(screen_pos, screen_size);
            
            let is_selected = selected == Some(block.address.0);
            let bg_color = if is_selected {
                Color32::from_rgb(60, 80, 120)
            } else {
                Color32::from_rgb(42, 44, 54)
            };
            let border_color = if is_selected {
                Color32::from_rgb(100, 180, 255)
            } else {
                Color32::from_rgb(90, 96, 116)
            };
            let border_width = if is_selected { 2.5 * self.scale } else { 1.0 * self.scale };
            
            painter.rect_filled(rect, 6.0 * self.scale, bg_color);
            painter.rect_stroke(rect, 6.0 * self.scale, Stroke::new(border_width, border_color), egui::StrokeKind::Inside);
            
            let name = binary.name_at(block.address).map(|n| format!("{n}\n")).unwrap_or_default();
            painter.text(
                rect.left_top() + Vec2::new(8.0 * self.scale, 4.0 * self.scale),
                Align2::LEFT_TOP,
                format!("{name}{:016x}", block.address.0),
                FontId::monospace(11.0 * self.scale),
                Color32::from_rgb(100, 200, 255),
            );

            // Instructions
            let mut y_offset = 24.0 * self.scale;
            for &insn_idx in block.instructions.iter().take(30) {
                if let Some(insn) = binary.instructions.get(insn_idx) {
                    painter.text(
                        rect.left_top() + Vec2::new(8.0 * self.scale, y_offset),
                        Align2::LEFT_TOP,
                        insn.text(),
                        FontId::monospace(10.0 * self.scale),
                        Color32::from_rgb(200, 200, 210),
                    );
                    y_offset += 14.0 * self.scale;
                }
            }
            
            painter.text(
                rect.left_bottom() + Vec2::new(8.0 * self.scale, -6.0 * self.scale),
                Align2::LEFT_BOTTOM,
                format!("{} insn · {}", block.instructions.len(), terminator_label(&block.terminator)),
                FontId::monospace(9.0 * self.scale),
                Color32::from_rgb(165, 172, 190),
            );
        }
    }
}

fn draw_arrow_head(painter: &egui::Painter, from: Pos2, to: Pos2, color: Color32, scale: f32) {
    let dir = to - from;
    let len = dir.length();
    if len < 1.0 { return; }
    let unit = dir / len;
    let normal = Vec2::new(-unit.y, unit.x);
    let tip = to;
    let base = tip - unit * (10.0 * scale);
    painter.line_segment([tip, base + normal * (5.0 * scale)], Stroke::new(2.0 * scale, color));
    painter.line_segment([tip, base - normal * (5.0 * scale)], Stroke::new(2.0 * scale, color));
}

fn edge_color(edge_type: rustida_loader::CFGEdgeType) -> Color32 {
    match edge_type {
        rustida_loader::CFGEdgeType::Fallthrough => Color32::from_rgb(120, 220, 140),
        rustida_loader::CFGEdgeType::Conditional => Color32::from_rgb(100, 160, 255),
        rustida_loader::CFGEdgeType::Unconditional => Color32::from_rgb(90, 220, 230),
        rustida_loader::CFGEdgeType::Return => Color32::from_rgb(255, 120, 120),
        rustida_loader::CFGEdgeType::Indirect => Color32::from_rgb(170, 170, 180),
    }
}

fn terminator_label(terminator: &BlockTerminator) -> &'static str {
    match terminator {
        BlockTerminator::Fallthrough => "fallthrough",
        BlockTerminator::UnconditionalJump(_) => "jump",
        BlockTerminator::ConditionalBranch { .. } => "branch",
        BlockTerminator::Call(_) => "call",
        BlockTerminator::IndirectCall => "indirect call",
        BlockTerminator::Return => "return",
        BlockTerminator::IndirectJump(_) => "indirect jump",
        BlockTerminator::Interrupt => "interrupt",
        BlockTerminator::Invalid => "invalid",
    }
}

fn cfg_edges_by_source(
    analysis: &rustida_loader::DisassemblyAnalysis,
) -> HashMap<u64, Vec<rustida_loader::CFGEdge>> {
    let mut map: HashMap<u64, Vec<rustida_loader::CFGEdge>> = HashMap::new();
    for node in &analysis.cfg_nodes {
        map.insert(node.address.0, node.edges.clone());
    }
    map
}

fn show_control_flow_graph(ui: &mut egui::Ui, blocks: &[&BasicBlock], edges: &HashMap<u64, Vec<rustida_loader::CFGEdge>>, binary: &Binary, selected_address: Option<u64>) {
    // Fill the remaining area of the panel
    let rect = ui.available_rect_before_wrap();
    let id = ui.make_persistent_id("cfg_state");
    let mut state = ui.data_mut(|d| d.get_temp::<(Vec2, f32)>(id).unwrap_or((Vec2::ZERO, 1.0)));

    let response = ui.allocate_rect(rect, Sense::click_and_drag());
    
    // Pan: Left or Middle click-drag
    if response.dragged_by(egui::PointerButton::Middle) || response.dragged_by(egui::PointerButton::Primary) {
        state.0 += response.drag_delta();
    }
    
    // Zoom: Scroll
    let zoom_delta = ui.input(|i| i.smooth_scroll_delta.y);
    if zoom_delta != 0.0 && response.hovered() {
        state.1 = (state.1 * (1.0 + zoom_delta * 0.005)).clamp(0.2, 3.0);
    }
    
    ui.data_mut(|d| d.insert_temp(id, state));

    let mut layout = CfgLayout::new(blocks, edges, binary);
    layout.offset = -state.0 / state.1;
    layout.scale = state.1;
    
    // Use the painter on the full rectangle
    let painter = ui.painter_at(rect);
    layout.draw_with_painter(&painter, blocks, edges, binary, selected_address);
}

fn instruction_color(instruction: &DisassembledInstruction) -> Color32 {
    if !instruction.valid {
        return Color32::from_rgb(180, 120, 120);
    }
    match instruction.flow {
        rustida_loader::InstructionFlow::Call => Color32::from_rgb(130, 220, 150),
        rustida_loader::InstructionFlow::IndirectCall => Color32::from_rgb(170, 220, 180),
        rustida_loader::InstructionFlow::Jump => Color32::from_rgb(110, 210, 220),
        rustida_loader::InstructionFlow::IndirectJump => Color32::from_rgb(160, 210, 215),
        rustida_loader::InstructionFlow::ConditionalJump => Color32::from_rgb(120, 170, 255),
        rustida_loader::InstructionFlow::Return => Color32::from_rgb(255, 140, 140),
        rustida_loader::InstructionFlow::Interrupt => Color32::from_rgb(230, 190, 120),
        rustida_loader::InstructionFlow::Exception => Color32::from_rgb(220, 120, 120),
        rustida_loader::InstructionFlow::Next => Color32::from_rgb(215, 218, 228),
    }
}

fn instruction_hint(binary: &Binary, instruction: &DisassembledInstruction) -> String {
    let mut hint = format!(
        "{} bytes at {}\nflow: {:?}\nvalid: {}",
        instruction.length, instruction.address, instruction.flow, instruction.valid
    );
    if let Some(target) = instruction.target {
        hint.push_str(&format!("\ntarget: {target}"));
        if let Some(name) = binary.name_at(target) {
            hint.push_str(&format!(" ({name})"));
        }
    }
    hint
}

fn symbol_kind(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Function => "func",
        SymbolKind::Variable => "var",
        SymbolKind::Label => "label",
        SymbolKind::Import => "import",
        SymbolKind::Export => "export",
        SymbolKind::Tls => "tls",
    }
}

fn permissions_text(permissions: rustida_core::Permissions) -> String {
    format!(
        "{}{}{}",
        if permissions.readable() { "R" } else { "-" },
        if permissions.writable() { "W" } else { "-" },
        if permissions.executable() { "X" } else { "-" },
    )
}

fn endianness_name(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::LittleEndian => "little-endian",
        Endianness::BigEndian => "big-endian",
    }
}

fn detected_name(kind: FormatKind) -> &'static str {
    match kind {
        FormatKind::Elf => "ELF",
        FormatKind::Pe => "PE",
        FormatKind::MachO => "Mach-O",
        FormatKind::FatMachO => "Fat Mach-O",
    }
}

fn format_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let mut result: String = text.chars().take(width.saturating_sub(1)).collect();
        result.push('…');
        result
    }
}


