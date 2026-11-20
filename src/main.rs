//! RustIDA desktop entry point.
//!
//! Launches the egui/eframe GUI from [`rustida_gui::app::RustidaApp`].

use std::path::PathBuf;

use eframe::egui;
use rustida_gui::app::RustidaApp;

fn initial_binary() -> Option<PathBuf> {
    // First non-flag command-line argument wins; `--binary <path>` is also
    // accepted. RUSTIDA_BINARY is useful for scripted/screenshot runs.
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--binary" {
            return args.next().map(PathBuf::from);
        }
        if !arg.starts_with('-') {
            return Some(PathBuf::from(arg));
        }
    }
    std::env::var("RUSTIDA_BINARY").ok().map(PathBuf::from)
}

fn main() -> eframe::Result<()> {
    let initial = initial_binary();
    let screenshot_mode = std::env::var_os("EFRAME_SCREENSHOT_TO").is_some();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("RustIDA")
            .with_inner_size([1400.0, 900.0])
            .with_min_inner_size([900.0, 600.0]),
        renderer: if screenshot_mode {
            eframe::Renderer::Glow
        } else {
            eframe::Renderer::default()
        },
        ..Default::default()
    };

    eframe::run_native(
        "RustIDA",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(RustidaApp::new(initial)))
        }),
    )
}
