#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(target_os = "android"))]
fn main() -> eframe::Result<()> {
    use easyvpn_gui::{platform::DesktopPlatform, window::WindowState};
    use eframe::egui;

    let state = WindowState::load();
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size(state.startup_size())
        .with_min_inner_size([300.0_f32, 190.0_f32])
        .with_resizable(true)
        .with_decorations(false)
        .with_transparent(true);
    if let Some(position) = state.startup_position() {
        viewport = viewport.with_position(position);
    }
    if state.mini {
        viewport = viewport.with_always_on_top();
    }
    easyvpn_gui::run_app(
        eframe::NativeOptions {
            viewport,
            centered: state.startup_position().is_none(),
            ..Default::default()
        },
        Box::new(DesktopPlatform),
    )
}

#[cfg(target_os = "android")]
fn main() {}
