pub mod app;
pub mod flags;
pub mod pages;
pub mod platform;
pub mod text;
pub mod theme;
pub mod window;

pub use platform::{Platform, VpnStatus};

/// Shared desktop and Android UI entry point.
pub fn run_app(
    options: eframe::NativeOptions,
    platform: Box<dyn Platform>,
) -> eframe::Result<()> {
    eframe::run_native(
        "EasyVpn",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, platform)))),
    )
}
