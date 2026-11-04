use std::path::Path;

use easyvpn_core::{core, store};
use eframe::egui::*;

use crate::{app::App, platform::Platform, theme};

fn folder_row(ui: &mut Ui, label: &str, path: &Path, platform: &dyn Platform) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).font(theme::semibold_font(13.0_f32)));
        if !platform.is_mobile() {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if theme::secondary(ui, "Open", false).clicked() {
                    platform.open_folder(path);
                }
            });
        }
    });
    ui.add(
        Label::new(
            RichText::new(path.display().to_string())
                .monospace()
                .size(10.0_f32)
                .color(theme::MUTED),
        )
        .wrap()
        .selectable(true),
    );
}

pub fn show(app: &mut App, ui: &mut Ui) {
    ScrollArea::vertical().show(ui, |ui| {
        ui.add_space(12.0_f32);
        ui.vertical_centered(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(100.0_f32, 100.0_f32), Sense::hover());
            theme::halo(ui.painter(), rect.center(), 42.0_f32, theme::BLUE, 14);
            theme::disc(
                ui.painter(),
                rect.center(),
                42.0_f32,
                Color32::from_rgb(59, 130, 246),
                Color32::from_rgb(29, 78, 216),
            );
            theme::power_icon(ui.painter(), rect.center());
            ui.label(RichText::new("EasyVpn").font(theme::bold_font(28.0_f32)));
            ui.label(
                RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                    .size(12.0_f32)
                    .color(theme::MUTED),
            );
            ui.add_space(6.0_f32);
            ui.label(
                RichText::new(if app.platform.is_mobile() {
                    "Xray · sing-box · mihomo"
                } else {
                    "Xray · sing-box · mihomo · OpenVPN"
                })
                    .size(11.0_f32)
                    .color(theme::MUTED),
            );
        });
        ui.add_space(20.0_f32);
        theme::section(ui, "UPDATE");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            if !app.update_status.is_empty() {
                ui.label(RichText::new(app.update_status.as_str()).size(12.0_f32).color(theme::MUTED));
                ui.add_space(6.0_f32);
            }
            ui.add_enabled_ui(!app.update_busy, |ui| {
                if app.update.is_some() {
                    if theme::primary(ui, "Download and install").clicked() { app.download_update(ui.ctx()); }
                } else if theme::secondary(ui, "Check for updates", false).clicked() {
                    app.check_update(ui.ctx());
                }
            });
        });
        ui.add_space(20.0_f32);
        theme::section(ui, "APPLICATION");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            folder_row(ui, "Data folder", &store::data_dir(), app.platform.as_ref());
            theme::divider(ui);
            let cores = if app.platform.is_mobile() {
                std::env::var_os("EASYVPN_CORE_DIR")
                    .map(std::path::PathBuf::from).unwrap_or_else(core::cores_dir)
            } else {
                core::cores_dir()
            };
            folder_row(ui, "Cores folder", &cores, app.platform.as_ref());
            theme::divider(ui);
            ui.label(RichText::new("Licenses").font(theme::semibold_font(13.0_f32)));
            ui.label(RichText::new("EasyVpn uses open-source Rust libraries. Proxy cores are separate programs with their own licenses; consult each core's upstream distribution for license terms.").size(11.0_f32).color(theme::MUTED));
        });
        ui.add_space(12.0_f32);
        ui.label(
            RichText::new("Your configurations. Your connection.")
                .size(12.0_f32)
                .color(theme::MUTED),
        );
    });
}
