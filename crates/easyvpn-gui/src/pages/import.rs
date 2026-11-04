use eframe::egui::*;

use crate::{app::{App, Page}, theme};

pub fn show(app: &mut App, ui: &mut Ui) {
    ui.label(RichText::new("Bring your own configuration").font(theme::semibold_font(16.0_f32)));
    ui.add(Label::new(RichText::new(
        "Share links · subscription URLs and bodies · OpenVPN · WireGuard · Xray JSON · sing-box JSON · mihomo YAML")
        .size(11.0_f32).color(theme::MUTED)).wrap());
    let height = (ui.ctx().screen_rect().height() - 300.0_f32).clamp(140.0_f32, 600.0_f32);
    theme::text_area(ui, &mut app.import_text, height);
    ui.add_space(8.0_f32);
    ui.add_enabled_ui(!app.import_text.trim().is_empty(), |ui| {
        if theme::primary(ui, "Import").clicked() {
            let text = app.import_text.clone();
            if app.smart_import(&text) {
                app.import_text.clear();
                app.page = Page::Home;
            }
        }
    });
}
