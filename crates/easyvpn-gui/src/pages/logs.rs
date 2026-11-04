use eframe::egui::{self, *};

use crate::{
    app::App,
    theme::{self, Icon},
};

fn level(line: &str) -> (&'static str, Color32) {
    let lower = line.to_lowercase();
    if lower.contains("error") || lower.contains("fatal") {
        ("Error", theme::RED)
    } else if lower.contains("warn") {
        ("Warn", theme::AMBER)
    } else {
        ("Info", theme::BLUE)
    }
}

fn colored_line(line: &str) -> egui::text::LayoutJob {
    let (_, color) = level(line);
    let mut job = egui::text::LayoutJob::default();
    let mut start = 0;
    for (index, ch) in line.char_indices() {
        if ch.is_ascii_whitespace() || ch.is_ascii_punctuation() {
            if start < index { append_word(&mut job, &line[start..index], color); }
            let end = index + ch.len_utf8();
            job.append(&line[index..end], 0.0_f32,
                egui::text::TextFormat::simple(FontId::monospace(11.0_f32), theme::MUTED));
            start = end;
        }
    }
    if start < line.len() { append_word(&mut job, &line[start..], color); }
    job
}

fn append_word(job: &mut egui::text::LayoutJob, word: &str, color: Color32) {
    let is_level = matches!(word.to_ascii_lowercase().as_str(), "info" | "warn" | "warning" | "error" | "fatal" | "debug");
    job.append(word, 0.0_f32, egui::text::TextFormat::simple(
        FontId::monospace(11.0_f32), if is_level { color } else { theme::TEXT }));
}

pub fn show(app: &mut App, ui: &mut Ui) {
    ui.horizontal_wrapped(|ui| {
        for filter in ["All", "Info", "Warn", "Error"] {
            if theme::chip(ui, filter, app.log_filter == filter).clicked() {
                app.log_filter = filter.into();
            }
        }
    });
    ui.horizontal_wrapped(|ui| {
        if theme::secondary(ui, "Copy", false).clicked() { app.copy_text(app.logs.join("\n")); }
        if theme::secondary(ui, "Clear", true).clicked() { app.logs.clear(); }
    });
    // The surrounding page scroll has an unbounded content height. Derive the
    // inner log viewport from the actual window instead.
    let panel_height = (ui.ctx().screen_rect().height() - 320.0_f32).clamp(100.0_f32, 700.0_f32);
    Frame::none().fill(Color32::from_rgb(7, 11, 20))
        .rounding(18.0_f32).stroke(Stroke::new(1.0_f32, theme::BORDER))
        .inner_margin(14.0_f32).show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            ScrollArea::vertical().id_salt("core-log-lines").auto_shrink([false, false])
                .max_height(panel_height).stick_to_bottom(app.log_autoscroll).show(ui, |ui| {
                    ui.set_min_height(panel_height);
                    if app.logs.is_empty() { theme::empty(ui, Icon::Terminal, "No core logs yet"); }
                    for line in &app.logs {
                        if app.log_filter != "All" && level(line).0 != app.log_filter { continue; }
                        ui.add(Label::new(colored_line(line)).selectable(true).wrap());
                    }
                });
        });
    theme::settings_row(ui, "Auto-scroll", None, |ui| {
        theme::toggle(ui, &mut app.log_autoscroll);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_and_unicode_lines() {
        assert_eq!(level("[WARNING] retry").0, "Warn");
        assert_eq!(level("fatal: stopped").0, "Error");
        assert_eq!(level("INFO connected").0, "Info");
        assert_eq!(colored_line("INFO اتصال برقرار شد").text, "INFO اتصال برقرار شد");
    }
}
