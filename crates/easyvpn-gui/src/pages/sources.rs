use std::time::{SystemTime, UNIX_EPOCH};

use easyvpn_core::{rules::{self, SourceFormat}, store};
use eframe::egui::*;

use crate::{app::App, text::display_name, theme};

fn relative_time(timestamp: u64) -> String {
    if timestamp == 0 {
        return "Not downloaded".into();
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(timestamp);
    let seconds = now.saturating_sub(timestamp);
    if seconds < 60 {
        "Updated just now".into()
    } else if seconds < 3600 {
        format!("Updated {}m ago", seconds / 60)
    } else if seconds < 86400 {
        format!("Updated {}h ago", seconds / 3600)
    } else {
        format!("Updated {}d ago", seconds / 86400)
    }
}

fn format_picker(ui: &mut Ui, format: &mut SourceFormat) -> bool {
    let previous = *format;
    ui.horizontal_wrapped(|ui| {
        for (value, name) in [
            (SourceFormat::Domains, "Domains"),
            (SourceFormat::Cidrs, "IP ranges"),
        ] {
            if theme::chip(ui, name, *format == value).clicked() {
                *format = value;
            }
        }
    });
    previous != *format
}

pub fn show(app: &mut App, ui: &mut Ui, ctx: &Context) {
    let previous = app.store.settings.bypass.clone();
    let mut detect = false;
    let mut update_all = false;
    let mut update = Vec::new();
    let mut delete = None;
    let mut reset = false;

    theme::card_frame().show(ui, |ui| {
        theme::settings_row(ui, "Bypass my country", Some("Country sources route directly, after your custom rules"), |ui| {
            theme::toggle(ui, &mut app.store.settings.bypass.enabled);
        });
        theme::divider(ui);
        ui.horizontal_wrapped(|ui| {
            let country = &app.store.settings.bypass.country;
            if country.is_empty() {
                ui.label(RichText::new("Country not detected").color(theme::MUTED));
            } else {
                let (rect, _) = ui.allocate_exact_size(vec2(28.0_f32, 20.0_f32), Sense::hover());
                app.flags.draw(ui, rect, country);
                ui.label(RichText::new(country.to_ascii_uppercase()).font(theme::semibold_font(13.0_f32)));
            }
            ui.add_enabled_ui(!app.detecting_country, |ui| {
                if theme::secondary(ui, if app.detecting_country { "Detecting…" } else { "Detect again" }, false).clicked() {
                    detect = true;
                }
            });
        });
        theme::divider(ui);
        let label = if app.store.settings.bypass.country.is_empty() {
            "Country TLD domains".to_owned()
        } else {
            format!(".{} domains", app.store.settings.bypass.country)
        };
        theme::settings_row(ui, &label, Some("Also bypass domains ending in the country code"), |ui| {
            theme::toggle(ui, &mut app.store.settings.bypass.tld_suffix);
        });
    });

    theme::section(ui, "SOURCES");
    ui.horizontal_wrapped(|ui| {
        if theme::secondary(ui, "Update all", false).clicked() {
            update_all = true;
        }
        ui.add_enabled_ui(!app.store.settings.bypass.country.is_empty(), |ui| {
            if theme::secondary(ui, "Reset to recommended", false).clicked() {
                reset = true;
            }
        });
    });
    if app.store.settings.bypass.sources.is_empty() {
        theme::empty(ui, theme::Icon::Link, "No bypass sources yet");
    }
    for source in &mut app.store.settings.bypass.sources {
        ui.push_id(&source.id, |ui| {
            let busy = app.updating_sources.contains(&source.id);
            theme::card_frame().show(ui, |ui| {
                let name = display_name(&source.name);
                ui.add(Label::new(RichText::new(&name.text).font(theme::semibold_font(14.0_f32)))
                    .truncate()).on_hover_text(&name.text);
                ui.label(RichText::new(format!("{} entries · {}", source.entries, relative_time(source.updated_at)))
                    .size(11.0_f32).color(theme::MUTED));
                ui.horizontal_wrapped(|ui| {
                    theme::toggle(ui, &mut source.enabled);
                    ui.add_enabled_ui(!busy, |ui| {
                        if theme::secondary(ui, if busy { "Updating…" } else { "Update" }, false).clicked() {
                            update.push(source.id.clone());
                        }
                    });
                    if !source.builtin && theme::secondary(ui, "Delete", true).clicked() {
                        delete = Some(source.id.clone());
                    }
                });
                if busy {
                    ui.label(RichText::new("Downloading directly…").size(11.0_f32).color(theme::BLUE));
                }
                ui.add_enabled_ui(!busy, |ui| {
                    ui.label(RichText::new("Name").size(11.0_f32).color(theme::MUTED));
                    theme::input(ui, &mut source.name, "Source name");
                    ui.label(RichText::new("URL").size(11.0_f32).color(theme::MUTED));
                    let old_url = source.url.clone();
                    theme::input(ui, &mut source.url, "https://example.org/domains.txt");
                    let format_changed = format_picker(ui, &mut source.format);
                    if old_url != source.url || format_changed {
                        source.updated_at = 0;
                        source.entries = 0;
                    }
                });
            });
        });
    }

    theme::section(ui, "ADD CUSTOM SOURCE");
    let mut add = false;
    theme::card_frame().show(ui, |ui| {
        theme::input(ui, &mut app.source_draft.name, "Name");
        theme::input(ui, &mut app.source_draft.url, "https://example.org/domains.txt");
        format_picker(ui, &mut app.source_draft.format);
        let valid = !app.source_draft.name.trim().is_empty()
            && (app.source_draft.url.trim().starts_with("https://")
                || app.source_draft.url.trim().starts_with("http://"));
        ui.add_enabled_ui(valid, |ui| {
            add = theme::primary(ui, "Add source").clicked();
        });
    });
    if let Some(id) = delete {
        app.store.settings.bypass.sources.retain(|source| source.id != id);
    }
    if add {
        let mut source = app.source_draft.clone();
        source.id = store::new_id();
        source.name = source.name.trim().to_owned();
        source.url = source.url.trim().to_owned();
        source.builtin = false;
        app.store.settings.bypass.sources.push(source);
        app.source_draft = Default::default();
        app.status = "Source added".into();
    }
    if reset {
        app.store.settings.bypass.sources =
            rules::recommended_sources(&app.store.settings.bypass.country);
        update_all = true;
    }
    if previous != app.store.settings.bypass {
        app.save();
    }
    if detect {
        app.detect_bypass_country(ctx);
    } else {
        app.ensure_bypass_country(ctx);
    }
    if update_all {
        app.update_bypass_sources(None, ctx);
    } else {
        for id in update {
            app.update_bypass_sources(Some(id), ctx);
        }
    }
}
