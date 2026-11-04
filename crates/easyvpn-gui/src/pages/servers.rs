use easyvpn_core::Protocol;
use eframe::egui::*;

use crate::{
    app::{address, protocol_name, App, Page},
    pages::profile_editor::EditorState,
    text::display_name,
    theme::{self, Icon},
};

fn badge(protocol: Option<Protocol>) -> (&'static str, Color32) {
    match protocol {
        Some(Protocol::Vless) => ("VL", theme::BLUE),
        Some(Protocol::Vmess) => ("VM", theme::CYAN),
        Some(Protocol::Trojan) => ("TR", Color32::from_rgb(251, 146, 60)),
        Some(Protocol::Shadowsocks) => ("SS", theme::GREEN),
        Some(Protocol::Hysteria | Protocol::Hysteria2) => ("HY", theme::CYAN),
        Some(Protocol::Tuic) => ("TU", Color32::from_rgb(167, 139, 250)),
        Some(Protocol::Wireguard) => ("WG", theme::GREEN),
        Some(Protocol::OpenVpn) => ("OV", Color32::from_rgb(251, 146, 60)),
        Some(Protocol::Ssh) => ("SH", theme::AMBER),
        Some(Protocol::AnyTls) => ("AT", theme::CYAN),
        Some(Protocol::Custom) => ("CU", theme::MUTED),
        Some(Protocol::Socks) => ("SO", theme::BLUE),
        Some(Protocol::Http) => ("HT", theme::BLUE),
        None => ("?", theme::MUTED),
    }
}

pub fn show(app: &mut App, ui: &mut Ui, _ctx: &Context) {
    theme::input(ui, &mut app.search, "Search servers…");
    ui.horizontal_wrapped(|ui| {
        for (id, label) in [("all", "All"), ("manual", "Manual")] {
            if theme::chip(ui, label, app.server_filter == id).clicked() {
                app.server_filter = id.into();
            }
        }
        for sub in &app.store.subscriptions {
            let name = display_name(&sub.name);
            if theme::chip(ui, &name.text, app.server_filter == sub.id).clicked() {
                app.server_filter.clone_from(&sub.id);
            }
        }
    });
    let query = app.search.to_lowercase();
    let normalized_query: String = unicode_normalization::UnicodeNormalization::nfkc(query.as_str()).collect();
    let mut selected = None;
    let mut deleted = None;
    let mut copied = None;
    let mut edited = None;
    let mut visible = 0;
    for profile in &app.store.profiles {
        let matches_filter = match app.server_filter.as_str() {
            "all" => true,
            "manual" => profile.subscription_id.is_none(),
            id => profile.subscription_id.as_deref() == Some(id),
        };
        let searchable: String = unicode_normalization::UnicodeNormalization::nfkc(
            format!("{} {} {}", profile.name, profile.address, protocol_name(profile.protocol)).as_str()
        ).collect();
        if !matches_filter || !searchable.to_lowercase().contains(&normalized_query) { continue; }
        visible += 1;
        ui.push_id(&profile.id, |ui| {
            let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 64.0_f32), Sense::click());
            let active = app.store.selected.as_deref() == Some(profile.id.as_str());
            let painter = ui.painter();
            painter.rect(rect, 18.0_f32,
                if active { Color32::from_rgb(19, 34, 58) } else { theme::CARD },
                Stroke::new(1.0_f32, if active { theme::BLUE } else { theme::BORDER }));
            let (initials, color) = badge(profile.protocol);
            let tile = pos2(rect.left() + 28.0_f32, rect.center().y);
            painter.circle_filled(tile, 20.0_f32, color.gamma_multiply(0.16_f32));
            theme::bold_text(painter, tile, Align2::CENTER_CENTER, initials, 13.0_f32, color);
            if active {
                painter.rect_filled(
                    Rect::from_min_size(rect.min + vec2(0.0_f32, 18.0_f32), vec2(3.0_f32, 28.0_f32)),
                    2.0_f32, theme::BLUE);
                painter.circle_filled(tile + vec2(13.0_f32, 13.0_f32), 7.0_f32, Color32::from_rgb(29, 78, 216));
                theme::icon(painter, tile + vec2(13.0_f32, 13.0_f32), Icon::Check, 10.0_f32, Color32::WHITE);
            }
            let left = rect.left() + 59.0_f32;
            let right = rect.right() - 106.0_f32;
            let name = display_name(if profile.name.is_empty() { "(unnamed)" } else { &profile.name });
            let flag_drawn = name.country().is_some_and(|code| {
                app.flags.draw(ui,
                    Rect::from_center_size(pos2(left + 11.0_f32, rect.top() + 21.0_f32), vec2(22.0_f32, 16.0_f32)),
                    code)
            });
            let name_left = left + if flag_drawn { 28.0_f32 } else { 0.0_f32 };
            theme::elided_with_font(painter,
                Rect::from_min_max(pos2(name_left, rect.top() + 10.0_f32), pos2(right, rect.top() + 31.0_f32)),
                &name.text, theme::semibold_font(13.0_f32), theme::TEXT);
            let description = format!("{} · {}", protocol_name(profile.protocol), address(profile));
            theme::elided(painter,
                Rect::from_min_max(pos2(left, rect.top() + 33.0_f32), pos2(right, rect.bottom() - 9.0_f32)),
                &description, 10.0_f32, theme::MUTED);
            let pill = Rect::from_center_size(pos2(rect.right() - 69.0_f32, rect.center().y), vec2(64.0_f32, 24.0_f32));
            theme::latency(painter, pill, app.pings.get(&profile.id).copied());
            let menu_rect = Rect::from_center_size(pos2(rect.right() - 20.0_f32, rect.center().y), vec2(30.0_f32, 36.0_f32));
            let menu = ui.interact(menu_rect, ui.id().with("more"), Sense::click());
            theme::icon(ui.painter(), menu_rect.center(), Icon::More, 20.0_f32, theme::MUTED);
            let shareable = !matches!(profile.protocol, Some(Protocol::Custom | Protocol::OpenVpn));
            theme::dropdown(ui, ui.make_persistent_id("actions"), &menu, |ui| {
                if theme::menu_row(ui, Icon::Text, "Edit", false).clicked() {
                    edited = Some(profile.clone());
                    ui.close_menu();
                }
                ui.add_enabled_ui(shareable, |ui| {
                    if theme::menu_row(ui, Icon::Copy, "Copy link", false).clicked() {
                        copied = Some(profile.clone());
                        ui.close_menu();
                    }
                });
                if theme::menu_row(ui, Icon::Trash, "Delete", true).clicked() {
                    deleted = Some(profile.id.clone());
                    ui.close_menu();
                }
            });
            if response.clicked() && !menu.hovered() { selected = Some(profile.id.clone()); }
            response.on_hover_text(format!("{}\n{description}", name.text)).context_menu(|ui| {
                if theme::menu_row(ui, Icon::Text, "Edit", false).clicked() {
                    edited = Some(profile.clone());
                    ui.close_menu();
                }
                ui.add_enabled_ui(shareable, |ui| {
                    if theme::menu_row(ui, Icon::Copy, "Copy link", false).clicked() {
                        copied = Some(profile.clone());
                        ui.close_menu();
                    }
                });
                if theme::menu_row(ui, Icon::Trash, "Delete", true).clicked() {
                    deleted = Some(profile.id.clone());
                    ui.close_menu();
                }
            });
        });
    }
    if visible == 0 {
        theme::empty(ui, Icon::Server, if app.store.profiles.is_empty() { "No servers yet" } else { "No matching servers" });
        if theme::primary(ui, "Add config").clicked() {
            app.editor = Some(EditorState::new(None));
            app.page = Page::Editor;
        }
    }
    if let Some(profile) = copied { app.copy_profile(&profile); }
    if let Some(id) = deleted { app.delete_profile(&id); }
    if let Some(id) = selected { app.select_profile(id); }
    if let Some(profile) = edited {
        app.editor = Some(EditorState::new(Some(&profile)));
        app.page = Page::Editor;
    }
}
