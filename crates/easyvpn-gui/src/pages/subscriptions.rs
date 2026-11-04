use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use eframe::egui::*;
use crate::{app::{App, Page}, text::display_name, theme::{self, Icon}};

pub fn relative_time(updated_at: u64, now: u64) -> String {
    if updated_at == 0 { return "never updated".into(); }
    let seconds = now.saturating_sub(updated_at);
    if seconds < 60 { "updated just now".into() }
    else if seconds < 3600 { format!("updated {}m ago", seconds / 60) }
    else if seconds < 86400 { format!("updated {}h ago", seconds / 3600) }
    else { format!("updated {}d ago", seconds / 86400) }
}

fn subscription_host(value: &str) -> Option<String> {
    let parsed = url::Url::parse(value.trim()).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") { return None; }
    parsed.host_str().filter(|host| !host.is_empty()).map(str::to_owned)
}

pub fn add_form(app: &mut App, ui: &mut Ui) {
    ScrollArea::vertical().show(ui, |ui| {
        theme::section(ui, "SUBSCRIPTION");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            ui.label(RichText::new("Keep your servers up to date automatically.").size(12.0_f32).color(theme::MUTED));
            ui.add_space(8.0_f32);
            ui.label(RichText::new("Name (optional)").size(12.0_f32).color(theme::MUTED));
            theme::input(ui, &mut app.subscription_name, "My subscription");
            ui.label(RichText::new("URL").size(12.0_f32).color(theme::MUTED));
            theme::input(ui, &mut app.subscription_url, "https://…");
            if !app.subscription_url.trim().is_empty() && subscription_host(&app.subscription_url).is_none() {
                ui.add(Label::new(RichText::new("Enter a valid http:// or https:// URL with a host.")
                    .size(11.0_f32).color(theme::RED.gamma_multiply(0.75_f32))).wrap());
            }
        });
        ui.add_space(12.0_f32);
        let host = subscription_host(&app.subscription_url);
        let valid = host.is_some() && !app.updating_subscriptions;
        ui.add_enabled_ui(valid, |ui| {
            if theme::primary(ui, "Add & update").clicked() {
                if app.subscription_name.trim().is_empty() {
                    if let Some(host) = &host { app.subscription_name = host.clone(); }
                }
                app.subscription_url = app.subscription_url.trim().to_owned();
                let before = app.store.subscriptions.len();
                app.add_subscription();
                if let Some(sub) = app.store.subscriptions.get(before) {
                    app.update_subscriptions(Some(sub.id.clone()), ui.ctx());
                }
            }
        });
        if app.updating_subscriptions {
            ui.label(RichText::new("Wait for the current update to finish.").size(11.0_f32).color(theme::MUTED));
        }
    });
}

pub fn show(app: &mut App, ui: &mut Ui, ctx: &Context) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut update = None;
    let mut remove = None;
    let mut confirm = None;
    ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        if app.store.subscriptions.is_empty() {
            theme::empty(ui, Icon::Link, "No subscriptions yet");
            ui.label(RichText::new("Add a subscription URL to keep your server list fresh.").color(theme::MUTED).size(12.0_f32));
        }
        for sub in &app.store.subscriptions {
            ui.push_id(&sub.id, |ui| {
                theme::card_frame().show(ui, |ui| {
                    ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
                    let name = display_name(&sub.name);
                    ui.add(Label::new(RichText::new(&name.text).font(theme::semibold_font(15.0_f32))).truncate());
                    ui.add(Label::new(RichText::new(&sub.url).monospace().size(11.0_f32).color(theme::MUTED)).truncate()).on_hover_text(&sub.url);
                    let count = app.store.profiles.iter().filter(|p| p.subscription_id.as_deref() == Some(sub.id.as_str())).count();
                    ui.label(RichText::new(format!("{count} servers · {}", relative_time(sub.updated_at, now))).size(11.0_f32).color(theme::MUTED));
                    theme::divider(ui);
                    ui.horizontal(|ui| {
                        let busy = app.updating_ids.contains(&sub.id);
                        ui.add_enabled_ui(!app.updating_subscriptions || busy, |ui| {
                            if theme::busy_button(ui, Icon::Refresh, busy).on_hover_text("Update subscription").clicked() {
                                update = Some(sub.id.clone());
                            }
                        });
                        let armed = app.confirm_delete.as_ref().is_some_and(|(id, time)| id == &sub.id && time.elapsed() < Duration::from_secs(3));
                        if theme::round_button_tinted(ui, Icon::Trash, if armed { theme::RED } else { theme::MUTED })
                            .on_hover_text(if armed { "Click again to delete" } else { "Delete subscription and its servers" }).clicked()
                        {
                            if armed { remove = Some(sub.id.clone()); }
                            else { confirm = Some(sub.id.clone()); }
                        }
                        if armed { ui.label(RichText::new("Delete?").size(12.0_f32).color(theme::RED)); }
                    });
                });
            });
        }
        ui.add_space(12.0_f32);
        if theme::primary(ui, "+ Add subscription").clicked() { app.page = Page::AddSubscription; }
    });
    if let Some(id) = update { app.update_subscriptions(Some(id), ctx); }
    if let Some(id) = confirm { app.confirm_delete = Some((id, Instant::now())); }
    if let Some(id) = remove { app.remove_subscription(&id); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn relative_update_labels() {
        assert_eq!(relative_time(0, 10000), "never updated");
        assert_eq!(relative_time(9990, 10000), "updated just now");
        assert_eq!(relative_time(2800, 10000), "updated 2h ago");
        assert_eq!(relative_time(10001, 10000), "updated just now");
    }
    #[test]
    fn validates_urls_and_extracts_default_names() {
        assert_eq!(subscription_host(" https://zerofee.ok-exor.ir/sub?id=123 "), Some("zerofee.ok-exor.ir".into()));
        assert_eq!(subscription_host("http://localhost:8080/sub"), Some("localhost".into()));
        for value in ["", "https://", "https://exa mple.org", "example.org/sub", "ftp://example.org/sub"] {
            assert_eq!(subscription_host(value), None, "{value}");
        }
    }
}
