use easyvpn_core::{store, Rule, RuleAction, RuleKind};
use eframe::egui::*;
use crate::{app::App, theme};

fn kind_name(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Domain => "Domain",
        RuleKind::DomainSuffix => "Suffix",
        RuleKind::DomainKeyword => "Keyword",
        RuleKind::IpCidr => "IP range",
        RuleKind::Process => "App",
    }
}
fn action_name(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Proxy => "Proxy", RuleAction::Direct => "Direct", RuleAction::Block => "Block",
    }
}
fn action_color(action: RuleAction) -> Color32 {
    match action {
        RuleAction::Proxy => theme::BLUE, RuleAction::Direct => theme::MUTED, RuleAction::Block => theme::RED,
    }
}
fn placeholder(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Domain => "google.com",
        RuleKind::DomainSuffix => "example.org",
        RuleKind::DomainKeyword => "google",
        RuleKind::IpCidr => "10.0.0.0/8",
        RuleKind::Process => "telegram.exe",
    }
}
fn valid_value(kind: RuleKind, value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_control) { return false; }
    match kind {
        RuleKind::IpCidr => value.split_once('/').is_some_and(|(ip, prefix)| {
            match (ip.parse::<std::net::IpAddr>(), prefix.parse::<u8>()) {
                (Ok(std::net::IpAddr::V4(_)), Ok(prefix)) => prefix <= 32,
                (Ok(std::net::IpAddr::V6(_)), Ok(prefix)) => prefix <= 128,
                _ => false,
            }
        }),
        RuleKind::Domain | RuleKind::DomainSuffix => {
            !value.contains(['/', ':', '*']) && !value.chars().any(char::is_whitespace) && url_like_domain(value)
        }
        RuleKind::DomainKeyword | RuleKind::Process => true,
    }
}
fn url_like_domain(value: &str) -> bool {
    value.trim_matches('.').split('.').all(|label| {
        !label.is_empty() && !label.starts_with('-') && !label.ends_with('-')
            && label.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    })
}

pub fn show(app: &mut App, ui: &mut Ui, _ctx: &Context) {
    let mobile = app.platform.is_mobile();
    ui.label(RichText::new("Rules are applied from top to bottom, before bypass sources and LAN rules.")
        .size(12.0_f32).color(theme::MUTED));
    ui.label(RichText::new(if mobile { "App rules use Android package names" } else { "App rules work in TUN mode" })
        .size(12.0_f32).color(theme::BLUE));
    if mobile {
        ui.label(RichText::new("In VPN mode, Direct apps bypass the VPN. With Only selected via VPN, Proxy apps use the VPN. Block app rules are ignored.")
            .size(11.0_f32).color(theme::MUTED));
    }
    let mut changed = false;
    let mut delete = None;
    let mut movement = None;
    let count = app.store.settings.rules.len();
    if count == 0 { theme::empty(ui, theme::Icon::Link, "No custom rules yet"); }
    for (index, rule) in app.store.settings.rules.iter_mut().enumerate() {
        ui.push_id(&rule.id, |ui| {
            theme::card_frame().show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let _ = theme::chip(ui, kind_name(rule.kind), false);
                    ui.label(RichText::new(action_name(rule.action)).font(theme::semibold_font(12.0_f32)).color(action_color(rule.action)));
                    changed |= theme::toggle(ui, &mut rule.enabled).changed();
                });
                ui.add(Label::new(RichText::new(&rule.value).monospace().size(13.0_f32)).truncate()).on_hover_text(&rule.value);
                ui.horizontal_wrapped(|ui| {
                    ui.add_enabled_ui(index > 0, |ui| {
                        if theme::secondary(ui, "Move up", false).clicked() { movement = Some((index, index - 1)); }
                    });
                    ui.add_enabled_ui(index + 1 < count, |ui| {
                        if theme::secondary(ui, "Move down", false).clicked() { movement = Some((index, index + 1)); }
                    });
                    if theme::secondary(ui, "Delete", true).clicked() { delete = Some(index); }
                });
            });
        });
    }
    if let Some(index) = delete {
        app.store.settings.rules.remove(index);
        changed = true;
    } else if let Some((from, to)) = movement {
        app.store.settings.rules.swap(from, to);
        changed = true;
    }
    theme::section(ui, "ADD RULE");
    let mut add = false;
    theme::card_frame().show(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            for kind in [RuleKind::Domain, RuleKind::DomainSuffix, RuleKind::DomainKeyword, RuleKind::IpCidr, RuleKind::Process] {
                if theme::chip(ui, kind_name(kind), app.rule_draft.kind == kind).clicked() { app.rule_draft.kind = kind; }
            }
        });
        let hint = if mobile && app.rule_draft.kind == RuleKind::Process {
            "org.telegram.messenger"
        } else { placeholder(app.rule_draft.kind) };
        theme::input(ui, &mut app.rule_draft.value, hint);
        ui.horizontal_wrapped(|ui| {
            for action in [RuleAction::Proxy, RuleAction::Direct, RuleAction::Block] {
                if theme::chip(ui, action_name(action), app.rule_draft.action == action).clicked() { app.rule_draft.action = action; }
            }
        });
        let valid = valid_value(app.rule_draft.kind, app.rule_draft.value.trim());
        if !app.rule_draft.value.is_empty() && !valid {
            ui.label(RichText::new("Enter a valid value for this rule type.").size(11.0_f32).color(theme::RED));
        }
        ui.add_enabled_ui(valid, |ui| { add = theme::primary(ui, "Add rule").clicked(); });
    });
    if add {
        let mut rule = app.rule_draft.clone();
        rule.id = store::new_id();
        rule.value = rule.value.trim().to_owned();
        rule.enabled = true;
        app.store.settings.rules.push(rule);
        app.rule_draft = Rule::default();
        app.status = "Rule added".into();
        changed = true;
    }
    if changed { app.save(); }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_rule_values() {
        assert!(valid_value(RuleKind::IpCidr, "10.0.0.0/8"));
        assert!(valid_value(RuleKind::IpCidr, "2001:db8::/32"));
        assert!(!valid_value(RuleKind::IpCidr, "10.0.0.0/33"));
        assert!(!valid_value(RuleKind::IpCidr, "example.org/24"));
        assert!(valid_value(RuleKind::DomainSuffix, "example.org"));
        assert!(!valid_value(RuleKind::Domain, "https://example.org"));
        assert!(valid_value(RuleKind::Process, "telegram.exe"));
        assert!(valid_value(RuleKind::Process, "org.telegram.messenger"));
        assert!(!valid_value(RuleKind::Process, ""));
        assert!(!valid_value(RuleKind::DomainKeyword, "bad\nvalue"));
    }
}
