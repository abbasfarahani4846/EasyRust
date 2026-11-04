use easyvpn_core::{Network, Profile, Protocol, Security};
use eframe::egui;
use crate::{app::{App, Page}, theme};

/// Retains identity and fields not exposed by the manual editor.
#[derive(Debug, Clone)]
pub struct EditorState {
    pub profile: Profile,
    pub port: String,
    pub errors: Vec<(String, String)>,
    pub transport_open: bool,
    pub tls_open: bool,
}

impl Default for EditorState {
    fn default() -> Self { Self::new(None) }
}

impl EditorState {
    pub fn new(existing: Option<&Profile>) -> Self {
        let profile = existing.cloned().unwrap_or_else(|| Profile {
            protocol: Some(Protocol::Vless), port: default_port(Protocol::Vless), ..Profile::default()
        });
        Self { port: profile.port.to_string(), profile, errors: Vec::new(), transport_open: false, tls_open: false }
    }

    fn select_protocol(&mut self, protocol: Protocol) {
        if self.profile.protocol == Some(protocol) { return; }
        let previous_default = self.profile.protocol.map(default_port);
        if self.port.trim().parse::<u16>().ok() == previous_default {
            self.port = default_port(protocol).to_string();
            self.profile.port = default_port(protocol);
        }
        self.profile.protocol = Some(protocol);
        self.errors.clear();
    }

    pub fn validate(&self) -> Result<Profile, Vec<(String, String)>> {
        let mut profile = self.profile.clone();
        let mut errors = Vec::new();
        profile.address = profile.address.trim().to_owned();
        profile.name = profile.name.trim().to_owned();
        if profile.address.is_empty() {
            error(&mut errors, "address", "Address is required");
        } else if profile.address.chars().any(char::is_whitespace) {
            error(&mut errors, "address", "Address must not contain whitespace");
        }
        match self.port.trim().parse::<u16>() {
            Ok(port) if port != 0 => profile.port = port,
            _ => error(&mut errors, "port", "Enter a port from 1 to 65535"),
        }
        match profile.protocol {
            Some(Protocol::Vless | Protocol::Vmess | Protocol::Tuic) => {
                profile.uuid = profile.uuid.trim().to_owned();
                if !valid_uuid(&profile.uuid) {
                    error(&mut errors, "uuid", "Enter a UUID in 8-4-4-4-12 hexadecimal form");
                }
                if profile.protocol == Some(Protocol::Tuic) { required(&mut errors, "password", &profile.password); }
            }
            Some(Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria | Protocol::Hysteria2) => {
                required(&mut errors, "password", &profile.password);
            }
            Some(Protocol::Shadowsocks) => {
                required(&mut errors, "method", &profile.method);
                required(&mut errors, "password", &profile.password);
            }
            Some(Protocol::Ssh) => {
                required(&mut errors, "username", &profile.username);
                if profile.password.is_empty() && profile.ssh_private_key.trim().is_empty() {
                    error(&mut errors, "password", "Enter a password or a private key");
                }
            }
            Some(Protocol::Wireguard) => {
                required(&mut errors, "private_key", &profile.private_key);
                required(&mut errors, "public_key", &profile.public_key);
                if profile.local_address.is_empty() {
                    error(&mut errors, "local_address", "At least one local IP address/prefix is required");
                }
                for address in &profile.local_address {
                    if !valid_interface_address(address) {
                        error(&mut errors, "local_address", "Use IP/prefix entries such as 10.0.0.2/32");
                        break;
                    }
                }
                if !profile.reserved.is_empty() && profile.reserved.len() != 3 {
                    error(&mut errors, "reserved", "Reserved must contain exactly three bytes");
                }
            }
            Some(Protocol::Socks | Protocol::Http) => {}
            _ => error(&mut errors, "protocol", "Choose a supported manual protocol"),
        }
        if uses_transport(profile.protocol) && profile.transport.network == Network::Xhttp
            && !profile.transport.extra.trim().is_empty()
            && serde_json::from_str::<serde_json::Value>(&profile.transport.extra).is_err()
        {
            error(&mut errors, "extra", "Extra must be valid JSON");
        }
        if uses_tls(profile.protocol) && profile.tls.security == Security::Reality {
            required(&mut errors, "reality_public_key", &profile.tls.reality_public_key);
        }
        if profile.name.is_empty() { profile.name = profile.address.clone(); }
        if errors.is_empty() { Ok(profile) } else { Err(errors) }
    }
}

fn default_port(protocol: Protocol) -> u16 {
    match protocol {
        Protocol::Ssh => 22, Protocol::Socks => 1080, Protocol::Http => 8080,
        Protocol::Shadowsocks => 8388, Protocol::Wireguard => 51820, Protocol::OpenVpn => 1194, _ => 443,
    }
}
fn error(errors: &mut Vec<(String, String)>, field: &str, message: &str) {
    errors.push((field.to_owned(), message.to_owned()));
}
fn required(errors: &mut Vec<(String, String)>, field: &str, value: &str) {
    if value.trim().is_empty() { error(errors, field, "This field is required"); }
}
fn valid_uuid(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' } else { byte.is_ascii_hexdigit() }
    })
}
fn valid_interface_address(value: &str) -> bool {
    let Some((ip, prefix)) = value.trim().split_once('/') else { return false; };
    match (ip.parse::<std::net::IpAddr>(), prefix.parse::<u8>()) {
        (Ok(std::net::IpAddr::V4(_)), Ok(prefix)) => prefix <= 32,
        (Ok(std::net::IpAddr::V6(_)), Ok(prefix)) => prefix <= 128,
        _ => false,
    }
}
fn uses_transport(protocol: Option<Protocol>) -> bool {
    matches!(protocol, Some(Protocol::Vless | Protocol::Vmess | Protocol::Trojan))
}
fn uses_tls(protocol: Option<Protocol>) -> bool {
    uses_transport(protocol) || matches!(protocol, Some(Protocol::Http | Protocol::AnyTls | Protocol::Hysteria | Protocol::Hysteria2 | Protocol::Tuic))
}
const PROTOCOLS: [(Protocol, &str); 12] = [
    (Protocol::Vless, "VLESS"), (Protocol::Vmess, "VMess"), (Protocol::Trojan, "Trojan"),
    (Protocol::Shadowsocks, "Shadowsocks"), (Protocol::Socks, "SOCKS"), (Protocol::Http, "HTTP"),
    (Protocol::Hysteria2, "Hysteria2"), (Protocol::Hysteria, "Hysteria"), (Protocol::Tuic, "TUIC"),
    (Protocol::Wireguard, "WireGuard"), (Protocol::Ssh, "SSH"), (Protocol::AnyTls, "AnyTLS"),
];
fn label(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).size(12.0_f32).color(theme::MUTED));
}
fn field(ui: &mut egui::Ui, name: &str, value: &mut String, hint: &str) {
    label(ui, name);
    theme::input(ui, value, hint);
}
fn secret(ui: &mut egui::Ui, name: &str, value: &mut String) {
    label(ui, name);
    theme::password_input(ui, value);
}
fn private_key(ui: &mut egui::Ui, value: &mut String) {
    label(ui, "Private key (PEM)");
    theme::text_area(ui, value, 150.0_f32);
}
fn list_field(ui: &mut egui::Ui, name: &str, values: &mut Vec<String>, hint: &str) {
    let mut text = values.join(", ");
    label(ui, name);
    if theme::input(ui, &mut text, hint).changed() {
        *values = text.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
    }
}
fn number(ui: &mut egui::Ui, name: &str, value: &mut u32) {
    let mut text = if *value == 0 { String::new() } else { value.to_string() };
    label(ui, name);
    if theme::input(ui, &mut text, "Default").changed() {
        if text.is_empty() { *value = 0; }
        else if let Ok(parsed) = text.parse() { *value = parsed; }
    }
}
fn credentials(ui: &mut egui::Ui, profile: &mut Profile) {
    match profile.protocol {
        Some(Protocol::Vless | Protocol::Vmess | Protocol::Tuic) => {
            field(ui, "UUID", &mut profile.uuid, "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx");
            match profile.protocol {
                Some(Protocol::Vless) => field(ui, "Flow", &mut profile.flow, "xtls-rprx-vision"),
                Some(Protocol::Vmess) => {
                    number(ui, "Alter ID", &mut profile.alter_id);
                    field(ui, "Security / method", &mut profile.method, "auto");
                }
                Some(Protocol::Tuic) => {
                    secret(ui, "Password", &mut profile.password);
                    field(ui, "Congestion control", &mut profile.congestion_control, "cubic / bbr / new_reno");
                }
                _ => {}
            }
        }
        Some(Protocol::Shadowsocks) => {
            field(ui, "Method", &mut profile.method, "aes-128-gcm");
            secret(ui, "Password", &mut profile.password);
            field(ui, "Plugin (optional)", &mut profile.plugin, "obfs-local / v2ray-plugin");
            field(ui, "Plugin options", &mut profile.plugin_opts, "");
        }
        Some(Protocol::Socks | Protocol::Http) => {
            field(ui, "Username (optional)", &mut profile.username, "");
            secret(ui, "Password (optional)", &mut profile.password);
        }
        Some(Protocol::Ssh) => {
            field(ui, "Username", &mut profile.username, "root");
            secret(ui, "Password (optional with private key)", &mut profile.password);
            private_key(ui, &mut profile.ssh_private_key);
            secret(ui, "Private key passphrase", &mut profile.ssh_private_key_passphrase);
            list_field(ui, "Host keys", &mut profile.ssh_host_key, "ssh-ed25519 AAAA…, ssh-rsa AAAA…");
            field(ui, "Client version (optional)", &mut profile.ssh_client_version, "");
        }
        Some(Protocol::Wireguard) => {
            secret(ui, "Private key", &mut profile.private_key);
            field(ui, "Peer public key", &mut profile.public_key, "");
            secret(ui, "Preshared key (optional)", &mut profile.pre_shared_key);
            list_field(ui, "Local addresses", &mut profile.local_address, "10.0.0.2/32, fd00::2/128");
            number(ui, "MTU", &mut profile.mtu);
            ui.horizontal_wrapped(|ui| {
                label(ui, "Reserved");
                let mut enabled = !profile.reserved.is_empty();
                if theme::toggle(ui, &mut enabled).changed() {
                    profile.reserved = if enabled { vec![0, 0, 0] } else { Vec::new() };
                }
                if enabled {
                    for byte in &mut profile.reserved { ui.add(egui::DragValue::new(byte).range(0..=255)); }
                }
            });
        }
        Some(Protocol::Hysteria | Protocol::Hysteria2) => {
            secret(ui, "Authentication / password", &mut profile.password);
            field(ui, "Obfuscation", &mut profile.obfs, "salamander (v2) / obfs password (v1)");
            if profile.protocol == Some(Protocol::Hysteria2) { secret(ui, "Obfuscation password", &mut profile.obfs_password); }
            number(ui, "Upload Mbps", &mut profile.up_mbps);
            number(ui, "Download Mbps", &mut profile.down_mbps);
        }
        Some(Protocol::Trojan | Protocol::AnyTls) => secret(ui, "Password", &mut profile.password),
        _ => {}
    }
}
fn section_header(ui: &mut egui::Ui, title: &str, open: &mut bool) {
    let (rect, mut response) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 40.0_f32), egui::Sense::click());
    if response.clicked() { *open = !*open; response.mark_changed(); }
    response.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, ui.is_enabled(), title));
    if !ui.is_rect_visible(rect) { return; }
    let painter = ui.painter();
    if response.hovered() { painter.rect_filled(rect, 10.0_f32, theme::INPUT); }
    let color = if response.hovered() { theme::BLUE } else { ui.visuals().text_color() };
    let center = egui::pos2(rect.left() + 14.0_f32, rect.center().y);
    let points = if *open {
        vec![center + egui::vec2(-4.0_f32, -2.0_f32), center + egui::vec2(0.0_f32, 2.0_f32), center + egui::vec2(4.0_f32, -2.0_f32)]
    } else {
        vec![center + egui::vec2(-2.0_f32, -4.0_f32), center + egui::vec2(2.0_f32, 0.0_f32), center + egui::vec2(-2.0_f32, 4.0_f32)]
    };
    painter.add(egui::Shape::line(points, egui::Stroke::new(1.8_f32, color)));
    painter.text(egui::pos2(rect.left() + 30.0_f32, rect.center().y), egui::Align2::LEFT_CENTER, title, egui::FontId::proportional(14.0_f32), color);
}
fn transport(ui: &mut egui::Ui, profile: &mut Profile) {
    ui.horizontal_wrapped(|ui| {
        for (network, name) in [
            (Network::Tcp, "TCP"), (Network::Ws, "WS"), (Network::Grpc, "gRPC"), (Network::H2, "H2"),
            (Network::HttpUpgrade, "HTTPUpgrade"), (Network::Xhttp, "XHTTP"), (Network::Kcp, "KCP"), (Network::Quic, "QUIC"),
        ] {
            if theme::chip(ui, name, profile.transport.network == network).clicked() { profile.transport.network = network; }
        }
    });
    field(ui, "Path", &mut profile.transport.path, "/");
    field(ui, "Host", &mut profile.transport.host, "");
    field(ui, "Service name", &mut profile.transport.service_name, "");
    field(ui, "Header type", &mut profile.transport.header_type, "none / http");
    field(ui, "Mode / extra (JSON for XHTTP)", &mut profile.transport.extra, "{}");
}
fn tls(ui: &mut egui::Ui, profile: &mut Profile) {
    ui.horizontal_wrapped(|ui| {
        for (security, name) in [(Security::None, "None"), (Security::Tls, "TLS"), (Security::Reality, "REALITY")] {
            if theme::chip(ui, name, profile.tls.security == security).clicked() { profile.tls.security = security; }
        }
    });
    if profile.tls.security != Security::None {
        field(ui, "Server name (SNI)", &mut profile.tls.sni, "example.com");
        list_field(ui, "ALPN", &mut profile.tls.alpn, "h2, http/1.1");
        field(ui, "Fingerprint", &mut profile.tls.fingerprint, "chrome");
        theme::settings_row(ui, "Allow insecure", Some("Disables certificate verification"), |ui| {
            theme::toggle(ui, &mut profile.tls.allow_insecure);
        });
        if profile.tls.security == Security::Reality {
            field(ui, "Public key", &mut profile.tls.reality_public_key, "");
            field(ui, "Short ID", &mut profile.tls.reality_short_id, "");
            field(ui, "Spider X", &mut profile.tls.reality_spider_x, "/");
        }
    }
}
pub fn show(app: &mut App, ui: &mut egui::Ui, _ctx: &egui::Context) {
    let mut editor = app.editor.take().unwrap_or_default();
    theme::section(ui, "PROTOCOL");
    ui.horizontal_wrapped(|ui| {
        for (protocol, name) in PROTOCOLS {
            if theme::chip(ui, name, editor.profile.protocol == Some(protocol)).clicked() { editor.select_protocol(protocol); }
        }
    });
    theme::section(ui, "SERVER");
    theme::card_frame().show(ui, |ui| {
        field(ui, "Name", &mut editor.profile.name, "My server");
        field(ui, "Address", &mut editor.profile.address, "example.com");
        field(ui, "Port", &mut editor.port, "Port");
        credentials(ui, &mut editor.profile);
    });
    if uses_transport(editor.profile.protocol) {
        theme::card_frame().show(ui, |ui| {
            section_header(ui, "Transport", &mut editor.transport_open);
            if editor.transport_open { transport(ui, &mut editor.profile); }
        });
    }
    if uses_tls(editor.profile.protocol) {
        theme::card_frame().show(ui, |ui| {
            section_header(ui, "TLS", &mut editor.tls_open);
            if editor.tls_open { tls(ui, &mut editor.profile); }
        });
    }
    for (field, message) in &editor.errors {
        ui.add(egui::Label::new(egui::RichText::new(format!("{field}: {message}")).size(12.0_f32).color(theme::RED)).wrap());
    }
    if theme::primary(ui, "Save config").clicked() {
        match editor.validate() {
            Ok(profile) => {
                let id = if !profile.id.is_empty() {
                    if let Some(existing) = app.store.profiles.iter_mut().find(|p| p.id == profile.id) {
                        let id = profile.id.clone();
                        *existing = profile;
                        id
                    } else { app.store.add_profile(profile) }
                } else { app.store.add_profile(profile) };
                app.store.selected = Some(id);
                if let Some(core) = app.store.selected_profile().and_then(|p| p.pick_core(app.store.settings.core)) {
                    app.store.settings.core = core;
                }
                app.save();
                app.page = Page::Home;
                return;
            }
            Err(errors) => editor.errors = errors,
        }
    }
    if theme::secondary(ui, "Cancel", false).clicked() { app.page = Page::Home; return; }
    app.editor = Some(editor);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn editor(protocol: Protocol) -> EditorState {
        EditorState::new(Some(&Profile {
            protocol: Some(protocol), address: "example.com".into(), port: 443,
            uuid: "00112233-4455-6677-8899-aabbccddeeff".into(), password: "secret".into(),
            username: "user".into(), method: "aes-128-gcm".into(), private_key: "private".into(),
            public_key: "public".into(), local_address: vec!["10.0.0.2/32".into(), "fd00::2/128".into()],
            ..Profile::default()
        }))
    }
    #[test]
    fn new_profiles_have_no_example_values() {
        let mut state = EditorState::default();
        for (protocol, _) in PROTOCOLS {
            state.select_protocol(protocol);
            assert_eq!(state.port, default_port(protocol).to_string());
            assert_eq!(state.profile, Profile { protocol: Some(protocol), port: default_port(protocol), ..Profile::default() });
        }
        assert!(state.validate().is_err());
    }
    #[test]
    fn default_ports_follow_protocol_without_overwriting_custom_ports() {
        let mut state = EditorState::default();
        for (protocol, expected) in [
            (Protocol::Ssh, 22), (Protocol::Socks, 1080), (Protocol::Http, 8080),
            (Protocol::Shadowsocks, 8388), (Protocol::Wireguard, 51820), (Protocol::Vless, 443),
            (Protocol::Vmess, 443), (Protocol::Trojan, 443), (Protocol::AnyTls, 443),
            (Protocol::Hysteria2, 443), (Protocol::Hysteria, 443), (Protocol::Tuic, 443),
        ] {
            state.select_protocol(protocol);
            assert_eq!(state.port, expected.to_string());
        }
        state.port = "12345".into();
        state.select_protocol(Protocol::Ssh);
        assert_eq!(state.port, "12345");
        state.port.clear();
        state.select_protocol(Protocol::Http);
        assert!(state.port.is_empty());
    }
    #[test]
    fn all_manual_protocols_validate() {
        for (protocol, _) in PROTOCOLS { assert!(editor(protocol).validate().is_ok(), "{protocol:?}"); }
    }
    #[test]
    fn editing_preserves_identity_and_unexposed_fields() {
        let profile = Profile { id: "abcd1234".into(), subscription_id: Some("subscription".into()),
            plugin_opts: "obfs=http".into(), ..editor(Protocol::Shadowsocks).profile };
        let state = EditorState::new(Some(&profile));
        assert_eq!(state.validate().expect("valid").id, profile.id);
        assert_eq!(state.validate().expect("valid").subscription_id, profile.subscription_id);
        assert_eq!(state.profile, profile);
    }
    #[test]
    fn invalid_ports_and_empty_address_have_field_errors() {
        for port in ["", "0", "65536", "-1", "443x"] {
            let mut state = editor(Protocol::Vless);
            state.port = port.into();
            state.profile.address.clear();
            let errors = state.validate().expect_err("invalid");
            assert!(errors.iter().any(|(field, _)| field == "port"));
            assert!(errors.iter().any(|(field, _)| field == "address"));
        }
    }
    #[test]
    fn uuid_is_checked_without_accepting_bad_separators() {
        for uuid in ["", "not-a-uuid", "00112233445566778899aabbccddeeff", "00112233_4455-6677-8899-aabbccddeeff", "00112233-4455-6677-8899-aabbccddeefg"] {
            for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Tuic] {
                let mut state = editor(protocol);
                state.profile.uuid = uuid.into();
                assert!(state.validate().expect_err("UUID").iter().any(|(f, _)| f == "uuid"));
            }
        }
    }
    #[test]
    fn ssh_accepts_key_instead_of_password() {
        let mut state = editor(Protocol::Ssh);
        state.profile.password.clear();
        assert!(state.validate().is_err());
        state.profile.ssh_private_key = "-----BEGIN OPENSSH PRIVATE KEY-----".into();
        assert!(state.validate().is_ok());
    }
    #[test]
    fn required_credentials_are_checked() {
        for protocol in [Protocol::Trojan, Protocol::AnyTls, Protocol::Hysteria, Protocol::Hysteria2, Protocol::Tuic, Protocol::Shadowsocks] {
            let mut state = editor(protocol);
            state.profile.password.clear();
            assert!(state.validate().expect_err("password").iter().any(|(f, _)| f == "password"));
        }
        let mut anonymous = editor(Protocol::Http);
        anonymous.profile.username.clear();
        anonymous.profile.password.clear();
        assert!(anonymous.validate().is_ok());
    }
    #[test]
    fn xhttp_extra_must_be_json() {
        let mut state = editor(Protocol::Vless);
        state.profile.transport.network = Network::Xhttp;
        state.profile.transport.extra = "{broken".into();
        assert!(state.validate().expect_err("JSON").iter().any(|(f, _)| f == "extra"));
        state.profile.transport.extra = r#"{"mode":"auto","extra":{"xPaddingBytes":"100-1000"}}"#.into();
        assert!(state.validate().is_ok());
    }
    #[test]
    fn wireguard_addresses_and_reserved_are_checked() {
        let mut state = editor(Protocol::Wireguard);
        state.profile.local_address = vec!["10.0.0.2/33".into()];
        assert!(state.validate().is_err());
        state.profile.local_address = vec!["fd00::2/128".into()];
        state.profile.reserved = vec![1, 2];
        assert!(state.validate().is_err());
        state.profile.reserved.push(3);
        assert!(state.validate().is_ok());
    }
    #[test]
    fn validation_is_pure_and_normalizes_only_the_result() {
        let mut state = editor(Protocol::Vless);
        state.profile.name = "  Example  ".into();
        state.profile.address = " example.com ".into();
        let before = state.clone();
        let result = state.validate().expect("valid");
        assert_eq!(result.name, "Example");
        assert_eq!(result.address, "example.com");
        assert_eq!(state.profile, before.profile);
        assert_eq!(state.port, before.port);
    }
    #[test]
    fn header_state_is_retained_without_affecting_validation() {
        let mut state = editor(Protocol::Vless);
        assert!(!state.transport_open);
        assert!(!state.tls_open);
        let before = state.validate().expect("valid");
        state.transport_open = true;
        state.tls_open = true;
        let retained = state.clone();
        assert!(retained.transport_open);
        assert!(retained.tls_open);
        assert_eq!(state.validate().expect("valid"), before);
    }
}
