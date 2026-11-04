//! Detect and import share links, tunnel configurations, and raw core configs.

use crate::{
    link,
    profile::{CoreKind, Profile, Protocol},
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use std::{collections::HashMap, path::Path};
use url::Url;

#[path = "import/xray_array.rs"]
mod xray_array;

/// The result of classifying pasted, scanned, or imported text.
#[derive(Debug, Clone, PartialEq)]
pub enum Classified {
    Subscription(String),
    Configs(Vec<Profile>),
    Nothing,
}

/// Decide whether text contains a subscription URL or supported configurations.
///
/// Share links on any line take precedence over subscription URLs. Otherwise,
/// only the first non-empty line is considered for subscription detection.
pub fn classify(text: &str) -> Classified {
    let body = text.trim().trim_start_matches('\u{feff}').trim();
    if body.is_empty() {
        return Classified::Nothing;
    }

    let has_share_link = body.lines().any(|line| {
        let Some((scheme, _)) = line.trim().split_once("://") else {
            return false;
        };
        matches!(
            scheme.to_ascii_lowercase().as_str(),
            "vmess"
                | "vless"
                | "trojan"
                | "ss"
                | "socks"
                | "socks5"
                | "hy2"
                | "hysteria2"
                | "hysteria"
                | "tuic"
                | "wireguard"
                | "wg"
                | "ssh"
                | "anytls"
        )
    });

    if !has_share_link {
        if let Some(url) = body
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .and_then(subscription_url)
        {
            return Classified::Subscription(url);
        }
    }

    let profiles = import_text(body, None);
    if profiles.is_empty() {
        Classified::Nothing
    } else {
        Classified::Configs(profiles)
    }
}

/// Require an HTTP(S) URL without userinfo, including explicitly empty userinfo.
fn remote_url(text: &str) -> Option<Url> {
    let url = Url::parse(text).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let (_, rest) = text.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    Some(url)
}

fn subscription_url(text: &str) -> Option<String> {
    let (scheme, payload) = text.split_once("://")?;
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "https" => {
            let url = remote_url(text)?;
            if url.path().trim_start_matches('/').is_empty() && url.query().is_none() {
                return None;
            }
            Some(text.to_owned())
        }
        "sub" => {
            for engine in [
                &general_purpose::STANDARD,
                &general_purpose::STANDARD_NO_PAD,
                &general_purpose::URL_SAFE,
                &general_purpose::URL_SAFE_NO_PAD,
            ] {
                let Ok(bytes) = engine.decode(payload) else {
                    continue;
                };
                let Ok(decoded) = String::from_utf8(bytes) else {
                    continue;
                };
                let decoded = decoded.trim();
                if remote_url(decoded).is_some() {
                    return Some(decoded.to_owned());
                }
            }
            None
        }
        "clash" | "sing-box" => {
            let url = Url::parse(text).ok()?;
            let expected_host = if scheme.eq_ignore_ascii_case("clash") {
                "install-config"
            } else {
                "import-remote-profile"
            };
            if url.host_str()? != expected_host {
                return None;
            }
            let decoded = url
                .query_pairs()
                .find_map(|(key, value)| (key == "url").then(|| value.into_owned()))?;
            remote_url(&decoded)?;
            Some(decoded)
        }
        _ => None,
    }
}

/// Detect and import any supported config text.
///
/// `file_name`, when known, supplies the profile name and helps detect OpenVPN.
/// Raw configurations are retained verbatim, including whitespace and comments.
pub fn import_text(text: &str, file_name: Option<&str>) -> Vec<Profile> {
    let body = text.trim_start_matches('\u{feff}');
    let extension = file_name
        .and_then(|name| Path::new(name).extension())
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let remote = body.lines().find_map(openvpn_remote);
    let has_client = body
        .lines()
        .any(|line| directive_words(line).first().copied() == Some("client"));

    if remote.is_some() && (matches!(extension.as_str(), "ovpn" | "conf") || has_client) {
        let (address, port) = remote.expect("remote was checked above");
        return vec![Profile {
            name: profile_name(file_name, &format!("OpenVPN {address}")),
            protocol: Some(Protocol::OpenVpn),
            address,
            port,
            raw_config: text.into(),
            ..Profile::default()
        }];
    }

    let has_interface = body.lines().any(|line| wg_line(line) == "[Interface]");
    let has_peer = body.lines().any(|line| wg_line(line) == "[Peer]");
    if has_interface && has_peer {
        return parse_wireguard(body, file_name).into_iter().collect();
    }

    if let Ok(value) = serde_json::from_str::<Value>(body) {
        if let Some(configs) = value.as_array() {
            return configs.iter().map(xray_array::import_config).collect();
        }
        if let Some(outbounds) = value.get("outbounds").and_then(Value::as_array) {
            let core = if outbounds.iter().any(|o| o.get("protocol").is_some()) {
                Some(CoreKind::Xray)
            } else if outbounds.iter().any(|o| o.get("type").is_some()) {
                Some(CoreKind::SingBox)
            } else {
                None
            };
            if let Some(core) = core {
                let (address, port) = outbounds
                    .iter()
                    .filter(|outbound| is_proxy_outbound(outbound))
                    .find_map(outbound_server)
                    .unwrap_or_default();
                return vec![Profile {
                    name: profile_name(file_name, &format!("Custom {}", core.name())),
                    protocol: Some(Protocol::Custom),
                    custom_core: Some(core),
                    raw_config: text.into(),
                    address,
                    port,
                    ..Profile::default()
                }];
            }
        }
    }

    if body.lines().any(|line| line.starts_with("proxies:")) {
        return vec![Profile {
            name: profile_name(file_name, "Custom mihomo"),
            protocol: Some(Protocol::Custom),
            custom_core: Some(CoreKind::Mihomo),
            raw_config: text.into(),
            ..Profile::default()
        }];
    }

    link::parse_many(body)
}

/// Read and import a config file, returning an error if no profiles were found.
pub fn import_file(path: &Path) -> Result<Vec<Profile>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read config {}", path.display()))?;
    let profiles = import_text(&text, path.file_name().and_then(|name| name.to_str()));
    if profiles.is_empty() {
        bail!("no supported profiles found in {}", path.display());
    }
    Ok(profiles)
}

fn profile_name(file_name: Option<&str>, fallback: &str) -> String {
    file_name
        .and_then(|name| Path::new(name).file_stem())
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or(fallback)
        .to_owned()
}

/// OpenVPN's common unquoted directives; surrounding quotes on individual
/// arguments are accepted as well. Comment and blank lines are ignored.
fn directive_words(line: &str) -> Vec<&str> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with(';') {
        return Vec::new();
    }
    line.split_whitespace()
        .take_while(|word| !word.starts_with('#') && !word.starts_with(';'))
        .map(|word| word.trim_matches(|c| c == '"' || c == '\''))
        .collect()
}

fn openvpn_remote(line: &str) -> Option<(String, u16)> {
    let words = directive_words(line);
    if words.first().copied()? != "remote" {
        return None;
    }
    let host = words.get(1)?.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    let port = match words.get(2) {
        Some(port) => port.parse::<u16>().ok()?,
        None => 1194,
    };
    if port == 0 {
        return None;
    }
    Some((host.into(), port))
}

fn wg_line(line: &str) -> &str {
    line.split_once('#')
        .map_or(line, |(before, _)| before)
        .trim()
}

fn comma_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

fn parse_wireguard(text: &str, file_name: Option<&str>) -> Option<Profile> {
    let mut interface = HashMap::new();
    let mut peer = HashMap::new();
    let mut section = "";
    let mut seen_peer = false;
    for line in text.lines().map(wg_line) {
        if line.starts_with('[') && line.ends_with(']') {
            if line == "[Peer]" {
                if seen_peer {
                    break;
                }
                seen_peer = true;
            }
            section = line;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let target = match section {
            "[Interface]" => &mut interface,
            "[Peer]" => &mut peer,
            _ => continue,
        };
        target.insert(key.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    let endpoint = peer.get("endpoint")?;
    let (host, port) = endpoint.rsplit_once(':')?;
    let address = host.trim_start_matches('[').trim_end_matches(']');
    let port = port.trim().parse::<u16>().ok()?;
    if address.is_empty() || port == 0 {
        return None;
    }
    if address.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        return None;
    }
    let private_key = interface.get("privatekey")?.clone();
    let public_key = peer.get("publickey")?.clone();
    if private_key.is_empty() || public_key.is_empty() {
        return None;
    }
    let mtu = match interface.get("mtu") {
        Some(value) => value.parse().ok()?,
        None => 0,
    };
    let reserved = match peer.get("reserved").or_else(|| interface.get("reserved")) {
        Some(value) => comma_list(value)
            .iter()
            .map(|byte| byte.parse::<u8>().ok())
            .collect::<Option<Vec<_>>>()?,
        None => Vec::new(),
    };

    Some(Profile {
        name: profile_name(file_name, &format!("WireGuard {address}")),
        protocol: Some(Protocol::Wireguard),
        address: address.into(),
        port,
        private_key,
        public_key,
        pre_shared_key: peer.get("presharedkey").cloned().unwrap_or_default(),
        local_address: interface
            .get("address")
            .map(|value| comma_list(value))
            .unwrap_or_default(),
        mtu,
        reserved,
        ..Profile::default()
    })
}

fn is_proxy_outbound(outbound: &Value) -> bool {
    let kind = outbound
        .get("protocol")
        .or_else(|| outbound.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("");
    !matches!(
        kind,
        "" | "direct" | "freedom" | "block" | "blackhole" | "dns" | "selector" | "urltest"
    )
}

fn outbound_server(outbound: &Value) -> Option<(String, u16)> {
    if let Some(server) = outbound.get("server").and_then(Value::as_str) {
        return Some((server.into(), json_port(outbound.get("server_port"))));
    }
    let settings = outbound.get("settings")?;
    for key in ["vnext", "servers", "peers"] {
        if let Some(entries) = settings.get(key).and_then(Value::as_array) {
            for entry in entries {
                if let Some(address) = entry.get("address").and_then(Value::as_str) {
                    return Some((address.into(), json_port(entry.get("port"))));
                }
                if let Some(endpoint) = entry.get("endpoint").and_then(Value::as_str) {
                    if let Some((host, port)) = endpoint.rsplit_once(':') {
                        if let Ok(port) = port.parse::<u16>() {
                            return Some((
                                host.trim_start_matches('[').trim_end_matches(']').into(),
                                port,
                            ));
                        }
                    }
                }
            }
        }
    }
    None
}

fn json_port(value: Option<&Value>) -> u16 {
    match value {
        Some(Value::Number(number)) => number
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(0),
        Some(Value::String(port)) => port.parse().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str, file_name: Option<&str>) -> Profile {
        let profiles = import_text(text, file_name);
        assert_eq!(profiles.len(), 1);
        profiles.into_iter().next().expect("one profile")
    }

    #[test]
    fn classify_subscription_and_proxy_urls() {
        let url = "https://zerofee.ok-exor.ir/sub/djMs…";
        assert_eq!(classify(url), Classified::Subscription(url.into()));
        for url in [
            "https://example.com/sub",
            "https://example.com/?token=abc",
            "https://example.com?token=abc",
        ] {
            assert_eq!(
                classify(&format!(" \n{url}\n ")),
                Classified::Subscription(url.into())
            );
        }
        let Classified::Configs(profiles) = classify("http://u:p@1.2.3.4:8080") else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].protocol, Some(Protocol::Http));
        assert_eq!(profiles[0].username, "u");
        assert_eq!(profiles[0].password, "p");
        assert_eq!(profiles[0].port, 8080);

        // A path or query must not turn authenticated proxy links into subscriptions.
        assert!(matches!(
            classify("https://u:p@example.com:443/path?token=x"),
            Classified::Configs(_)
        ));
        assert!(subscription_url("http://@example.com/sub").is_none());
        assert!(subscription_url("https://example.com/").is_none());
        assert!(subscription_url("https://example.com").is_none());
        assert!(subscription_url("ftp://example.com/sub").is_none());
    }

    #[test]
    fn classify_deep_links() {
        let expected = Classified::Subscription("https://example.com/sub".into());
        assert_eq!(
            classify("sub://aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWI="),
            expected
        );
        for engine in [
            &general_purpose::STANDARD,
            &general_purpose::STANDARD_NO_PAD,
            &general_purpose::URL_SAFE,
            &general_purpose::URL_SAFE_NO_PAD,
        ] {
            assert_eq!(
                classify(&format!("sub://{}", engine.encode("https://example.com/sub"))),
                expected
            );
        }
        for deep_link in [
            "clash://install-config?url=https%3A%2F%2Fexample.com%2Fsub",
            "sing-box://import-remote-profile?url=https%3A%2F%2Fexample.com%2Fsub#name",
        ] {
            assert_eq!(classify(deep_link), expected);
        }
        for invalid in [
            "sub://!!!",
            "sub://_w",
            "clash://install-config",
            "clash://other?url=https%3A%2F%2Fexample.com%2Fsub",
            "sing-box://import-remote-profile?url=not-a-url",
            "sub://ZnRwOi8vZXhhbXBsZS5jb20vc3Vi",
        ] {
            assert_eq!(classify(invalid), Classified::Nothing, "{invalid}");
        }
    }

    #[test]
    fn classify_share_links_and_multiline_precedence() {
        let vless = "vless://9706e33d-a122-4123-8123-123456789abc@example.org:443";
        let Classified::Configs(profiles) = classify(vless) else {
            panic!("expected VLESS profile");
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].protocol, Some(Protocol::Vless));

        let subscription = "https://example.com/sub";
        let mixed = format!("{subscription}\n{vless}");
        assert_eq!(
            classify(&mixed),
            Classified::Configs(import_text(&mixed, None))
        );
        let reversed = format!("{vless}\n{subscription}");
        assert!(matches!(classify(&reversed), Classified::Configs(_)));
        assert_eq!(
            classify(" \nhttps://example.com/first\nhttps://example.com/second\n"),
            Classified::Subscription("https://example.com/first".into())
        );
        assert!(subscription_url("not-a-link").is_none());

        for scheme in [
            "vmess", "vless", "trojan", "ss", "socks", "socks5", "hy2",
            "hysteria2", "hysteria", "tuic", "wireguard", "wg", "ssh", "anytls",
        ] {
            // Even a malformed share link prevents selecting a subscription URL.
            let text = format!("{subscription}\n{scheme}://invalid");
            assert_eq!(
                classify(&text),
                Classified::Configs(import_text(&text, None)),
                "{scheme}"
            );
        }
    }

    #[test]
    fn classify_two_vmess_links() {
        let payload = general_purpose::STANDARD.encode(
            r#"{"v":"2","ps":"Test","add":"example.org","port":"443","id":"uuid","net":"tcp"}"#,
        );
        let text = format!("vmess://{payload}\nvmess://{payload}");
        let Classified::Configs(profiles) = classify(&text) else {
            panic!("expected VMess profiles");
        };
        assert_eq!(profiles.len(), 2);
        assert!(profiles.iter().all(|p| p.protocol == Some(Protocol::Vmess)));
    }

    #[test]
    fn classify_empty_invalid_and_raw_config() {
        for text in ["", " \r\n\t ", "\u{feff} \n", "not a config"] {
            assert_eq!(classify(text), Classified::Nothing);
        }
        assert!(matches!(
            classify("client\nremote vpn.example.org 1194\n"),
            Classified::Configs(profiles)
                if profiles.len() == 1 && profiles[0].protocol == Some(Protocol::OpenVpn)
        ));
        assert!(matches!(
            classify("\u{feff}https://example.com/sub"),
            Classified::Subscription(_)
        ));
    }

    #[test]
    fn openvpn_detection_and_verbatim_config() {
        let text = "\u{feff}# VPN\r\nclient\r\nremote vpn.example.org 443 tcp-client\r\nremote backup.example.org 1194\r\n<ca>\r\ncertificate\r\n</ca>\r\n";
        let p = one(text, Some("office.ovpn"));
        assert_eq!(p.protocol, Some(Protocol::OpenVpn));
        assert_eq!(p.name, "office");
        assert_eq!(p.address, "vpn.example.org");
        assert_eq!(p.port, 443);
        assert_eq!(p.raw_config, text);
        assert_eq!(one(text, None).name, "OpenVPN vpn.example.org");
    }

    #[test]
    fn openvpn_extension_or_client_is_required() {
        let text = "# client\nremote vpn.example.org\n";
        let p = one(text, Some("office.CONF"));
        assert_eq!(p.port, 1194);
        assert_eq!(p.name, "office");
        assert!(import_text(text, Some("office.txt")).is_empty());
        assert!(import_text("remote vpn.example.org\n", None).is_empty());
        let p = one("client\nremote [2001:db8::1]\n", None);
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.port, 1194);
        assert!(import_text("client\n# remote example.org\n", None).is_empty());
    }

    #[test]
    fn wireguard_first_peer_and_all_fields() {
        let text = "\
[Interface]
PrivateKey = private+/=
Address = 10.0.0.2/32, fd00::2/128
MTU = 1420
DNS = 1.1.1.1

[Peer]
PublicKey = public+/=
PresharedKey = secret=
Endpoint = [2001:db8::1]:51820 # primary
AllowedIPs = 0.0.0.0/0, ::/0
Reserved = 1, 2, 255

[Peer]
PublicKey = ignored
Endpoint = other.example.org:1234
";
        let p = one(text, Some("home.conf"));
        assert_eq!(p.protocol, Some(Protocol::Wireguard));
        assert_eq!(p.name, "home");
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.port, 51820);
        assert_eq!(p.private_key, "private+/=");
        assert_eq!(p.public_key, "public+/=");
        assert_eq!(p.pre_shared_key, "secret=");
        assert_eq!(p.local_address, ["10.0.0.2/32", "fd00::2/128"]);
        assert_eq!(p.mtu, 1420);
        assert_eq!(p.reserved, [1, 2, 255]);
        assert!(p.raw_config.is_empty());
    }

    #[test]
    fn wireguard_defaults_and_invalid_values() {
        let text = "[Interface]\nPrivateKey=private\nAddress=10.0.0.2/32\n[Peer]\nPublicKey=public\nEndpoint=vpn.example.org:51820\n";
        let p = one(text, None);
        assert_eq!(p.name, "WireGuard vpn.example.org");
        assert_eq!(p.mtu, 0);
        assert!(p.reserved.is_empty());
        assert!(p.pre_shared_key.is_empty());
        for invalid in [
            text.replace(":51820", ":0"),
            text.replace(":51820", ":invalid"),
            text.replace("vpn.example.org:51820", "2001:db8::1:51820"),
            format!("{text}Reserved=256\n"),
            text.replace("PrivateKey=private", "MTU=no"),
            text.replace("PublicKey=public", "PublicKey="),
        ] {
            assert!(import_text(&invalid, Some("bad.conf")).is_empty());
        }
    }

    #[test]
    fn xray_custom_detection_and_address() {
        let text = r#"{
  "outbounds": [
    {"protocol": "freedom", "settings": {}},
    {"protocol": "vless", "settings": {
      "vnext": [{"address": "vpn.example.org", "port": 443, "users": []}]
    }}
  ]
}
"#;
        let p = one(text, Some("my.xray.json"));
        assert_eq!(p.protocol, Some(Protocol::Custom));
        assert_eq!(p.custom_core, Some(CoreKind::Xray));
        assert_eq!(p.name, "my.xray");
        assert_eq!(p.raw_config, text);
        assert_eq!(p.address, "vpn.example.org");
        assert_eq!(p.port, 443);
        assert_eq!(one(text, None).name, "Custom xray");
        let p = one(
            r#"{"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"trojan.example.org","port":"8443"}]}}]}"#,
            None,
        );
        assert_eq!(p.address, "trojan.example.org");
        assert_eq!(p.port, 8443);
    }

    #[test]
    fn singbox_custom_detection_and_address() {
        let text = r#"{"outbounds":[
            {"type":"direct","tag":"direct"},
            {"type":"selector","tag":"selector","outbounds":["proxy"]},
            {"type":"anytls","tag":"proxy","server":"tls.example.org","server_port":443}
        ]}"#;
        let p = one(text, None);
        assert_eq!(p.protocol, Some(Protocol::Custom));
        assert_eq!(p.custom_core, Some(CoreKind::SingBox));
        assert_eq!(p.name, "Custom sing-box");
        assert_eq!(p.address, "tls.example.org");
        assert_eq!(p.port, 443);
        assert_eq!(p.raw_config, text);
    }

    #[test]
    fn custom_json_with_no_discoverable_server() {
        let p = one(r#"{"outbounds":[{"type":"direct"}]}"#, None);
        assert_eq!(p.custom_core, Some(CoreKind::SingBox));
        assert!(p.address.is_empty());
        assert_eq!(p.port, 0);
        assert!(import_text(r#"{"outbounds":[]}"#, None).is_empty());
        assert!(import_text(r#"{"outbounds":[{}]}"#, None).is_empty());
        assert!(import_text(r#"{"outbounds":{}}"#, None).is_empty());
        assert!(import_text("{invalid json", None).is_empty());
    }

    #[test]
    fn mihomo_yaml_is_verbatim_and_requires_top_level_proxies() {
        let text = "# example\nmixed-port: 7890\nproxies:\n  - name: proxy\n    type: ss\n    server: example.org\n";
        let p = one(text, Some("clash.yaml"));
        assert_eq!(p.protocol, Some(Protocol::Custom));
        assert_eq!(p.custom_core, Some(CoreKind::Mihomo));
        assert_eq!(p.name, "clash");
        assert_eq!(p.raw_config, text);
        assert_eq!(one(text, None).name, "Custom mihomo");
        assert!(import_text("nested:\n  proxies: []\n", None).is_empty());
        assert!(import_text("# proxies: []\n", None).is_empty());
    }

    #[test]
    fn detection_order_prefers_openvpn() {
        let text = "client\nremote vpn.example.org\nproxies: []\n";
        assert_eq!(one(text, None).protocol, Some(Protocol::OpenVpn));
    }

    #[test]
    fn fallback_to_plain_and_base64_links() {
        let text = "ssh://user:pass@example.org:22#SSH\ninvalid\nanytls://pass@example.org:443#TLS\nhysteria://example.org:443?auth=pass\n";
        let profiles = import_text(text, Some("links.txt"));
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles, link::parse_many(text));
        assert_eq!(
            import_text(&general_purpose::URL_SAFE_NO_PAD.encode(text), None),
            profiles
        );
        assert_eq!(
            import_text("\u{feff}ssh://user@example.org:22", None).len(),
            1
        );
        assert!(import_text("", None).is_empty());
        assert!(import_text("not a config", None).is_empty());
    }

    #[test]
    fn file_import_and_errors() {
        let dir = std::env::temp_dir().join(format!(
            "easyvpn-import-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).expect("create temporary directory");
        let path = dir.join("office.ovpn");
        std::fs::write(&path, "remote vpn.example.org\n").expect("write fixture");
        let profiles = import_file(&path).expect("import file");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "office");
        assert_eq!(profiles[0].port, 1194);

        let invalid = dir.join("invalid.txt");
        std::fs::write(&invalid, "not a config").expect("write invalid fixture");
        assert!(import_file(&invalid).is_err());
        assert!(import_file(&dir.join("missing.ovpn")).is_err());
        std::fs::write(&invalid, [0xff, 0xfe]).expect("write non-UTF-8 fixture");
        assert!(import_file(&invalid).is_err());
        std::fs::remove_dir_all(dir).expect("remove temporary directory");
    }
}
