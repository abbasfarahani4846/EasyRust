//! Configuration generators and shared routing side files.

pub mod mihomo;
pub mod singbox;
pub mod xray;

use crate::profile::{CoreKind, Profile, Protocol, Settings};
use crate::rules::RuleEntries;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};
use std::path::Path;

/// Load cached bypass data and materialize any referenced side files before the
/// process manager spawns the core. Raw configurations never touch side files.
pub fn build(core: CoreKind, p: &Profile, s: &Settings) -> Result<String> {
    let entries = crate::rules::effective_entries(s);
    let text = build_with(core, p, s, &entries)?;
    if p.protocol != Some(Protocol::Custom) && !core.is_tunnel() {
        write_side_files(core, &run_dir(core.name()), &entries)?;
    }
    Ok(text)
}

/// Pure configuration generation with explicitly supplied bypass entries.
pub fn build_with(core: CoreKind, p: &Profile, s: &Settings, entries: &RuleEntries) -> Result<String> {
    if p.protocol == Some(Protocol::Custom) {
        if p.custom_core != Some(core) {
            bail!("custom configuration is not configured for {}", core.name());
        }
        return Ok(p.raw_config.clone());
    }
    if core == CoreKind::OpenVpn {
        if p.protocol != Some(Protocol::OpenVpn) {
            bail!("openvpn requires an OpenVPN profile");
        }
        if p.raw_config.trim().is_empty() {
            bail!("OpenVPN configuration must not be empty");
        }
        return Ok(p.raw_config.clone());
    }
    let value = match core {
        CoreKind::Xray => xray::build_with(p, s, entries)?,
        CoreKind::SingBox => singbox::build_with(p, s, entries)?,
        CoreKind::Mihomo => mihomo::build_with(p, s, entries)?,
        CoreKind::OpenVpn => unreachable!("OpenVPN handled above"),
    };
    serde_json::to_string_pretty(&value).context("serialize core configuration")
}

pub fn file_name(core: CoreKind) -> &'static str {
    match core {
        CoreKind::Xray | CoreKind::SingBox => "config.json",
        CoreKind::Mihomo => "config.yaml",
        CoreKind::OpenVpn => "config.ovpn",
    }
}

pub(crate) fn run_dir(name: &str) -> std::path::PathBuf {
    let path = crate::store::data_dir().join("run").join(name);
    // Generated configs use absolute paths because Xray's working directory is
    // its binary folder, not the run directory.
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir().unwrap_or_else(|_| ".".into()).join(path)
    }
}

pub(crate) fn bypass_path(name: &str, core: CoreKind) -> String {
    run_dir(name)
        .join(if core == CoreKind::Mihomo { "rules-bypass.txt" } else { "rules-bypass.json" })
        .to_string_lossy()
        .into_owned()
}

pub fn write_side_files(core: CoreKind, dir: &Path, entries: &RuleEntries) -> Result<()> {
    if entries.is_empty() || !matches!(core, CoreKind::SingBox | CoreKind::Mihomo) {
        return Ok(());
    }
    std::fs::create_dir_all(dir).context("creating routing side-file directory")?;
    let (name, text) = if core == CoreKind::SingBox {
        let mut rule = Map::new();
        for (key, values) in [
            ("domain_suffix", &entries.suffixes),
            ("domain", &entries.full),
            ("domain_keyword", &entries.keywords),
            ("ip_cidr", &entries.cidrs),
        ] {
            if !values.is_empty() {
                rule.insert(key.into(), json!(values));
            }
        }
        ("rules-bypass.json", serde_json::to_string_pretty(&json!({
            "version":3,"rules":[rule]
        }))?)
    } else {
        ("rules-bypass.txt", crate::rules::classical(entries))
    };
    std::fs::write(dir.join(name), text).context("writing bypass routing side file")
}

fn validate(core: CoreKind, p: &Profile, s: &Settings) -> Result<Protocol> {
    let protocol = p.protocol.context("profile has no protocol")?;
    if !core.supports(protocol) {
        bail!("{} does not support {:?}", core.name(), protocol);
    }
    if p.address.trim().is_empty() || p.port == 0 {
        bail!("profile must have a server address and a nonzero port");
    }
    if s.mixed_port == 0 {
        bail!("local proxy port must be nonzero");
    }
    if !s.allow_lan && s.listen.trim().is_empty() {
        bail!("local listen address must not be empty");
    }
    Ok(protocol)
}

fn listen(s: &Settings) -> &str {
    if s.allow_lan { "0.0.0.0" } else { &s.listen }
}

fn put_nonempty(map: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        map.insert(key.into(), Value::String(value.into()));
    }
}

fn comma_list(s: &str) -> Vec<&str> {
    s.split(',').map(str::trim).filter(|v| !v.is_empty()).collect()
}

fn cipher(p: &Profile) -> &str {
    if p.method.is_empty() { "auto" } else { &p.method }
}

fn dns_ip(address: &str) -> Option<String> {
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    let url = url::Url::parse(address).ok()?;
    url.host_str()?.trim_matches(['[', ']']).parse::<std::net::IpAddr>()
        .ok().map(|ip| ip.to_string())
}

pub(crate) fn final_tag(s: &Settings) -> &'static str {
    if s.default_route == crate::DefaultRoute::Direct { "direct" } else { "proxy" }
}

pub(crate) fn action_tag(action: crate::RuleAction) -> &'static str {
    match action {
        crate::RuleAction::Proxy => "proxy",
        crate::RuleAction::Direct => "direct",
        crate::RuleAction::Block => "block",
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{Network, Rule, RuleAction, RuleKind, Security};

    pub fn samples() -> Vec<Profile> {
        let base = Profile {
            name: "sample".into(), address: "server.example.com".into(), port: 443,
            uuid: "11111111-2222-4333-8444-555555555555".into(),
            password: "secret".into(), ..Profile::default()
        };
        let mut reality = base.clone();
        reality.protocol = Some(Protocol::Vless);
        reality.flow = "xtls-rprx-vision".into();
        reality.tls.security = Security::Reality;
        reality.tls.sni = "www.example.com".into();
        reality.tls.fingerprint = "chrome".into();
        reality.tls.reality_public_key = "test-public-key".into();
        reality.tls.reality_short_id = "abcd".into();
        reality.tls.reality_spider_x = "/".into();
        let mut vmess = base.clone();
        vmess.protocol = Some(Protocol::Vmess);
        vmess.method = "auto".into();
        vmess.transport.network = Network::Ws;
        vmess.transport.path = "/websocket".into();
        vmess.transport.host = "cdn.example.com".into();
        vmess.tls.security = Security::Tls;
        vmess.tls.sni = "cdn.example.com".into();
        vmess.tls.alpn = vec!["http/1.1".into()];
        let mut trojan = base.clone();
        trojan.protocol = Some(Protocol::Trojan);
        trojan.transport.network = Network::Grpc;
        trojan.transport.service_name = "tunnel".into();
        trojan.tls.security = Security::Tls;
        let mut ss = base.clone();
        ss.protocol = Some(Protocol::Shadowsocks);
        ss.method = "aes-128-gcm".into();
        let mut hy = base;
        hy.protocol = Some(Protocol::Hysteria2);
        hy.tls.security = Security::Tls;
        hy.obfs = "salamander".into();
        hy.obfs_password = "obfs-secret".into();
        hy.up_mbps = 20;
        hy.down_mbps = 100;
        vec![reality, vmess, trojan, ss, hy]
    }

    pub fn routing_settings() -> Settings {
        Settings {
            rules: vec![
                Rule { kind: RuleKind::Domain, value: "first.test".into(),
                    action: RuleAction::Block, ..Rule::default() },
                Rule { kind: RuleKind::Process, value: "telegram.exe".into(),
                    action: RuleAction::Proxy, ..Rule::default() },
                Rule { kind: RuleKind::DomainSuffix, value: "second.test".into(),
                    action: RuleAction::Direct, ..Rule::default() },
                Rule { enabled: false, value: "disabled.test".into(), ..Rule::default() },
            ],
            default_route: crate::DefaultRoute::Direct,
            ..Settings::default()
        }
    }

    #[test]
    fn dispatch_samples_and_stats() {
        for core in [CoreKind::Xray, CoreKind::SingBox, CoreKind::Mihomo] {
            for p in samples() {
                if core.supports(p.protocol.expect("protocol")) {
                    let text = build_with(core, &p, &Settings::default(), &RuleEntries::default())
                        .expect("config");
                    assert!(text.contains("127.0.0.1:10810"));
                }
            }
        }
    }

    #[test]
    fn raw_configs_preserve_text() {
        for core in [CoreKind::Xray, CoreKind::SingBox, CoreKind::Mihomo] {
            let p = Profile { protocol: Some(Protocol::Custom), custom_core: Some(core),
                raw_config: " raw\n".into(), ..Profile::default() };
            assert_eq!(build_with(core, &p, &Settings::default(), &RuleEntries::default())
                .expect("custom"), " raw\n");
        }
        let p = Profile { protocol: Some(Protocol::OpenVpn), raw_config: "client\n".into(),
            ..Profile::default() };
        assert_eq!(build_with(CoreKind::OpenVpn, &p, &Settings::default(), &RuleEntries::default())
            .expect("openvpn"), "client\n");
        assert!(build_with(CoreKind::Xray, &Profile::default(), &Settings::default(),
            &RuleEntries::default()).is_err());
    }

    #[test]
    fn side_files_have_expected_formats() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("easyvpn-rules-{}", crate::store::new_id()));
        let e = RuleEntries {
            suffixes: vec!["example.ir".into()], cidrs: vec!["10.0.0.0/8".into()],
            ..Default::default()
        };
        write_side_files(CoreKind::SingBox, &dir, &e)?;
        let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("rules-bypass.json"))?)?;
        assert_eq!(v["version"], 3);
        assert_eq!(v["rules"][0]["domain_suffix"], json!(["example.ir"]));
        write_side_files(CoreKind::Mihomo, &dir, &e)?;
        let text = std::fs::read_to_string(dir.join("rules-bypass.txt"))?;
        assert!(text.contains("DOMAIN-SUFFIX,example.ir"));
        assert!(text.contains("IP-CIDR,10.0.0.0/8,no-resolve"));
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}
