//! Clash.Meta / Mihomo JSON configuration.

use super::{cipher, comma_list, listen, put_nonempty, validate};
use crate::profile::{
    CoreKind, Network, Profile, Protocol, ProxyMode, RoutingMode, RuleAction, RuleKind,
    Security, Settings,
};
use crate::rules::RuleEntries;
use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

pub fn build(p: &Profile, s: &Settings) -> Result<Value> {
    build_with(p, s, &crate::rules::effective_entries(s))
}

pub fn build_with(p: &Profile, s: &Settings, entries: &RuleEntries) -> Result<Value> {
    let protocol = validate(CoreKind::Mihomo, p, s)?;
    let stats_port = s.mixed_port.checked_add(2).context("stats port overflows u16")?;
    let proxy = proxy(p, protocol)?;
    let tun = s.mode == ProxyMode::Tun;
    let mut rules = Vec::<String>::new();
    for rule in s.rules.iter().filter(|r| r.enabled && !r.value.trim().is_empty()) {
        let value = rule.value.trim();
        let kind = match rule.kind {
            RuleKind::Domain => "DOMAIN",
            RuleKind::DomainSuffix => "DOMAIN-SUFFIX",
            RuleKind::DomainKeyword => "DOMAIN-KEYWORD",
            RuleKind::IpCidr if value.contains(':') => "IP-CIDR6",
            RuleKind::IpCidr => "IP-CIDR",
            RuleKind::Process if tun => "PROCESS-NAME",
            RuleKind::Process => continue,
        };
        let action = match rule.action {
            RuleAction::Proxy => "proxy",
            RuleAction::Direct => "DIRECT",
            RuleAction::Block => "REJECT",
        };
        let suffix = if rule.kind == RuleKind::IpCidr { ",no-resolve" } else { "" };
        rules.push(format!("{kind},{value},{action}{suffix}"));
    }
    if !entries.is_empty() { rules.push("RULE-SET,bypass,DIRECT".into()); }
    let legacy = crate::rules::legacy_iran(s, entries);
    if legacy {
        rules.push("DOMAIN-SUFFIX,ir,DIRECT".into());
        rules.push("GEOIP,IR,DIRECT".into());
    }
    if s.routing != RoutingMode::Global {
        rules.push("GEOIP,LAN,DIRECT,no-resolve".into());
    }
    if tun { rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".into()); }
    rules.push(if super::final_tag(s) == "direct" { "MATCH,DIRECT" } else { "MATCH,proxy" }.into());

    if s.remote_dns.is_empty() || s.direct_dns.is_empty() {
        bail!("DNS resolvers must not be empty");
    }
    let remote = resolver_detour(&s.remote_dns, "proxy");
    let direct = resolver_detour(&s.direct_dns, "DIRECT");
    let mut policy = Map::new();
    policy.insert(p.address.clone(), json!([direct]));
    if s.routing != RoutingMode::Global {
        policy.insert("+.local".into(), json!([direct]));
        policy.insert("+.localhost".into(), json!([direct]));
    }
    for suffix in &entries.suffixes {
        policy.insert(format!("+.{suffix}"), json!([direct]));
    }
    for domain in &entries.full {
        policy.insert(domain.clone(), json!([direct]));
    }
    if legacy { policy.insert("+.ir".into(), json!([direct])); }
    let mut dns = json!({
        "enable":true,"ipv6":!tun,
        "enhanced-mode":if tun {"fake-ip"} else {"redir-host"},
        "nameserver":[remote],"proxy-server-nameserver":[s.direct_dns],
        "direct-nameserver":[direct],"direct-nameserver-follow-policy":true,
        "nameserver-policy":policy
    });
    if tun {
        dns["fake-ip-range"] = json!("198.18.0.1/16");
        dns["fake-ip-filter"] = json!(["*.lan","*.local","localhost"]);
    }
    let level = match s.log_level.as_str() {
        "warn" => "warning", "trace" => "debug", "none" | "off" => "silent", other => other,
    };
    let mut config = json!({
        "mixed-port":s.mixed_port,"external-controller":format!("127.0.0.1:{stats_port}"),
        "allow-lan":s.allow_lan,"bind-address":listen(s),"mode":"rule",
        "log-level":level,"ipv6":!tun,
        "sniffer":{
            "enable":true,
            "sniff":{
                "HTTP":{"ports":[80,"8080-8880"],"override-destination":true},
                "TLS":{"ports":[443,8443]},"QUIC":{"ports":[443,8443]}
            }
        },
        "dns":dns,"proxies":[proxy],"rules":rules
    });
    if !entries.is_empty() {
        config["rule-providers"] = json!({
            "bypass":{
                "type":"file","behavior":"classical","format":"text",
                "path":super::bypass_path("mihomo", CoreKind::Mihomo)
            }
        });
    }
    if tun {
        config["find-process-mode"] = json!("always");
        config["tun"] = json!({
            "enable":true,"stack":"mixed","auto-route":true,
            "auto-detect-interface":true,"dns-hijack":["any:53"]
        });
    }
    Ok(config)
}

fn resolver_detour(resolver: &str, detour: &str) -> String {
    format!("{resolver}{}{detour}", if resolver.contains('#') {"&"} else {"#"})
}

fn proxy(p: &Profile, protocol: Protocol) -> Result<Value> {
    let mut out = json!({
        "name":"proxy","server":p.address.trim_matches(['[', ']']),"port":p.port
    });
    match protocol {
        Protocol::Vmess => {
            out["type"] = json!("vmess");
            out["uuid"] = json!(p.uuid);
            out["alterId"] = json!(p.alter_id);
            out["cipher"] = json!(cipher(p));
            out["udp"] = json!(true);
        }
        Protocol::Vless => {
            out["type"] = json!("vless");
            out["uuid"] = json!(p.uuid);
            out["udp"] = json!(true);
            if !p.flow.is_empty() { out["flow"] = json!(p.flow); }
        }
        Protocol::Trojan => {
            out["type"] = json!("trojan");
            out["password"] = json!(p.password);
            out["udp"] = json!(true);
        }
        Protocol::Shadowsocks => {
            out["type"] = json!("ss");
            out["cipher"] = json!(p.method);
            out["password"] = json!(p.password);
            out["udp"] = json!(true);
            if !p.plugin.is_empty() {
                let (name, opts) = plugin(p)?;
                out["plugin"] = json!(name);
                out["plugin-opts"] = opts;
            }
        }
        Protocol::Socks | Protocol::Http => {
            out["type"] = json!(if protocol == Protocol::Socks {"socks5"} else {"http"});
            if protocol == Protocol::Socks { out["udp"] = json!(true); }
            if !p.username.is_empty() || !p.password.is_empty() {
                out["username"] = json!(p.username);
                out["password"] = json!(p.password);
            }
        }
        Protocol::Ssh => {
            out["type"] = json!("ssh");
            out["username"] = json!(p.username);
            out["password"] = json!(p.password);
            if !p.ssh_private_key.is_empty() { out["private-key"] = json!(p.ssh_private_key); }
            if !p.ssh_private_key_passphrase.is_empty() {
                out["private-key-passphrase"] = json!(p.ssh_private_key_passphrase);
            }
            if !p.ssh_host_key.is_empty() { out["host-key"] = json!(p.ssh_host_key); }
        }
        Protocol::AnyTls => {
            out["type"] = json!("anytls");
            out["password"] = json!(p.password);
        }
        Protocol::Hysteria | Protocol::Hysteria2 => {
            let v1 = protocol == Protocol::Hysteria;
            out["type"] = json!(if v1 {"hysteria"} else {"hysteria2"});
            out[if v1 {"auth-str"} else {"password"}] = json!(p.password);
            if !p.obfs.is_empty() {
                out["obfs"] = json!(p.obfs);
                if !v1 { out["obfs-password"] = json!(p.obfs_password); }
            }
            if p.up_mbps != 0 { out["up"] = json!(format!("{} Mbps", p.up_mbps)); }
            if p.down_mbps != 0 { out["down"] = json!(format!("{} Mbps", p.down_mbps)); }
        }
        Protocol::Tuic => {
            out["type"] = json!("tuic");
            out["uuid"] = json!(p.uuid);
            out["password"] = json!(p.password);
            if !p.congestion_control.is_empty() {
                out["congestion-controller"] = json!(p.congestion_control);
            }
            out["udp-relay-mode"] = json!("native");
        }
        Protocol::Wireguard => {
            if !p.reserved.is_empty() && p.reserved.len() != 3 {
                bail!("WireGuard reserved must contain exactly three bytes");
            }
            out["type"] = json!("wireguard");
            out["private-key"] = json!(p.private_key);
            out["public-key"] = json!(p.public_key);
            out["udp"] = json!(true);
            out["remote-dns-resolve"] = json!(false);
            if p.local_address.is_empty() {
                bail!("WireGuard requires at least one local address");
            }
            for address in &p.local_address {
                let ip = address.split('/').next().context("empty WireGuard address")?;
                let parsed: std::net::IpAddr = ip.parse().context("invalid WireGuard local address")?;
                out[if parsed.is_ipv4() {"ip"} else {"ipv6"}] = json!(ip);
            }
            if !p.pre_shared_key.is_empty() { out["pre-shared-key"] = json!(p.pre_shared_key); }
            if !p.reserved.is_empty() { out["reserved"] = json!(p.reserved); }
            if p.mtu != 0 { out["mtu"] = json!(p.mtu); }
            return Ok(out);
        }
        Protocol::OpenVpn => bail!("Mihomo does not support OpenVPN"),
        Protocol::Custom => bail!("custom configurations must be built through config::build"),
    }
    let tls_required = matches!(protocol,
        Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria | Protocol::Hysteria2 | Protocol::Tuic);
    if p.tls.security != Security::None || tls_required {
        if protocol == Protocol::Shadowsocks {
            bail!("Mihomo Shadowsocks TLS must be configured through a plugin");
        }
        if protocol == Protocol::Ssh { bail!("Mihomo SSH does not support native TLS"); }
        if matches!(protocol, Protocol::Vmess | Protocol::Vless | Protocol::Http | Protocol::Socks) {
            out["tls"] = json!(true);
        }
        out["skip-cert-verify"] = json!(p.tls.allow_insecure);
        if !p.tls.sni.is_empty() {
            out[if matches!(protocol, Protocol::Vmess | Protocol::Vless) {"servername"} else {"sni"}]
                = json!(p.tls.sni);
        }
        if !p.tls.alpn.is_empty() { out["alpn"] = json!(p.tls.alpn); }
        if !p.tls.fingerprint.is_empty() || p.tls.security == Security::Reality {
            out["client-fingerprint"] = json!(
                if p.tls.fingerprint.is_empty() {"chrome"} else {&p.tls.fingerprint});
        }
        if p.tls.security == Security::Reality {
            if protocol != Protocol::Vless { bail!("Mihomo REALITY requires VLESS"); }
            out["reality-opts"] = json!({
                "public-key":p.tls.reality_public_key,"short-id":p.tls.reality_short_id
            });
        }
    }
    if matches!(protocol, Protocol::Vmess | Protocol::Vless | Protocol::Trojan) {
        transport(&mut out, p)?;
    } else if p.transport.network != Network::Tcp {
        bail!("Mihomo {:?} does not support a V2Ray transport", protocol);
    }
    Ok(out)
}

fn transport(out: &mut Value, p: &Profile) -> Result<()> {
    let t = &p.transport;
    match t.network {
        Network::Tcp if t.header_type != "http" => {}
        Network::Tcp => {
            out["network"] = json!("http");
            let mut opts = json!({
                "method":"GET","path":if t.path.is_empty() {vec!["/"]} else {comma_list(&t.path)}
            });
            if !t.host.is_empty() { opts["headers"] = json!({"Host":comma_list(&t.host)}); }
            out["http-opts"] = opts;
        }
        Network::Ws | Network::HttpUpgrade => {
            out["network"] = json!("ws");
            let mut opts = json!({"path":t.path});
            if !t.host.is_empty() { opts["headers"] = json!({"Host":t.host}); }
            if t.network == Network::HttpUpgrade { opts["v2ray-http-upgrade"] = json!(true); }
            out["ws-opts"] = opts;
        }
        Network::Grpc => {
            out["network"] = json!("grpc");
            out["grpc-opts"] = json!({"grpc-service-name":t.service_name});
        }
        Network::H2 => {
            out["network"] = json!("h2");
            out["h2-opts"] = json!({"host":comma_list(&t.host),"path":t.path});
        }
        Network::Xhttp | Network::Kcp | Network::Quic =>
            bail!("Mihomo does not support the {:?} V2Ray transport", t.network),
    }
    Ok(())
}

fn plugin(p: &Profile) -> Result<(&'static str, Value)> {
    let mut values = Map::new();
    for option in p.plugin_opts.split(';').filter(|v| !v.is_empty()) {
        let (key, value) = option.split_once('=').unwrap_or((option, ""));
        values.insert(key.to_owned(), json!(value));
    }
    match p.plugin.as_str() {
        "obfs" | "obfs-local" | "simple-obfs" => {
            let mut opts = Map::new();
            opts.insert("mode".into(),
                values.get("obfs").or_else(|| values.get("mode")).cloned().unwrap_or(json!("http")));
            if let Some(host) = values.get("obfs-host").or_else(|| values.get("host")) {
                opts.insert("host".into(), host.clone());
            }
            Ok(("obfs", Value::Object(opts)))
        }
        "v2ray-plugin" => {
            let mut opts = Map::new();
            opts.insert("mode".into(),
                json!(values.get("mode").and_then(Value::as_str).unwrap_or("websocket")));
            opts.insert("tls".into(), json!(values.contains_key("tls")));
            opts.insert("mux".into(), json!(values.contains_key("mux")));
            for key in ["host", "path"] {
                if let Some(value) = values.get(key).and_then(Value::as_str) {
                    put_nonempty(&mut opts, key, value);
                }
            }
            if !p.tls.fingerprint.is_empty() {
                opts.insert("fingerprint".into(), json!(p.tls.fingerprint));
            }
            if p.tls.allow_insecure { opts.insert("skip-cert-verify".into(), json!(true)); }
            Ok(("v2ray-plugin", Value::Object(opts)))
        }
        other => bail!("Mihomo does not support Shadowsocks plugin {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{routing_settings, samples};

    fn config(p: &Profile, s: &Settings) -> Result<Value> {
        build_with(p, s, &RuleEntries::default())
    }

    fn iran_settings() -> Settings {
        let mut s = Settings {
            routing: RoutingMode::BypassIran,
            ..Settings::default()
        };
        s.bypass.country = "ir".into();
        s
    }

    #[test]
    fn ordering_process_block_and_final() {
        let e = RuleEntries { suffixes: vec!["bypass.test".into()], ..Default::default() };
        for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
            let s = Settings { mode, ..routing_settings() };
            let v = build_with(&samples()[0], &s, &e).expect("config");
            let r = v["rules"].as_array().expect("rules");
            assert_eq!(r[0], "DOMAIN,first.test,REJECT");
            let next = if mode == ProxyMode::Tun {
                assert_eq!(r[1], "PROCESS-NAME,telegram.exe,proxy");
                2
            } else {
                assert!(!v.to_string().contains("telegram.exe"));
                1
            };
            assert_eq!(r[next], "DOMAIN-SUFFIX,second.test,DIRECT");
            assert_eq!(r[next + 1], "RULE-SET,bypass,DIRECT");
            assert_eq!(r[next + 2], "GEOIP,LAN,DIRECT,no-resolve");
            assert_eq!(r.last(), Some(&json!("MATCH,DIRECT")));
            assert_eq!(v["rule-providers"]["bypass"]["behavior"], "classical");
            assert!(!v.to_string().contains("disabled.test"));
        }
    }

    #[test]
    fn builds_sample_profiles() {
        for p in samples() {
            assert!(build(&p, &Settings::default()).is_ok());
        }
    }

    #[test]
    fn cidr_and_keyword_rules() {
        let mut s = Settings::default();
        s.rules = vec![
            crate::Rule { kind: RuleKind::IpCidr, value: "10.0.0.0/8".into(),
                action: RuleAction::Direct, ..Default::default() },
            crate::Rule { kind: RuleKind::DomainKeyword, value: "ads".into(),
                action: RuleAction::Block, ..Default::default() },
        ];
        let v = build_with(&samples()[0], &s, &RuleEntries::default()).expect("config");
        assert_eq!(v["rules"][0], "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
        assert_eq!(v["rules"][1], "DOMAIN-KEYWORD,ads,REJECT");
    }

    #[test]
    fn sample_protocols_and_transports() {
        let p = samples();
        let s = Settings::default();
        let v = config(&p[0], &s).expect("VLESS");
        assert_eq!(v["proxies"][0]["type"], "vless");
        assert_eq!(v["proxies"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(v["proxies"][0]["reality-opts"]["public-key"], "test-public-key");
        assert_eq!(v["mixed-port"], s.mixed_port);

        let v = config(&p[1], &s).expect("VMess");
        assert_eq!(v["proxies"][0]["network"], "ws");
        assert_eq!(v["proxies"][0]["tls"], true);
        assert_eq!(v["proxies"][0]["ws-opts"]["path"], "/websocket");
        let v = config(&p[2], &s).expect("Trojan");
        assert_eq!(v["proxies"][0]["grpc-opts"]["grpc-service-name"], "tunnel");
        let v = config(&p[3], &s).expect("Shadowsocks");
        assert_eq!(v["proxies"][0]["type"], "ss");
        assert_eq!(v["proxies"][0]["cipher"], "aes-128-gcm");
        let v = config(&p[4], &s).expect("Hysteria2");
        assert_eq!(v["proxies"][0]["obfs-password"], "obfs-secret");
        assert_eq!(v["proxies"][0]["up"], "20 Mbps");
    }

    #[test]
    fn hysteria_bandwidth_strings_and_zero_omission() {
        for protocol in [Protocol::Hysteria, Protocol::Hysteria2] {
            for (up_mbps, down_mbps) in [(0, 0), (20, 0), (0, 100), (20, 100)] {
                let p = Profile {
                    protocol: Some(protocol), address: "hysteria.example".into(),
                    port: 443, password: "secret".into(), up_mbps, down_mbps,
                    ..Profile::default()
                };
                let v = config(&p, &Settings::default()).expect("Hysteria configuration");
                let out = &v["proxies"][0];
                for (key, rate) in [("up", up_mbps), ("down", down_mbps)] {
                    if rate == 0 {
                        assert!(out.get(key).is_none(), "{protocol:?}: {key} must be omitted");
                    } else {
                        assert_eq!(out[key], json!(format!("{rate} Mbps")));
                    }
                }
            }
        }
    }

    #[test]
    fn httpupgrade_uses_websocket_options() {
        for mut p in samples().into_iter().take(3) {
            p.transport.network = Network::HttpUpgrade;
            p.transport.path = "/upgrade".into();
            p.transport.host = "cdn.example.com".into();
            let v = config(&p, &Settings::default()).expect("HTTPUpgrade");
            assert_eq!(v["proxies"][0]["network"], "ws");
            assert_eq!(v["proxies"][0]["ws-opts"], json!({
                "path":"/upgrade","headers":{"Host":"cdn.example.com"},
                "v2ray-http-upgrade":true
            }));
            p.transport.host.clear();
            let v = config(&p, &Settings::default()).expect("HTTPUpgrade without Host");
            assert_eq!(v["proxies"][0]["ws-opts"]["v2ray-http-upgrade"], true);
            assert!(v["proxies"][0]["ws-opts"].get("headers").is_none());
            p.transport.network = Network::Ws;
            let v = config(&p, &Settings::default()).expect("WebSocket");
            assert!(v["proxies"][0]["ws-opts"].get("v2ray-http-upgrade").is_none());
        }
    }

    #[test]
    fn routing_dns_tun_and_lan() {
        let s = Settings {
            mode: ProxyMode::Tun, allow_lan: true, ..iran_settings()
        };
        let v = config(&samples()[0], &s).expect("configuration");
        // v8 places country bypasses before private/LAN; retain the exact
        // rule assertion, including the TUN-only QUIC rejection before MATCH.
        assert_eq!(v["rules"], json!([
            "DOMAIN-SUFFIX,ir,DIRECT", "GEOIP,IR,DIRECT",
            "GEOIP,LAN,DIRECT,no-resolve",
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT", "MATCH,proxy"
        ]));
        assert_eq!(v["bind-address"], "0.0.0.0");
        assert_eq!(v["ipv6"], false);
        assert_eq!(v["dns"]["ipv6"], false);
        assert_eq!(v["dns"]["enhanced-mode"], "fake-ip");
        assert_eq!(v["dns"]["nameserver"][0], format!("{}#proxy", s.remote_dns));
        assert_eq!(v["dns"]["nameserver-policy"]["+.ir"][0], format!("{}#DIRECT", s.direct_dns));
        assert_eq!(v["tun"]["dns-hijack"][0], "any:53");

        let s = Settings { routing: RoutingMode::Global, ..Settings::default() };
        let v = config(&samples()[0], &s).expect("global configuration");
        assert_eq!(v["rules"], json!(["MATCH,proxy"]));
        assert!(v.get("tun").is_none());
        assert_eq!(v["ipv6"], true);
        assert_eq!(v["dns"]["ipv6"], true);
        assert_eq!(v["dns"]["enhanced-mode"], "redir-host");
    }

    #[test]
    fn mode_is_the_only_tun_switch() {
        for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
            for tun in [false, true] {
                let s = Settings { mode, tun, ..Settings::default() };
                let v = config(&samples()[0], &s).expect("configuration");
                assert_eq!(v.get("tun").is_some(), mode == ProxyMode::Tun);
                assert_eq!(
                    v["dns"]["enhanced-mode"],
                    if mode == ProxyMode::Tun { "fake-ip" } else { "redir-host" }
                );
                assert_eq!(v["ipv6"], mode != ProxyMode::Tun);
                assert_eq!(v["dns"]["ipv6"], mode != ProxyMode::Tun);
            }
        }
    }

    #[test]
    fn quic_rejection_is_tun_only_and_immediately_before_match() {
        let reject = json!("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT");
        for routing in [RoutingMode::Global, RoutingMode::BypassLan, RoutingMode::BypassIran] {
            for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
                let s = Settings { routing, mode, ..iran_settings() };
                let v = config(&samples()[0], &s).expect("configuration");
                let rules = v["rules"].as_array().expect("rules");
                assert_eq!(rules.last(), Some(&json!("MATCH,proxy")));
                if mode == ProxyMode::Tun {
                    assert_eq!(rules[rules.len() - 2], reject);
                    assert_eq!(rules.iter().filter(|rule| *rule == &reject).count(), 1);
                    assert_eq!(v["ipv6"], false);
                    assert_eq!(v["dns"]["ipv6"], false);
                } else {
                    assert!(!rules.contains(&reject));
                    assert_eq!(v["ipv6"], true);
                    assert_eq!(v["dns"]["ipv6"], true);
                }
            }
        }
    }

    #[test]
    fn shadowsocks_plugins() {
        let mut p = samples()[3].clone();
        p.plugin = "obfs-local".into();
        p.plugin_opts = "obfs=tls;obfs-host=cdn.example.com".into();
        let v = config(&p, &Settings::default()).expect("obfs");
        assert_eq!(v["proxies"][0]["plugin"], "obfs");
        assert_eq!(v["proxies"][0]["plugin-opts"]["mode"], "tls");
        p.plugin = "v2ray-plugin".into();
        p.plugin_opts = "tls;host=cdn.example.com;path=/ws;mux".into();
        let v = config(&p, &Settings::default()).expect("v2ray plugin");
        assert_eq!(v["proxies"][0]["plugin-opts"]["tls"], true);
        assert_eq!(v["proxies"][0]["plugin-opts"]["path"], "/ws");
    }

    #[test]
    fn wireguard_and_tuic() {
        let mut p = samples()[0].clone();
        p.protocol = Some(Protocol::Wireguard);
        p.local_address = vec!["10.0.0.2/32".into(), "fd00::2/128".into()];
        p.private_key = "private".into();
        p.public_key = "public".into();
        p.pre_shared_key = "shared".into();
        p.reserved = vec![1, 2, 3];
        let v = config(&p, &Settings::default()).expect("WireGuard");
        assert_eq!(v["proxies"][0]["ip"], "10.0.0.2");
        assert_eq!(v["proxies"][0]["ipv6"], "fd00::2");
        assert_eq!(v["proxies"][0]["pre-shared-key"], "shared");
        p.protocol = Some(Protocol::Tuic);
        p.tls.security = Security::Tls;
        p.congestion_control = "bbr".into();
        let v = config(&p, &Settings::default()).expect("TUIC");
        assert_eq!(v["proxies"][0]["congestion-controller"], "bbr");
    }

    #[test]
    fn ssh_credentials_and_optional_fields() {
        let mut p = Profile {
            protocol: Some(Protocol::Ssh),
            address: "ssh.example".into(),
            port: 22,
            username: "alice".into(),
            password: "secret".into(),
            ssh_private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n".into(),
            ssh_private_key_passphrase: "passphrase".into(),
            ssh_host_key: vec!["ssh-ed25519 key1".into(), "ssh-rsa key2".into()],
            ..Profile::default()
        };
        let v = config(&p, &Settings::default()).expect("SSH");
        let out = &v["proxies"][0];
        assert_eq!(out["type"], "ssh");
        assert_eq!(out["name"], "proxy");
        assert_eq!(out["server"], "ssh.example");
        assert_eq!(out["port"], 22);
        assert_eq!(out["username"], "alice");
        assert_eq!(out["password"], "secret");
        assert_eq!(out["private-key"], p.ssh_private_key);
        assert_eq!(out["private-key-passphrase"], "passphrase");
        assert_eq!(out["host-key"], json!(p.ssh_host_key));
        assert!(out.get("tls").is_none());
        p.ssh_private_key.clear();
        p.ssh_private_key_passphrase.clear();
        p.ssh_host_key.clear();
        let v = config(&p, &Settings::default()).expect("password-only SSH");
        for key in ["private-key", "private-key-passphrase", "host-key"] {
            assert!(v["proxies"][0].get(key).is_none());
        }
    }

    #[test]
    fn anytls_and_hysteria_v1() {
        let mut p = Profile {
            protocol: Some(Protocol::AnyTls),
            address: "tls.example".into(),
            port: 443,
            password: "secret".into(),
            ..Profile::default()
        };
        p.tls.sni = "sni.example".into();
        p.tls.allow_insecure = true;
        p.tls.fingerprint = "chrome".into();
        p.tls.alpn = vec!["h3".into()];
        let v = config(&p, &Settings::default()).expect("AnyTLS");
        let out = &v["proxies"][0];
        assert_eq!(out["type"], "anytls");
        assert_eq!(out["password"], "secret");
        assert_eq!(out["sni"], "sni.example");
        assert_eq!(out["skip-cert-verify"], true);
        assert_eq!(out["client-fingerprint"], "chrome");
        assert_eq!(out["alpn"], json!(["h3"]));

        p.protocol = Some(Protocol::Hysteria);
        p.obfs = "obfs-secret".into();
        p.up_mbps = 20;
        p.down_mbps = 100;
        let v = config(&p, &Settings::default()).expect("Hysteria v1");
        let out = &v["proxies"][0];
        assert_eq!(out["type"], "hysteria");
        assert_eq!(out["auth-str"], "secret");
        assert_eq!(out["obfs"], "obfs-secret");
        assert_eq!(out["up"], "20 Mbps");
        assert_eq!(out["down"], "100 Mbps");
        assert_eq!(out["sni"], "sni.example");
        assert_eq!(out["skip-cert-verify"], true);
        assert_eq!(out["alpn"], json!(["h3"]));
        assert!(out.get("password").is_none());
        assert!(out.get("network").is_none());
    }

    #[test]
    fn raw_profiles_require_public_dispatch() {
        for protocol in [Protocol::Custom, Protocol::OpenVpn] {
            let p = Profile {
                protocol: Some(protocol), address: "example.com".into(), port: 443,
                ..Profile::default()
            };
            assert!(config(&p, &Settings::default()).is_err());
        }
    }

    #[test]
    fn stats_endpoint_is_loopback_only() {
        for allow_lan in [false, true] {
            let s = Settings { allow_lan, mixed_port: 12000, ..Settings::default() };
            let v = config(&samples()[0], &s).expect("configuration");
            assert_eq!(v["external-controller"], "127.0.0.1:12002");
        }
        for mixed_port in [u16::MAX - 1, u16::MAX] {
            let s = Settings { mixed_port, ..Settings::default() };
            assert!(config(&samples()[0], &s).is_err());
        }
    }
}
