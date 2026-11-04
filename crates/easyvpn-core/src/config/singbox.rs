//! sing-box 1.12+ configuration.

use super::{cipher, comma_list, listen, put_nonempty, validate};
use crate::profile::{
    CoreKind, Network, Profile, Protocol, ProxyMode, RoutingMode, RuleAction, RuleKind,
    Security, Settings,
};
use crate::rules::RuleEntries;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::net::IpAddr;
use url::Url;

pub fn build(p: &Profile, s: &Settings) -> Result<Value> {
    build_with(p, s, &crate::rules::effective_entries(s))
}

pub fn build_with(p: &Profile, s: &Settings, entries: &RuleEntries) -> Result<Value> {
    let protocol = validate(CoreKind::SingBox, p, s)?;
    let stats_port = s.mixed_port.checked_add(2).context("stats port overflows u16")?;
    let proxy = outbound(p, protocol)?;
    let tun = s.mode == ProxyMode::Tun;
    let mut inbounds = vec![json!({
        "type":"mixed","tag":"mixed-in","listen":listen(s),"listen_port":s.mixed_port
    })];
    if tun { inbounds.push(tun_inbound()); }
    let mut rules = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
    ];
    if tun { rules.extend(tun_reject_rules()); }
    append_user_rules(&mut rules, s, tun);
    let mut route = json!({
        "auto_detect_interface":true,
        "default_domain_resolver":{"server":"direct"},
        "final":super::final_tag(s)
    });
    append_bypass(&mut route, &mut rules, s, entries, "sing-box");
    if s.routing != RoutingMode::Global {
        rules.push(json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
    }
    route["rules"] = json!(rules);
    if tun { route["find_process"] = json!(true); }

    let mut dns_rules = vec![json!({
        "domain":[p.address],"action":"route","server":"direct"
    })];
    if s.routing != RoutingMode::Global {
        dns_rules.push(json!({
            "domain_suffix":["local","localhost"],"action":"route","server":"direct"
        }));
    }
    if !entries.suffixes.is_empty() {
        dns_rules.push(json!({"domain_suffix":entries.suffixes,"action":"route","server":"direct"}));
    }
    if !entries.full.is_empty() {
        dns_rules.push(json!({"domain":entries.full,"action":"route","server":"direct"}));
    }
    if crate::rules::legacy_iran(s, entries) {
        dns_rules.push(json!({"domain_suffix":["ir"],"action":"route","server":"direct"}));
    }
    let mut config = json!({
        "log":{"level":log_level(s)},
        "experimental":{"clash_api":{"external_controller":format!("127.0.0.1:{stats_port}")}},
        "dns":{
            "servers":[dns_server(&s.remote_dns,"remote","proxy")?,
                       dns_server(&s.direct_dns,"direct","direct")?],
            "rules":dns_rules,"final":"remote",
            "strategy":if tun {"ipv4_only"} else {"prefer_ipv4"}
        },
        "inbounds":inbounds,"route":route
    });
    if protocol == Protocol::Wireguard {
        config["endpoints"] = json!([proxy]);
        config["outbounds"] = json!([{"type":"direct","tag":"direct"}]);
    } else {
        config["outbounds"] = json!([proxy,{"type":"direct","tag":"direct"}]);
    }
    Ok(config)
}

fn append_user_rules(rules: &mut Vec<Value>, s: &Settings, processes: bool) {
    for rule in s.rules.iter().filter(|r| r.enabled && !r.value.trim().is_empty()) {
        let key = match rule.kind {
            RuleKind::Domain => "domain",
            RuleKind::DomainSuffix => "domain_suffix",
            RuleKind::DomainKeyword => "domain_keyword",
            RuleKind::IpCidr => "ip_cidr",
            RuleKind::Process if processes => "process_name",
            RuleKind::Process => continue,
        };
        let mut value = json!({});
        value[key] = json!([rule.value.trim()]);
        if rule.action == RuleAction::Block {
            value["action"] = json!("reject");
        } else {
            value["action"] = json!("route");
            value["outbound"] = json!(super::action_tag(rule.action));
        }
        rules.push(value);
    }
}

fn append_bypass(
    route: &mut Value,
    rules: &mut Vec<Value>,
    s: &Settings,
    entries: &RuleEntries,
    run_name: &str,
) {
    let mut sets = Vec::new();
    if !entries.is_empty() {
        sets.push(json!({
            "type":"local","tag":"bypass","format":"source",
            "path":super::bypass_path(run_name, CoreKind::SingBox)
        }));
        rules.push(json!({"rule_set":["bypass"],"action":"route","outbound":"direct"}));
    }
    if crate::rules::legacy_iran(s, entries) {
        rules.push(json!({"domain_suffix":["ir"],"action":"route","outbound":"direct"}));
        rules.push(json!({"rule_set":["geoip-ir"],"action":"route","outbound":"direct"}));
        sets.push(json!({
            "type":"remote","tag":"geoip-ir","format":"binary",
            "url":"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs",
            "download_detour":"proxy"
        }));
    }
    if !sets.is_empty() { route["rule_set"] = json!(sets); }
}

fn log_level(s: &Settings) -> &str {
    match s.log_level.as_str() {
        "warning" => "warn",
        "off" | "none" => "fatal",
        other => other,
    }
}

fn tun_inbound() -> Value {
    json!({
        "type":"tun","tag":"tun-in","address":["172.19.0.1/30"],
        "auto_route":true,"strict_route":true,"stack":"mixed"
    })
}

fn tun_reject_rules() -> [Value; 2] {
    [
        json!({"ip_version":6,"action":"reject"}),
        json!({"network":"udp","port":443,"action":"reject"}),
    ]
}

/// Compatibility entry point used by Connection. Materializes the helper's own
/// source rule-set before returning a config that references it. A write failure
/// leaves a missing/invalid rule-set, causing sing-box to fail startup rather
/// than silently bypassing the requested policy.
pub fn tun_helper(
    s: &Settings,
    socks_port: u16,
    server_host: &str,
    server_ips: &[IpAddr],
) -> Value {
    let entries = crate::rules::effective_entries(s);
    let mut config = tun_helper_with(s, socks_port, server_host, server_ips, &entries);
    if let Err(error) = super::write_side_files(
        CoreKind::SingBox, &super::run_dir("sing-box-tun"), &entries,
    ) {
        // This entry point predates Result. Force a clear startup failure rather
        // than using an older rule-set after a failed refresh.
        config["route"]["rule_set"] = json!([{
            "type":"local","tag":"bypass","format":"source",
            "path":format!("{}-write-failed-{}", super::bypass_path("sing-box-tun", CoreKind::SingBox),
                           crate::store::new_id())
        }]);
        eprintln!("writing sing-box TUN bypass rules: {error:#}");
    }
    config
}

/// Pure helper generator, including user process rules in their original order.
pub fn tun_helper_with(
    s: &Settings,
    socks_port: u16,
    server_host: &str,
    server_ips: &[IpAddr],
    entries: &RuleEntries,
) -> Value {
    let server_host = server_host.trim_matches(['[', ']']);
    let server_cidrs: Vec<String> = server_ips.iter()
        .map(|ip| format!("{ip}/{}", if ip.is_ipv4() {32} else {128})).collect();
    let direct_dns = s.direct_dns.parse::<IpAddr>().map(|ip| ip.to_string())
        .unwrap_or_else(|_| "8.8.8.8".into());
    let mut inbound = tun_inbound();
    inbound["route_exclude_address"] = json!(server_cidrs);
    let mut dns_rules = Vec::new();
    if !server_host.is_empty() && server_host.parse::<IpAddr>().is_err() {
        dns_rules.push(json!({"domain":[server_host],"action":"route","server":"direct"}));
    }
    dns_rules.push(json!({
        "domain_suffix":["local","localhost"],"action":"route","server":"direct"
    }));
    let mut rules = vec![
        json!({"action":"sniff"}),
        json!({"protocol":"dns","action":"hijack-dns"}),
        json!({"process_name":["xray.exe","xray"],"action":"route","outbound":"direct"}),
    ];
    if !server_cidrs.is_empty() {
        rules.push(json!({"ip_cidr":server_cidrs,"action":"route","outbound":"direct"}));
    }
    rules.extend(tun_reject_rules());
    append_user_rules(&mut rules, s, true);
    let mut route = json!({
        "final":super::final_tag(s),"auto_detect_interface":true,
        "find_process":true,"default_domain_resolver":{"server":"direct"}
    });
    append_bypass(&mut route, &mut rules, s, entries, "sing-box-tun");
    rules.push(json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
    route["rules"] = json!(rules);
    json!({
        "log":{"level":log_level(s)},
        "inbounds":[inbound],
        "outbounds":[
            {"type":"socks","tag":"proxy","server":"127.0.0.1","server_port":socks_port,"version":"5"},
            {"type":"direct","tag":"direct"}
        ],
        "dns":{
            "servers":[
                {"type":"https","tag":"remote","server":"1.1.1.1","detour":"proxy"},
                {"type":"udp","tag":"direct","server":direct_dns}
            ],
            "rules":dns_rules,"final":"remote","strategy":"ipv4_only"
        },
        "route":route
    })
}

fn dns_server(address: &str, tag: &str, detour: &str) -> Result<Value> {
    if address.is_empty() { bail!("DNS resolver must not be empty"); }
    if address == "local" || address == "localhost" {
        let mut value = json!({"type":"local","tag":tag});
        if detour != "direct" { value["detour"] = json!(detour); }
        return Ok(value);
    }
    let url = if address.contains("://") {
        Url::parse(address).context("invalid DNS resolver URL")?
    } else {
        let host = if address.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{address}]")
        } else { address.to_owned() };
        Url::parse(&format!("udp://{host}")).context("invalid DNS resolver address")?
    };
    let kind = match url.scheme() {
        "udp" => "udp", "tcp" => "tcp", "tls" => "tls", "https" => "https", "quic" => "quic",
        other => bail!("unsupported sing-box DNS scheme: {other}"),
    };
    let server = url.host_str().context("DNS resolver has no host")?.trim_matches(['[', ']']);
    let mut value = json!({"type":kind,"tag":tag,"server":server});
    if detour != "direct" { value["detour"] = json!(detour); }
    if let Some(port) = url.port() { value["server_port"] = json!(port); }
    if kind == "https" {
        let mut path = if url.path().is_empty() || url.path() == "/" {
            "/dns-query".to_owned()
        } else { url.path().to_owned() };
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
        value["path"] = json!(path);
    }
    if server.parse::<IpAddr>().is_err() {
        if tag == "direct" {
            bail!("sing-box direct DNS must use an IP address (or 'local')");
        }
        value["domain_resolver"] = json!("direct");
    }
    Ok(value)
}

fn outbound(p: &Profile, protocol: Protocol) -> Result<Value> {
    if protocol == Protocol::Wireguard {
        if !p.reserved.is_empty() && p.reserved.len() != 3 {
            bail!("WireGuard reserved must contain exactly three bytes");
        }
        let mut peer = json!({
            "address":p.address.trim_matches(['[', ']']),"port":p.port,
            "public_key":p.public_key,"allowed_ips":["0.0.0.0/0","::/0"]
        });
        if !p.pre_shared_key.is_empty() { peer["pre_shared_key"] = json!(p.pre_shared_key); }
        if !p.reserved.is_empty() { peer["reserved"] = json!(p.reserved); }
        let mut endpoint = json!({
            "type":"wireguard","tag":"proxy","system":false,
            "address":p.local_address,"private_key":p.private_key,"peers":[peer]
        });
        if p.mtu != 0 { endpoint["mtu"] = json!(p.mtu); }
        return Ok(endpoint);
    }
    let mut out = json!({
        "tag":"proxy","server":p.address.trim_matches(['[', ']']),"server_port":p.port
    });
    match protocol {
        Protocol::Vmess => {
            out["type"] = json!("vmess");
            out["uuid"] = json!(p.uuid);
            out["security"] = json!(cipher(p));
            out["alter_id"] = json!(p.alter_id);
        }
        Protocol::Vless => {
            out["type"] = json!("vless");
            out["uuid"] = json!(p.uuid);
            if !p.flow.is_empty() { out["flow"] = json!(p.flow); }
        }
        Protocol::Trojan => {
            out["type"] = json!("trojan");
            out["password"] = json!(p.password);
        }
        Protocol::Shadowsocks => {
            out["type"] = json!("shadowsocks");
            out["method"] = json!(p.method);
            out["password"] = json!(p.password);
            if !p.plugin.is_empty() {
                out["plugin"] = json!(p.plugin);
                out["plugin_opts"] = json!(p.plugin_opts);
            }
        }
        Protocol::Socks | Protocol::Http => {
            out["type"] = json!(if protocol == Protocol::Socks {"socks"} else {"http"});
            if protocol == Protocol::Socks { out["version"] = json!("5"); }
            if !p.username.is_empty() || !p.password.is_empty() {
                out["username"] = json!(p.username);
                out["password"] = json!(p.password);
            }
        }
        Protocol::Ssh => {
            out["type"] = json!("ssh");
            out["user"] = json!(p.username);
            out["password"] = json!(p.password);
            for (key, value) in [
                ("private_key", &p.ssh_private_key),
                ("private_key_passphrase", &p.ssh_private_key_passphrase),
                ("client_version", &p.ssh_client_version),
            ] {
                if !value.is_empty() { out[key] = json!(value); }
            }
            if !p.ssh_host_key.is_empty() { out["host_key"] = json!(p.ssh_host_key); }
        }
        Protocol::AnyTls => {
            out["type"] = json!("anytls");
            out["password"] = json!(p.password);
        }
        Protocol::Hysteria => {
            out["type"] = json!("hysteria");
            out["auth_str"] = json!(p.password);
            if !p.obfs.is_empty() { out["obfs"] = json!(p.obfs); }
            if p.up_mbps != 0 { out["up_mbps"] = json!(p.up_mbps); }
            if p.down_mbps != 0 { out["down_mbps"] = json!(p.down_mbps); }
        }
        Protocol::Hysteria2 => {
            out["type"] = json!("hysteria2");
            out["password"] = json!(p.password);
            if p.up_mbps != 0 { out["up_mbps"] = json!(p.up_mbps); }
            if p.down_mbps != 0 { out["down_mbps"] = json!(p.down_mbps); }
            if !p.obfs.is_empty() {
                out["obfs"] = json!({"type":p.obfs,"password":p.obfs_password});
            }
        }
        Protocol::Tuic => {
            out["type"] = json!("tuic");
            out["uuid"] = json!(p.uuid);
            out["password"] = json!(p.password);
            if !p.congestion_control.is_empty() {
                out["congestion_control"] = json!(p.congestion_control);
            }
        }
        Protocol::Wireguard => unreachable!("WireGuard handled above"),
        Protocol::OpenVpn => bail!("sing-box does not support OpenVPN"),
        Protocol::Custom => bail!("custom configurations must be built through config::build"),
    }
    let tls_required = matches!(protocol,
        Protocol::Trojan | Protocol::AnyTls | Protocol::Hysteria | Protocol::Hysteria2 | Protocol::Tuic);
    if p.tls.security != Security::None || tls_required {
        if matches!(protocol, Protocol::Socks | Protocol::Shadowsocks | Protocol::Ssh) {
            bail!("sing-box {:?} outbound does not support native TLS", protocol);
        }
        out["tls"] = tls(p)?;
    }
    if matches!(protocol, Protocol::Vmess | Protocol::Vless | Protocol::Trojan) {
        if let Some(transport) = transport(p)? { out["transport"] = transport; }
    } else if p.transport.network != Network::Tcp {
        bail!("sing-box {:?} does not support a V2Ray transport", protocol);
    }
    Ok(out)
}

fn tls(p: &Profile) -> Result<Value> {
    let mut tls = json!({"enabled":true,"insecure":p.tls.allow_insecure});
    let obj = tls.as_object_mut().context("TLS settings must be an object")?;
    put_nonempty(obj, "server_name", &p.tls.sni);
    if !p.tls.alpn.is_empty() { tls["alpn"] = json!(p.tls.alpn); }
    if !p.tls.fingerprint.is_empty() || p.tls.security == Security::Reality {
        tls["utls"] = json!({
            "enabled":true,
            "fingerprint":if p.tls.fingerprint.is_empty() {"chrome"} else {&p.tls.fingerprint}
        });
    }
    if p.tls.security == Security::Reality {
        tls["reality"] = json!({
            "enabled":true,"public_key":p.tls.reality_public_key,"short_id":p.tls.reality_short_id
        });
    }
    Ok(tls)
}

fn transport(p: &Profile) -> Result<Option<Value>> {
    let t = &p.transport;
    Ok(match t.network {
        Network::Tcp if t.header_type != "http" => None,
        Network::Tcp | Network::H2 => {
            let mut http = json!({"type":"http","path":if t.path.is_empty() {"/"} else {&t.path}});
            if !t.host.is_empty() { http["host"] = json!(comma_list(&t.host)); }
            if t.network == Network::Tcp { http["method"] = json!("GET"); }
            Some(http)
        }
        Network::Ws => {
            let mut ws = json!({"type":"ws","path":t.path});
            if !t.host.is_empty() { ws["headers"] = json!({"Host":t.host}); }
            Some(ws)
        }
        Network::Grpc => Some(json!({"type":"grpc","service_name":t.service_name})),
        Network::HttpUpgrade => {
            let mut upgrade = json!({"type":"httpupgrade","path":t.path});
            if !t.host.is_empty() { upgrade["host"] = json!(t.host); }
            Some(upgrade)
        }
        Network::Xhttp | Network::Kcp | Network::Quic =>
            bail!("sing-box does not support the {:?} V2Ray transport", t.network),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{routing_settings, samples};

    // Keep regression tests independent of downloaded rules and the user's store.
    fn config(p: &Profile, s: &Settings) -> Result<Value> {
        build_with(p, s, &RuleEntries::default())
    }

    fn helper(s: &Settings, port: u16, host: &str, ips: &[IpAddr]) -> Value {
        tun_helper_with(s, port, host, ips, &RuleEntries::default())
    }

    fn iran_settings() -> Settings {
        let mut s = Settings {
            routing: RoutingMode::BypassIran,
            ..Settings::default()
        };
        s.bypass.country = "ir".into();
        s
    }

    fn check_order(v: &Value, process: bool) {
        let r = v["route"]["rules"].as_array().expect("rules");
        let i = r.iter().position(|r| r["domain"] == json!(["first.test"])).expect("user");
        assert_eq!(r[i]["action"], "reject");
        assert!(r[i].get("outbound").is_none());
        let next = if process {
            assert_eq!(r[i + 1]["process_name"], json!(["telegram.exe"]));
            assert_eq!(r[i + 1]["outbound"], "proxy");
            i + 2
        } else { i + 1 };
        assert_eq!(r[next]["domain_suffix"], json!(["second.test"]));
        assert_eq!(r[next + 1]["rule_set"], json!(["bypass"]));
        assert_eq!(r[next + 2]["ip_is_private"], true);
        assert_eq!(v["route"]["final"], "direct");
        assert!(!v.to_string().contains("disabled.test"));
    }

    #[test]
    fn native_and_helper_ordering() {
        let e = RuleEntries { suffixes: vec!["bypass.test".into()], ..Default::default() };
        for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
            let s = Settings { mode, ..routing_settings() };
            let v = build_with(&samples()[0], &s, &e).expect("config");
            check_order(&v, mode == ProxyMode::Tun);
            if mode != ProxyMode::Tun { assert!(!v.to_string().contains("telegram.exe")); }
            let helper = tun_helper_with(&s, 10808, "server.test", &[], &e);
            check_order(&helper, true);
            assert_eq!(helper["route"]["rules"][2]["process_name"], json!(["xray.exe","xray"]));
            assert!(helper["route"]["rule_set"][0]["path"].as_str().expect("path")
                .contains("sing-box-tun"));
        }
    }

    #[test]
    fn samples_and_endpoints() {
        for p in samples() { assert!(build(&p, &Settings::default()).is_ok()); }
        let v = build(&samples()[0], &Settings::default()).expect("config");
        assert_eq!(v["outbounds"][0]["tls"]["reality"]["public_key"], "test-public-key");
        assert_eq!(v["experimental"]["clash_api"]["external_controller"], "127.0.0.1:10810");
    }

    #[test]
    fn sample_protocols_and_transports() {
        let p = samples();
        let s = Settings::default();
        let v = config(&p[0], &s).expect("VLESS");
        assert_eq!(v["outbounds"][0]["type"], "vless");
        assert_eq!(v["outbounds"][0]["tls"]["reality"]["public_key"], "test-public-key");
        assert_eq!(v["outbounds"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(v["inbounds"][0]["type"], "mixed");
        assert_eq!(v["route"]["rules"][0]["action"], "sniff");

        let v = config(&p[1], &s).expect("VMess");
        assert_eq!(v["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(v["outbounds"][0]["tls"]["enabled"], true);
        let v = config(&p[2], &s).expect("Trojan");
        assert_eq!(v["outbounds"][0]["transport"]["service_name"], "tunnel");
        let v = config(&p[3], &s).expect("Shadowsocks");
        assert_eq!(v["outbounds"][0]["method"], "aes-128-gcm");
        let v = config(&p[4], &s).expect("Hysteria2");
        assert_eq!(v["outbounds"][0]["type"], "hysteria2");
        assert_eq!(v["outbounds"][0]["obfs"]["type"], "salamander");
    }

    #[test]
    fn modern_dns_routing_and_tun() {
        let s = Settings { mode: ProxyMode::Tun, ..iran_settings() };
        let v = config(&samples()[0], &s).expect("configuration");
        assert_eq!(v["dns"]["servers"][0]["type"], "https");
        assert_eq!(v["dns"]["servers"][0]["server"], "1.1.1.1");
        assert_eq!(v["dns"]["servers"][0]["detour"], "proxy");
        assert_eq!(v["dns"]["servers"][1]["type"], "udp");
        assert_eq!(v["dns"]["strategy"], "ipv4_only");
        assert_eq!(v["route"]["default_domain_resolver"]["server"], "direct");
        assert_eq!(v["route"]["rule_set"][0]["tag"], "geoip-ir");
        assert_eq!(v["inbounds"][1]["address"], json!(["172.19.0.1/30"]));
        assert_eq!(v["inbounds"][1]["strict_route"], true);
        for out in v["outbounds"].as_array().expect("outbounds") {
            assert_ne!(out["type"], "dns");
            assert_ne!(out["type"], "block");
        }
    }

    #[test]
    fn mode_is_the_only_tun_switch() {
        for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
            for tun in [false, true] {
                let s = Settings { mode, tun, ..Settings::default() };
                let v = config(&samples()[0], &s).expect("configuration");
                assert_eq!(
                    v["inbounds"].as_array().expect("inbounds").len(),
                    if mode == ProxyMode::Tun { 2 } else { 1 }
                );
            }
        }
    }

    #[test]
    fn tun_restrictions_apply_only_in_tun_and_precede_routing_bypasses() {
        for routing in [RoutingMode::Global, RoutingMode::BypassLan, RoutingMode::BypassIran] {
            for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
                let s = Settings { mode, routing, ..iran_settings() };
                let v = config(&samples()[0], &s).expect("configuration");
                let rules = v["route"]["rules"].as_array().expect("route rules");
                assert_eq!(rules[0], json!({"action":"sniff"}));
                assert_eq!(rules[1], json!({"protocol":"dns","action":"hijack-dns"}));
                assert_eq!(v["route"]["final"], "proxy");
                let bypass_start = if mode == ProxyMode::Tun {
                    assert_eq!(v["dns"]["strategy"], "ipv4_only");
                    assert_eq!(v["inbounds"][1]["address"], json!(["172.19.0.1/30"]));
                    assert_eq!(rules[2], json!({"ip_version":6,"action":"reject"}));
                    assert_eq!(rules[3], json!({"network":"udp","port":443,"action":"reject"}));
                    4
                } else {
                    assert_eq!(v["dns"]["strategy"], "prefer_ipv4");
                    assert!(rules.iter().all(|rule| rule["action"] != "reject"));
                    2
                };
                // v8 orders country bypasses before private/LAN, after the
                // same mandatory TUN restrictions guarded by the old tests.
                let mut expected = Vec::new();
                if routing == RoutingMode::BypassIran {
                    expected.push(json!({"domain_suffix":["ir"],"action":"route","outbound":"direct"}));
                    expected.push(json!({"rule_set":["geoip-ir"],"action":"route","outbound":"direct"}));
                }
                if routing != RoutingMode::Global {
                    expected.push(json!({"ip_is_private":true,"action":"route","outbound":"direct"}));
                }
                assert_eq!(&rules[bypass_start..], expected.as_slice());
            }
        }
    }

    #[test]
    fn helper_shape_and_loop_prevention() {
        let s = Settings::default();
        let ips = [
            "203.0.113.10".parse().expect("IPv4"),
            "2001:db8::10".parse().expect("IPv6"),
        ];
        let v = helper(&s, 12345, "irusa.netbazshop.ir", &ips);
        let cidrs = json!(["203.0.113.10/32", "2001:db8::10/128"]);
        assert_eq!(v["inbounds"].as_array().expect("inbounds").len(), 1);
        assert_eq!(v["inbounds"][0]["type"], "tun");
        assert_eq!(v["inbounds"][0]["stack"], "mixed");
        assert_eq!(v["inbounds"][0]["auto_route"], true);
        assert_eq!(v["inbounds"][0]["strict_route"], true);
        assert_eq!(v["inbounds"][0]["address"], json!(["172.19.0.1/30"]));
        assert_eq!(v["inbounds"][0]["route_exclude_address"], cidrs);
        assert_eq!(v["outbounds"][0]["type"], "socks");
        assert_eq!(v["outbounds"][0]["server"], "127.0.0.1");
        assert_eq!(v["outbounds"][0]["server_port"], 12345);
        assert_eq!(v["outbounds"][0]["tag"], "proxy");
        assert_eq!(v["outbounds"][1]["tag"], "direct");
        assert_eq!(v["route"]["rules"][0]["action"], "sniff");
        assert_eq!(v["route"]["rules"][1]["action"], "hijack-dns");
        assert_eq!(v["route"]["rules"][2]["process_name"], json!(["xray.exe", "xray"]));
        assert_eq!(v["route"]["rules"][2]["outbound"], "direct");
        assert_eq!(v["route"]["rules"][3]["ip_cidr"], cidrs);
        assert_eq!(v["route"]["rules"][3]["action"], "route");
        assert_eq!(v["route"]["rules"][3]["outbound"], "direct");
        assert_eq!(v["route"]["rules"][4], json!({"ip_version":6,"action":"reject"}));
        assert_eq!(v["route"]["rules"][5], json!({"network":"udp","port":443,"action":"reject"}));
        assert_eq!(v["route"]["rules"][6]["ip_is_private"], true);
        assert_eq!(v["route"]["final"], "proxy");
        assert_eq!(v["route"]["auto_detect_interface"], true);
        assert_eq!(v["route"]["find_process"], true);
        assert_eq!(v["dns"]["strategy"], "ipv4_only");
        assert_eq!(v["dns"]["rules"][0], json!({
            "domain":["irusa.netbazshop.ir"],"action":"route","server":"direct"
        }));
        assert_eq!(v["dns"]["rules"][1]["domain_suffix"], json!(["local", "localhost"]));
        assert_eq!(v["dns"]["servers"][0]["detour"], "proxy");
        assert_eq!(v["dns"]["servers"][0]["server"], "1.1.1.1");
        assert_eq!(v["dns"]["servers"][1], json!({
            "type":"udp","tag":"direct","server":"8.8.8.8"
        }));
        assert!(v.get("experimental").is_none());
    }

    #[test]
    fn helper_without_server_ips_keeps_process_exclusion_before_rejections() {
        let v = helper(&Settings::default(), 10808, "server.example", &[]);
        assert_eq!(v["inbounds"][0]["route_exclude_address"], json!([]));
        assert_eq!(v["inbounds"][0]["address"], json!(["172.19.0.1/30"]));
        assert_eq!(v["dns"]["strategy"], "ipv4_only");
        assert_eq!(v["route"]["rules"], json!([
            {"action":"sniff"},
            {"protocol":"dns","action":"hijack-dns"},
            {"process_name":["xray.exe","xray"],"action":"route","outbound":"direct"},
            {"ip_version":6,"action":"reject"},
            {"network":"udp","port":443,"action":"reject"},
            {"ip_is_private":true,"action":"route","outbound":"direct"}
        ]));
    }

    #[test]
    fn helper_ip_literal_skips_domain_rule() {
        for host in ["203.0.113.10", "2001:db8::10", "[2001:db8::10]"] {
            let ip = host.trim_matches(['[', ']']).parse().expect("server IP");
            let v = helper(&Settings::default(), 10808, host, &[ip]);
            let rules = v["dns"]["rules"].as_array().expect("DNS rules");
            assert_eq!(rules.len(), 1);
            assert!(rules.iter().all(|rule| rule.get("domain").is_none()));
            assert_eq!(rules[0]["server"], "direct");
            assert_eq!(
                v["inbounds"][0]["route_exclude_address"],
                v["route"]["rules"][3]["ip_cidr"]
            );
        }
    }

    #[test]
    fn helper_direct_dns_is_explicit_udp_without_detour() {
        for (input, expected) in [
            ("9.9.9.9", "9.9.9.9"),
            ("2001:4860:4860::8888", "2001:4860:4860::8888"),
            ("local", "8.8.8.8"),
            ("localhost", "8.8.8.8"),
            ("https://1.1.1.1/dns-query", "8.8.8.8"),
            ("udp://9.9.9.9", "8.8.8.8"),
            ("dns.example", "8.8.8.8"),
            ("", "8.8.8.8"),
        ] {
            let s = Settings { direct_dns: input.into(), ..Settings::default() };
            let v = helper(
                &s, 10808, "server.example",
                &["203.0.113.10".parse().expect("server IP")],
            );
            assert_eq!(v["dns"]["servers"][1], json!({
                "type":"udp","tag":"direct","server":expected
            }));
        }
    }

    #[test]
    fn direct_dns_has_no_detour_in_any_mode() {
        for routing in [RoutingMode::Global, RoutingMode::BypassLan, RoutingMode::BypassIran] {
            for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
                for direct_dns in [
                    "8.8.8.8", "local", "localhost", "tcp://8.8.8.8",
                    "tls://8.8.8.8", "https://1.1.1.1/dns-query", "quic://8.8.8.8",
                ] {
                    let s = Settings {
                        routing, mode, direct_dns: direct_dns.into(), ..iran_settings()
                    };
                    let v = config(&samples()[0], &s).expect("configuration");
                    for server in v["dns"]["servers"].as_array().expect("DNS servers") {
                        assert_ne!(server["detour"], "direct");
                        if server["tag"] == "direct" {
                            assert!(server.get("detour").is_none());
                        } else if server["tag"] == "remote" {
                            assert_eq!(server["detour"], "proxy");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn wireguard_uses_endpoint_and_tuic_uses_outbound() {
        let mut p = samples()[0].clone();
        p.protocol = Some(Protocol::Wireguard);
        p.local_address = vec!["10.0.0.2/32".into()];
        p.private_key = "private".into();
        p.public_key = "public".into();
        p.reserved = vec![1, 2, 3];
        let v = config(&p, &Settings::default()).expect("WireGuard");
        assert_eq!(v["endpoints"][0]["tag"], "proxy");
        assert_eq!(v["endpoints"][0]["peers"][0]["port"], 443);
        assert_eq!(v["outbounds"].as_array().expect("outbounds").len(), 1);

        p.protocol = Some(Protocol::Tuic);
        p.tls.security = Security::Tls;
        p.congestion_control = "bbr".into();
        let v = config(&p, &Settings::default()).expect("TUIC");
        assert_eq!(v["outbounds"][0]["congestion_control"], "bbr");
    }

    #[test]
    fn typed_dns_url_conversion() {
        let v = dns_server("tls://8.8.8.8:8853", "remote", "proxy").expect("TLS DNS");
        assert_eq!(v["type"], "tls");
        assert_eq!(v["server_port"], 8853);
        let v = dns_server("https://dns.example/dns-query", "remote", "proxy").expect("DoH");
        assert_eq!(v["domain_resolver"], "direct");
        let v = dns_server("2001:4860:4860::8888", "direct", "direct").expect("IPv6 DNS");
        assert_eq!(v["server"], "2001:4860:4860::8888");
        assert!(dns_server("ftp://example.com", "remote", "proxy").is_err());
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
            ssh_client_version: "SSH-2.0-client".into(),
            ..Profile::default()
        };
        let v = config(&p, &Settings::default()).expect("SSH");
        let out = &v["outbounds"][0];
        assert_eq!(out["type"], "ssh");
        assert_eq!(out["tag"], "proxy");
        assert_eq!(out["server"], "ssh.example");
        assert_eq!(out["server_port"], 22);
        assert_eq!(out["user"], "alice");
        assert_eq!(out["password"], "secret");
        assert_eq!(out["private_key"], p.ssh_private_key);
        assert_eq!(out["private_key_passphrase"], "passphrase");
        assert_eq!(out["host_key"], json!(p.ssh_host_key));
        assert_eq!(out["client_version"], "SSH-2.0-client");
        assert!(out.get("tls").is_none());

        p.ssh_private_key.clear();
        p.ssh_private_key_passphrase.clear();
        p.ssh_host_key.clear();
        p.ssh_client_version.clear();
        let v = config(&p, &Settings::default()).expect("password-only SSH");
        for key in ["private_key", "private_key_passphrase", "host_key", "client_version"] {
            assert!(v["outbounds"][0].get(key).is_none());
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
        let out = &v["outbounds"][0];
        assert_eq!(out["type"], "anytls");
        assert_eq!(out["password"], "secret");
        assert_eq!(out["tls"]["enabled"], true);
        assert_eq!(out["tls"]["insecure"], true);
        assert_eq!(out["tls"]["server_name"], "sni.example");
        assert_eq!(out["tls"]["alpn"], json!(["h3"]));
        assert_eq!(out["tls"]["utls"]["fingerprint"], "chrome");

        p.protocol = Some(Protocol::Hysteria);
        p.obfs = "obfs-secret".into();
        p.up_mbps = 20;
        p.down_mbps = 100;
        let v = config(&p, &Settings::default()).expect("Hysteria v1");
        let out = &v["outbounds"][0];
        assert_eq!(out["type"], "hysteria");
        assert_eq!(out["auth_str"], "secret");
        assert_eq!(out["obfs"], "obfs-secret");
        assert_eq!(out["up_mbps"], 20);
        assert_eq!(out["down_mbps"], 100);
        assert_eq!(out["tls"]["enabled"], true);
        assert_eq!(out["tls"]["server_name"], "sni.example");
        assert!(out.get("password").is_none());
        assert!(out.get("transport").is_none());
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
            assert_eq!(
                v["experimental"]["clash_api"]["external_controller"],
                "127.0.0.1:12002"
            );
        }
        for mixed_port in [u16::MAX - 1, u16::MAX] {
            let s = Settings { mixed_port, ..Settings::default() };
            assert!(config(&samples()[0], &s).is_err());
        }
    }
}
