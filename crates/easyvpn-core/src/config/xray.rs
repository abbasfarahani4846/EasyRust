//! Xray JSON configuration.

use super::{cipher, comma_list, dns_ip, listen, put_nonempty, validate};
use crate::profile::{
    CoreKind, Network, Profile, Protocol, RoutingMode, RuleKind, Security, Settings,
};
use crate::rules::RuleEntries;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

pub fn build(p: &Profile, s: &Settings) -> Result<Value> {
    build_with(p, s, &crate::rules::effective_entries(s))
}

pub fn build_with(p: &Profile, s: &Settings, entries: &RuleEntries) -> Result<Value> {
    let protocol = validate(CoreKind::Xray, p, s)?;
    let http_port = s.mixed_port.checked_add(1).context("Xray HTTP port overflows u16")?;
    let stats_port = s.mixed_port.checked_add(2).context("stats port overflows u16")?;
    let proxy = outbound(p, protocol)?;
    let mut rules = Vec::new();
    // Bootstrap exceptions are infrastructure, not user traffic.
    if let Some(ip) = dns_ip(&s.direct_dns) {
        rules.push(json!({"type":"field","ip":[ip],"port":"53,443,853","outboundTag":"direct"}));
    }
    rules.push(json!({
        "type":"field","domain":[format!("full:{}", p.address)],"outboundTag":"direct"
    }));
    for rule in s.rules.iter().filter(|r| r.enabled && !r.value.trim().is_empty()) {
        let value = rule.value.trim();
        let mut field = json!({"type":"field","outboundTag":super::action_tag(rule.action)});
        match rule.kind {
            RuleKind::Domain => field["domain"] = json!([format!("full:{value}")]),
            RuleKind::DomainSuffix => field["domain"] = json!([format!("domain:{value}")]),
            RuleKind::DomainKeyword => field["domain"] = json!([format!("keyword:{value}")]),
            RuleKind::IpCidr => field["ip"] = json!([value]),
            // Xray has no process matcher; the TUN helper applies these.
            RuleKind::Process => continue,
        }
        rules.push(field);
    }
    let domains: Vec<String> = entries.suffixes.iter().map(|v| format!("domain:{v}"))
        .chain(entries.full.iter().map(|v| format!("full:{v}")))
        .chain(entries.keywords.iter().map(|v| format!("keyword:{v}"))).collect();
    if !domains.is_empty() {
        rules.push(json!({"type":"field","domain":domains,"outboundTag":"direct"}));
    }
    if !entries.cidrs.is_empty() {
        rules.push(json!({"type":"field","ip":entries.cidrs,"outboundTag":"direct"}));
    }
    let legacy = crate::rules::legacy_iran(s, entries);
    if legacy {
        rules.push(json!({"type":"field","domain":["domain:ir"],"outboundTag":"direct"}));
        rules.push(json!({"type":"field","ip":["geoip:ir"],"outboundTag":"direct"}));
    }
    if s.routing != RoutingMode::Global {
        rules.push(json!({"type":"field","ip":["geoip:private"],"outboundTag":"direct"}));
    }
    rules.push(json!({"type":"field","inboundTag":["dns-in"],"outboundTag":"proxy"}));
    rules.push(json!({"type":"field","network":"tcp,udp","outboundTag":super::final_tag(s)}));

    let mut direct_domains = vec![format!("full:{}", p.address)];
    direct_domains.extend(domains);
    if s.routing != RoutingMode::Global {
        direct_domains.extend(["domain:localhost".into(), "domain:local".into()]);
    }
    if legacy {
        direct_domains.push("domain:ir".into());
    }
    let servers = json!([
        {"address":s.direct_dns,"domains":direct_domains,"skipFallback":true},
        {"address":s.remote_dns}
    ]);
    let sniffing = json!({
        "enabled":true,"destOverride":["http","tls","quic"],"routeOnly":true
    });
    Ok(json!({
        "log":{"loglevel":s.log_level},
        "stats":{},
        "policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}},
        "metrics":{"tag":"metrics","listen":format!("127.0.0.1:{stats_port}")},
        "dns":{"tag":"dns-in","servers":servers,"queryStrategy":"UseIP"},
        "inbounds":[
            {"tag":"socks-in","listen":listen(s),"port":s.mixed_port,
             "protocol":"socks","settings":{"auth":"noauth","udp":true},"sniffing":sniffing},
            {"tag":"http-in","listen":listen(s),"port":http_port,
             "protocol":"http","settings":{},"sniffing":sniffing}
        ],
        "outbounds":[proxy,{"tag":"direct","protocol":"freedom","settings":{}},
                     {"tag":"block","protocol":"blackhole","settings":{}}],
        "routing":{"domainStrategy":"IPIfNonMatch","rules":rules}
    }))
}

fn outbound(p: &Profile, protocol: Protocol) -> Result<Value> {
    let (name, settings) = match protocol {
        Protocol::Vmess => ("vmess", json!({"vnext":[{
            "address":p.address,"port":p.port,
            "users":[{"id":p.uuid,"alterId":p.alter_id,"security":cipher(p)}]
        }]})),
        Protocol::Vless => ("vless", json!({"vnext":[{
            "address":p.address,"port":p.port,
            "users":[{"id":p.uuid,"encryption":"none","flow":p.flow}]
        }]})),
        Protocol::Trojan => ("trojan", json!({"servers":[{
            "address":p.address,"port":p.port,"password":p.password
        }]})),
        Protocol::Shadowsocks => {
            if !p.plugin.is_empty() {
                bail!("Xray does not support Shadowsocks SIP003 plugins");
            }
            ("shadowsocks", json!({"servers":[{
                "address":p.address,"port":p.port,"method":p.method,"password":p.password
            }]}))
        }
        Protocol::Socks | Protocol::Http => {
            let mut server = json!({"address":p.address,"port":p.port});
            if !p.username.is_empty() || !p.password.is_empty() {
                server["users"] = json!([{"user":p.username,"pass":p.password}]);
            }
            (if protocol == Protocol::Socks { "socks" } else { "http" },
             json!({"servers":[server]}))
        }
        Protocol::Wireguard => {
            let host = if p.address.contains(':') && !p.address.starts_with('[') {
                format!("[{}]", p.address)
            } else { p.address.clone() };
            let mut peer = json!({
                "publicKey":p.public_key,"endpoint":format!("{host}:{}", p.port),
                "allowedIPs":["0.0.0.0/0","::/0"]
            });
            if !p.pre_shared_key.is_empty() {
                peer["preSharedKey"] = json!(p.pre_shared_key);
            }
            let mut settings = json!({
                "secretKey":p.private_key,"address":p.local_address,"peers":[peer]
            });
            if p.mtu != 0 { settings["mtu"] = json!(p.mtu); }
            if !p.reserved.is_empty() {
                if p.reserved.len() != 3 {
                    bail!("WireGuard reserved must contain exactly three bytes");
                }
                settings["reserved"] = json!(p.reserved);
            }
            return Ok(json!({"tag":"proxy","protocol":"wireguard","settings":settings}));
        }
        Protocol::Custom => bail!("custom configurations must be built through config::build"),
        _ => bail!("Xray does not support {:?}", protocol),
    };
    Ok(json!({
        "tag":"proxy","protocol":name,"settings":settings,
        "streamSettings":stream(p)?,"mux":{"enabled":false}
    }))
}

fn stream(p: &Profile) -> Result<Value> {
    let t = &p.transport;
    let mut stream = json!({
        "network":match t.network {
            Network::Tcp => "tcp", Network::Ws => "ws", Network::Grpc => "grpc",
            Network::H2 => "h2", Network::HttpUpgrade => "httpupgrade",
            Network::Xhttp => "xhttp", Network::Kcp => "kcp", Network::Quic => "quic"
        },
        "security":match p.tls.security {
            Security::None => "none", Security::Tls => "tls", Security::Reality => "reality"
        }
    });
    match p.tls.security {
        Security::None => {}
        Security::Tls => {
            let mut tls = json!({"allowInsecure":p.tls.allow_insecure});
            let obj = tls.as_object_mut().context("TLS settings must be an object")?;
            put_nonempty(obj, "serverName", &p.tls.sni);
            put_nonempty(obj, "fingerprint", &p.tls.fingerprint);
            if !p.tls.alpn.is_empty() { tls["alpn"] = json!(p.tls.alpn); }
            stream["tlsSettings"] = tls;
        }
        Security::Reality => stream["realitySettings"] = json!({
            "serverName":p.tls.sni,
            "fingerprint":if p.tls.fingerprint.is_empty() {"chrome"} else {&p.tls.fingerprint},
            "publicKey":p.tls.reality_public_key,"shortId":p.tls.reality_short_id,
            "spiderX":p.tls.reality_spider_x
        }),
    }
    match t.network {
        Network::Tcp => {
            if t.header_type == "http" {
                let mut request = json!({
                    "path":if t.path.is_empty() {vec!["/"]} else {comma_list(&t.path)}
                });
                if !t.host.is_empty() {
                    request["headers"] = json!({"Host":comma_list(&t.host)});
                }
                stream["tcpSettings"] = json!({"header":{"type":"http","request":request}});
            } else {
                stream["tcpSettings"] = json!({"header":{"type":"none"}});
            }
        }
        Network::Ws => {
            let mut ws = json!({"path":t.path});
            if !t.host.is_empty() { ws["headers"] = json!({"Host":t.host}); }
            stream["wsSettings"] = ws;
        }
        Network::Grpc => stream["grpcSettings"] = json!({
            "serviceName":t.service_name,"multiMode":t.header_type == "multi"
        }),
        Network::H2 => stream["httpSettings"] = json!({"host":comma_list(&t.host),"path":t.path}),
        Network::HttpUpgrade => stream["httpupgradeSettings"] = json!({"host":t.host,"path":t.path}),
        Network::Xhttp => {
            let mut settings = json!({
                "host":t.host,"path":t.path,
                "mode":if t.header_type.is_empty() {"auto"} else {&t.header_type}
            });
            if let Ok(extra @ Value::Object(_)) = serde_json::from_str::<Value>(&t.extra) {
                settings["extra"] = extra;
            }
            stream["xhttpSettings"] = settings;
        }
        Network::Kcp => stream["kcpSettings"] = json!({
            "seed":t.path,"header":{"type":if t.header_type.is_empty() {"none"} else {&t.header_type}}
        }),
        Network::Quic => stream["quicSettings"] = json!({
            "security":"none","key":t.path,
            "header":{"type":if t.header_type.is_empty() {"none"} else {&t.header_type}}
        }),
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{routing_settings, samples};

    fn config(p: &Profile, s: &Settings) -> Result<Value> {
        build_with(p, s, &RuleEntries::default())
    }

    #[test]
    fn ordering_block_and_default() {
        let s = routing_settings();
        let e = RuleEntries { suffixes: vec!["bypass.test".into()], ..Default::default() };
        let v = build_with(&samples()[0], &s, &e).expect("config");
        let rules = v["routing"]["rules"].as_array().expect("rules");
        let user = rules.iter().position(|r| r["domain"] == json!(["full:first.test"])).expect("user");
        assert_eq!(rules[user]["outboundTag"], "block");
        assert_eq!(rules[user + 1]["domain"], json!(["domain:second.test"]));
        assert_eq!(rules[user + 2]["domain"], json!(["domain:bypass.test"]));
        assert_eq!(rules[user + 3]["ip"], json!(["geoip:private"]));
        assert_eq!(rules.last().expect("final")["outboundTag"], "direct");
        assert!(!v.to_string().contains("telegram.exe"));
        assert!(!v.to_string().contains("disabled.test"));
        assert_eq!(v["outbounds"][2]["protocol"], "blackhole");
    }

    #[test]
    fn protocols_and_transport() {
        let p = samples();
        let s = Settings::default();
        assert_eq!(build(&p[0], &s).expect("vless")["outbounds"][0]["streamSettings"]
            ["realitySettings"]["publicKey"], "test-public-key");
        assert_eq!(build(&p[1], &s).expect("vmess")["outbounds"][0]["streamSettings"]
            ["wsSettings"]["headers"]["Host"], "cdn.example.com");
        assert_eq!(build(&p[2], &s).expect("trojan")["outbounds"][0]["streamSettings"]
            ["grpcSettings"]["serviceName"], "tunnel");
        assert!(build(&p[3], &s).is_ok());
        assert!(build(&p[4], &s).is_err());
    }

    #[test]
    fn sample_protocols_and_transports() {
        let profiles = samples();
        let s = Settings::default();
        let v = config(&profiles[0], &s).expect("VLESS");
        assert_eq!(v["outbounds"][0]["protocol"], "vless");
        assert_eq!(
            v["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            v["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"],
            "test-public-key"
        );
        assert_eq!(v["inbounds"][0]["protocol"], "socks");
        assert_eq!(v["inbounds"][1]["port"], s.mixed_port + 1);

        let v = config(&profiles[1], &s).expect("VMess");
        assert_eq!(
            v["outbounds"][0]["streamSettings"]["wsSettings"]["headers"]["Host"],
            "cdn.example.com"
        );
        assert_eq!(v["outbounds"][0]["streamSettings"]["security"], "tls");
        let v = config(&profiles[2], &s).expect("Trojan");
        assert_eq!(v["outbounds"][0]["streamSettings"]["grpcSettings"]["serviceName"], "tunnel");
        assert_eq!(v["outbounds"][0]["settings"]["servers"][0]["password"], "secret");
        let v = config(&profiles[3], &s).expect("Shadowsocks");
        assert_eq!(v["outbounds"][0]["settings"]["servers"][0]["method"], "aes-128-gcm");
        assert!(config(&profiles[4], &s).is_err());
    }

    #[test]
    fn routing_dns_and_port_validation() {
        let mut s = Settings {
            routing: RoutingMode::BypassIran,
            allow_lan: true,
            tun: true,
            ..Settings::default()
        };
        s.bypass.country = "ir".into();
        let v = config(&samples()[0], &s).expect("configuration");
        assert_eq!(v["inbounds"][0]["listen"], "0.0.0.0");
        assert_eq!(v["inbounds"].as_array().expect("inbounds").len(), 2);
        let rules = v["routing"]["rules"].to_string();
        assert!(rules.contains("geoip:private"));
        assert!(rules.contains("geoip:ir"));
        assert!(rules.contains("domain:ir"));
        assert!(v["dns"]["servers"].to_string().contains(&s.remote_dns));
        assert!(config(&samples()[0], &Settings { mixed_port: u16::MAX, ..s }).is_err());
    }

    #[test]
    fn all_xray_transports() {
        for network in [
            Network::Tcp, Network::Ws, Network::Grpc, Network::H2,
            Network::HttpUpgrade, Network::Xhttp, Network::Kcp, Network::Quic,
        ] {
            let mut p = samples()[1].clone();
            p.transport.network = network;
            assert!(config(&p, &Settings::default()).is_ok());
        }
    }

    #[test]
    fn xhttp_extra_from_share_link() {
        let p = crate::link::parse_link(
            "vless://uuid@example.org:443?type=xhttp&security=tls&mode=stream-up&path=%2Fvpn&host=cdn.example.org&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22xPaddingObfsMode%22%3Atrue%7D",
        )
        .expect("share link");
        let v = config(&p, &Settings::default()).expect("configuration");
        assert_eq!(
            v["outbounds"][0]["streamSettings"]["xhttpSettings"],
            json!({
                "mode": "stream-up",
                "path": "/vpn",
                "host": "cdn.example.org",
                "extra": {"xPaddingBytes": "100-1000", "xPaddingObfsMode": true}
            })
        );
    }

    #[test]
    fn xhttp_ignores_invalid_or_non_object_extra() {
        let mut p = samples()[0].clone();
        p.transport.network = Network::Xhttp;
        for extra in ["", "{invalid", "null", "[]", "true", "42", "\"text\""] {
            p.transport.extra = extra.into();
            let v = config(&p, &Settings::default()).expect("configuration");
            assert!(v["outbounds"][0]["streamSettings"]["xhttpSettings"]
                .get("extra")
                .is_none());
        }
        p.transport.header_type.clear();
        p.transport.extra = "{}".into();
        let v = config(&p, &Settings::default()).expect("configuration");
        let settings = &v["outbounds"][0]["streamSettings"]["xhttpSettings"];
        assert_eq!(settings["mode"], "auto");
        assert_eq!(settings["extra"], json!({}));
    }

    #[test]
    fn unsupported_and_raw_protocols_return_errors() {
        for protocol in [
            Protocol::Ssh, Protocol::AnyTls, Protocol::Hysteria,
            Protocol::Hysteria2, Protocol::Tuic, Protocol::OpenVpn, Protocol::Custom,
        ] {
            let p = Profile {
                protocol: Some(protocol), address: "example.com".into(), port: 443,
                ..Profile::default()
            };
            assert!(config(&p, &Settings::default()).is_err(), "{protocol:?}");
        }
    }

    #[test]
    fn stats_endpoint_is_loopback_only() {
        for allow_lan in [false, true] {
            let s = Settings {
                allow_lan, mixed_port: 12000, ..Settings::default()
            };
            let v = config(&samples()[0], &s).expect("configuration");
            assert_eq!(v["stats"], json!({}));
            assert_eq!(v["policy"]["system"]["statsOutboundUplink"], true);
            assert_eq!(v["policy"]["system"]["statsOutboundDownlink"], true);
            assert_eq!(v["metrics"]["tag"], "metrics");
            assert_eq!(v["metrics"]["listen"], "127.0.0.1:12002");
        }
        let s = Settings {
            mixed_port: u16::MAX - 1, ..Settings::default()
        };
        assert!(config(&samples()[0], &s).is_err());
    }
}
