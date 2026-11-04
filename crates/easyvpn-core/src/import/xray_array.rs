//! Conversion of panel subscriptions containing arrays of Xray client configs.

use crate::profile::{CoreKind, Network, Profile, Protocol, Security};
use anyhow::{bail, Context, Result};
use serde_json::Value;

pub(super) fn import_config(config: &Value) -> Profile {
    let name = config["remarks"]
        .as_str()
        .unwrap_or("Custom xray")
        .to_owned();
    match convert(config) {
        Ok(mut profile) => {
            profile.name = name;
            profile
        }
        Err(_) => Profile {
            name,
            protocol: Some(Protocol::Custom),
            custom_core: Some(CoreKind::Xray),
            // Value serialization cannot fail and preserves the complete element,
            // including routing, inbounds, and unsupported outbound options.
            raw_config: config.to_string(),
            ..Profile::default()
        },
    }
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or("").to_owned()
}

fn required(value: &Value, key: &str) -> Result<String> {
    let result = text(value, key);
    if result.is_empty() {
        bail!("missing {key}");
    }
    Ok(result)
}

fn protocol(outbound: &Value) -> Option<Protocol> {
    Some(match outbound["protocol"].as_str()? {
        "vless" => Protocol::Vless,
        "vmess" => Protocol::Vmess,
        "trojan" => Protocol::Trojan,
        "shadowsocks" => Protocol::Shadowsocks,
        "socks" => Protocol::Socks,
        "http" => Protocol::Http,
        "wireguard" => Protocol::Wireguard,
        _ => return None,
    })
}

fn convert(config: &Value) -> Result<Profile> {
    let outbounds = config["outbounds"].as_array().context("missing outbounds")?;
    let outbound = outbounds
        .iter()
        .find(|o| o["tag"].as_str() == Some("proxy"))
        .or_else(|| outbounds.iter().find(|o| protocol(o).is_some()))
        .context("no proxy outbound")?;
    let kind = protocol(outbound).context("unsupported proxy protocol")?;
    let settings = &outbound["settings"];
    let mut p = Profile {
        protocol: Some(kind),
        ..Profile::default()
    };

    if kind == Protocol::Wireguard {
        p.private_key = required(settings, "secretKey")?;
        p.local_address = string_list(&settings["address"])?;
        p.mtu = optional_u32(settings, "mtu")?;
        if let Some(reserved) = settings.get("reserved") {
            p.reserved = reserved
                .as_array()
                .context("invalid reserved bytes")?
                .iter()
                .map(|v| {
                    v.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .context("invalid reserved byte")
                })
                .collect::<Result<_>>()?;
        }
        let peer = &settings["peers"][0];
        p.public_key = required(peer, "publicKey")?;
        p.pre_shared_key = text(peer, "preSharedKey");
        let endpoint = required(peer, "endpoint")?;
        let (host, port) = endpoint.rsplit_once(':').context("invalid endpoint")?;
        p.address = host.trim_start_matches('[').trim_end_matches(']').into();
        p.port = port.parse().context("invalid endpoint port")?;
    } else {
        let server = if matches!(kind, Protocol::Vless | Protocol::Vmess) {
            &settings["vnext"][0]
        } else {
            &settings["servers"][0]
        };
        p.address = required(server, "address")?;
        p.port = super::json_port(server.get("port"));
        match kind {
            Protocol::Vless | Protocol::Vmess => {
                let user = &server["users"][0];
                p.uuid = required(user, "id")?;
                p.flow = text(user, "flow");
                p.method = if kind == Protocol::Vmess {
                    let cipher = text(user, "security");
                    if cipher.is_empty() {
                        text(user, "encryption")
                    } else {
                        cipher
                    }
                } else {
                    text(user, "encryption")
                };
                p.alter_id = optional_u32(user, "alterId")?;
            }
            Protocol::Trojan | Protocol::Shadowsocks => {
                p.password = required(server, "password")?;
                if kind == Protocol::Shadowsocks {
                    p.method = required(server, "method")?;
                }
            }
            Protocol::Socks | Protocol::Http => {
                if let Some(user) = server["users"].as_array().and_then(|users| users.first()) {
                    p.username = text(user, "user");
                    p.password = text(user, "pass");
                }
            }
            _ => bail!("unsupported server layout"),
        }
    }

    if p.address.is_empty() || p.port == 0 {
        bail!("invalid server address or port");
    }
    parse_stream(&mut p, &outbound["streamSettings"])?;
    Ok(p)
}

fn optional_u32(value: &Value, key: &str) -> Result<u32> {
    match value.get(key) {
        None => Ok(0),
        Some(Value::String(s)) => s.parse().with_context(|| format!("invalid {key}")),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .with_context(|| format!("invalid {key}")),
    }
}

fn string_list(value: &Value) -> Result<Vec<String>> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(s) => Ok(super::comma_list(s)),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).context("expected string"))
            .collect(),
        _ => bail!("expected string list"),
    }
}

fn host(value: &Value) -> Result<String> {
    Ok(string_list(value)?.join(","))
}

fn parse_stream(p: &mut Profile, stream: &Value) -> Result<()> {
    p.transport.network = match stream["network"].as_str().unwrap_or("tcp") {
        "" | "tcp" | "raw" => Network::Tcp,
        "ws" => Network::Ws,
        "grpc" => Network::Grpc,
        "h2" | "http" => Network::H2,
        "httpupgrade" => Network::HttpUpgrade,
        "xhttp" | "splithttp" => Network::Xhttp,
        "kcp" | "mkcp" => Network::Kcp,
        "quic" => Network::Quic,
        _ => bail!("unsupported network"),
    };
    let options = match p.transport.network {
        Network::Tcp => {
            let tcp = stream
                .get("tcpSettings")
                .or_else(|| stream.get("rawSettings"))
                .unwrap_or(&Value::Null);
            p.transport.header_type = text(&tcp["header"], "type");
            p.transport.path = host(&tcp["header"]["request"]["path"])?;
            p.transport.host = host(&tcp["header"]["request"]["headers"]["Host"])?;
            None
        }
        Network::Ws => Some(&stream["wsSettings"]),
        Network::Grpc => {
            p.transport.service_name = text(&stream["grpcSettings"], "serviceName");
            None
        }
        Network::H2 => Some(&stream["httpSettings"]),
        Network::HttpUpgrade => Some(&stream["httpupgradeSettings"]),
        Network::Xhttp => {
            let options = stream
                .get("xhttpSettings")
                .or_else(|| stream.get("splithttpSettings"))
                .unwrap_or(&Value::Null);
            p.transport.header_type = text(options, "mode");
            if let Some(extra @ Value::Object(_)) = options.get("extra") {
                p.transport.extra = extra.to_string();
            }
            Some(options)
        }
        Network::Kcp => {
            p.transport.path = text(&stream["kcpSettings"], "seed");
            p.transport.header_type = text(&stream["kcpSettings"]["header"], "type");
            None
        }
        Network::Quic => {
            p.transport.path = text(&stream["quicSettings"], "key");
            p.transport.header_type = text(&stream["quicSettings"]["header"], "type");
            None
        }
    };
    if let Some(options) = options {
        p.transport.path = text(options, "path");
        p.transport.host = host(
            options
                .get("host")
                .or_else(|| options.get("headers").and_then(|h| h.get("Host")))
                .unwrap_or(&Value::Null),
        )?;
    }

    p.tls.security = match stream["security"].as_str().unwrap_or("none") {
        "" | "none" => Security::None,
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        _ => bail!("unsupported security"),
    };
    let tls = match p.tls.security {
        Security::None => return Ok(()),
        Security::Tls => &stream["tlsSettings"],
        Security::Reality => &stream["realitySettings"],
    };
    p.tls.sni = text(tls, "serverName");
    p.tls.fingerprint = text(tls, "fingerprint");
    p.tls.alpn = string_list(&tls["alpn"])?;
    p.tls.allow_insecure = tls["allowInsecure"].as_bool().unwrap_or(false);
    if p.tls.security == Security::Reality {
        p.tls.reality_public_key = required(tls, "publicKey")?;
        p.tls.reality_short_id = text(tls, "shortId");
        p.tls.reality_spider_x = text(tls, "spiderX");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::import_text;
    use serde_json::json;

    #[test]
    fn marzban_two_config_subscription() {
        let configs = json!([
            {
                "remarks": "Germany · REALITY",
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {"tag": "socks", "port": 10808, "protocol": "socks",
                     "settings": {"auth": "noauth", "udp": true}}
                ],
                "outbounds": [
                    {"tag": "direct", "protocol": "freedom", "settings": {}},
                    {
                        "tag": "proxy",
                        "protocol": "vless",
                        "settings": {"vnext": [{
                            "address": "de.example.org", "port": 443,
                            "users": [{
                                "id": "11111111-1111-4111-8111-111111111111",
                                "encryption": "none", "flow": "xtls-rprx-vision"
                            }]
                        }]},
                        "streamSettings": {
                            "network": "tcp", "security": "reality",
                            "tcpSettings": {"header": {"type": "none"}},
                            "realitySettings": {
                                "serverName": "www.example.org",
                                "fingerprint": "chrome",
                                "publicKey": "example-public-key",
                                "shortId": "a1b2c3d4", "spiderX": "/"
                            }
                        }
                    },
                    {"tag": "block", "protocol": "blackhole"}
                ]
            },
            {
                "remarks": "هلند · WebSocket",
                "inbounds": [],
                "outbounds": [{
                    "tag": "proxy", "protocol": "vless",
                    "settings": {"vnext": [{
                        "address": "cdn.example.org", "port": 8443,
                        "users": [{
                            "id": "22222222-2222-4222-8222-222222222222",
                            "encryption": "none"
                        }]
                    }]},
                    "streamSettings": {
                        "network": "ws", "security": "tls",
                        "wsSettings": {
                            "path": "/vpn?ed=2048",
                            "headers": {"Host": "ws.example.org"}
                        },
                        "tlsSettings": {
                            "serverName": "ws.example.org",
                            "alpn": ["h2", "http/1.1"],
                            "fingerprint": "firefox", "allowInsecure": true
                        }
                    }
                }]
            }
        ]);
        let profiles = import_text(&configs.to_string(), None);
        assert_eq!(profiles.len(), 2);
        let reality = &profiles[0];
        assert_eq!(reality.protocol, Some(Protocol::Vless));
        assert_eq!(reality.name, "Germany · REALITY");
        assert_eq!(reality.address, "de.example.org");
        assert_eq!(reality.port, 443);
        assert_eq!(reality.uuid, "11111111-1111-4111-8111-111111111111");
        assert_eq!(reality.flow, "xtls-rprx-vision");
        assert_eq!(reality.method, "none");
        assert_eq!(reality.transport.network, Network::Tcp);
        assert_eq!(reality.transport.header_type, "none");
        assert_eq!(reality.tls.security, Security::Reality);
        assert_eq!(reality.tls.sni, "www.example.org");
        assert_eq!(reality.tls.fingerprint, "chrome");
        assert_eq!(reality.tls.reality_public_key, "example-public-key");
        assert_eq!(reality.tls.reality_short_id, "a1b2c3d4");
        assert_eq!(reality.tls.reality_spider_x, "/");

        let ws = &profiles[1];
        assert_eq!(ws.protocol, Some(Protocol::Vless));
        assert_eq!(ws.name, "هلند · WebSocket");
        assert_eq!(ws.address, "cdn.example.org");
        assert_eq!(ws.port, 8443);
        assert_eq!(ws.uuid, "22222222-2222-4222-8222-222222222222");
        assert_eq!(ws.transport.network, Network::Ws);
        assert_eq!(ws.transport.path, "/vpn?ed=2048");
        assert_eq!(ws.transport.host, "ws.example.org");
        assert_eq!(ws.tls.security, Security::Tls);
        assert_eq!(ws.tls.sni, "ws.example.org");
        assert_eq!(ws.tls.alpn, ["h2", "http/1.1"]);
        assert_eq!(ws.tls.fingerprint, "firefox");
        assert!(ws.tls.allow_insecure);
        assert!(profiles.iter().all(|p| p.raw_config.is_empty()));

        // A standalone config must still be imported verbatim as Custom.
        let standalone = configs[0].to_string();
        let single = import_text(&standalone, None);
        assert_eq!(single[0].protocol, Some(Protocol::Custom));
        assert_eq!(single[0].raw_config, standalone);
    }

    #[test]
    fn fallback_preserves_element_and_selection_prefers_proxy_tag() {
        let configs = json!([
            {
                "remarks": "unsupported",
                "outbounds": [
                    {"protocol": "socks", "settings": {"servers": [
                        {"address": "ignored.example.org", "port": 1080}
                    ]}},
                    {"tag": "proxy", "protocol": "unknown", "settings": {}}
                ]
            },
            {"remarks": "broken", "outbounds": [
                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": []}}
            ]},
            {"remarks": "valid", "outbounds": [
                {"protocol": "freedom"},
                {"protocol": "socks", "settings": {"servers": [
                    {"address": "proxy.example.org", "port": "1080",
                     "users": [{"user": "alice", "pass": "secret"}]}
                ]}}
            ]}
        ]);
        let profiles = import_text(&configs.to_string(), None);
        assert_eq!(profiles.len(), 3);
        for i in 0..2 {
            assert_eq!(profiles[i].protocol, Some(Protocol::Custom));
            assert_eq!(profiles[i].custom_core, Some(CoreKind::Xray));
            assert_eq!(
                serde_json::from_str::<Value>(&profiles[i].raw_config).expect("raw JSON"),
                configs[i]
            );
            assert_eq!(profiles[i].name, configs[i]["remarks"].as_str().expect("name"));
        }
        assert_eq!(profiles[2].protocol, Some(Protocol::Socks));
        assert_eq!(profiles[2].username, "alice");
        assert_eq!(profiles[2].password, "secret");
        assert_eq!(profiles[2].port, 1080);
    }

    #[test]
    fn other_protocol_credentials() {
        for (kind, settings, expected) in [
            (
                "vmess",
                json!({"vnext": [{"address": "vpn.example.org", "port": 443,
                    "users": [{"id": "uuid", "alterId": 4, "security": "auto"}]}]}),
                Protocol::Vmess,
            ),
            (
                "trojan",
                json!({"servers": [{"address": "vpn.example.org", "port": 443,
                    "password": "secret"}]}),
                Protocol::Trojan,
            ),
            (
                "shadowsocks",
                json!({"servers": [{"address": "vpn.example.org", "port": 443,
                    "password": "secret", "method": "aes-128-gcm"}]}),
                Protocol::Shadowsocks,
            ),
            (
                "http",
                json!({"servers": [{"address": "vpn.example.org", "port": 443,
                    "users": [{"user": "alice", "pass": "secret"}]}]}),
                Protocol::Http,
            ),
            (
                "wireguard",
                json!({"secretKey": "private", "address": ["10.0.0.2/32"],
                    "mtu": 1420, "reserved": [1, 2, 3],
                    "peers": [{"publicKey": "public", "preSharedKey": "psk",
                        "endpoint": "[2001:db8::1]:51820"}]}),
                Protocol::Wireguard,
            ),
        ] {
            let p = import_config(&json!({"remarks": kind, "outbounds": [{
                "protocol": kind, "settings": settings
            }]}));
            assert_eq!(p.protocol, Some(expected));
            match expected {
                Protocol::Vmess => {
                    assert_eq!(p.uuid, "uuid");
                    assert_eq!(p.method, "auto");
                    assert_eq!(p.alter_id, 4);
                }
                Protocol::Trojan => assert_eq!(p.password, "secret"),
                Protocol::Shadowsocks => {
                    assert_eq!(p.password, "secret");
                    assert_eq!(p.method, "aes-128-gcm");
                }
                Protocol::Http => assert_eq!(p.username, "alice"),
                Protocol::Wireguard => {
                    assert_eq!(p.address, "2001:db8::1");
                    assert_eq!(p.port, 51820);
                    assert_eq!(p.reserved, [1, 2, 3]);
                    assert_eq!(p.pre_shared_key, "psk");
                }
                _ => panic!("unexpected fixture"),
            }
        }
    }

    #[test]
    fn transport_mapping() {
        for (network, expected, options) in [
            ("raw", Network::Tcp, json!({"tcpSettings": {"header": {"type": "http"}}})),
            ("grpc", Network::Grpc, json!({"grpcSettings": {"serviceName": "vpn"}})),
            ("http", Network::H2, json!({"httpSettings": {"path": "/vpn", "host": ["a.example.org"]}})),
            ("h2", Network::H2, json!({})),
            ("httpupgrade", Network::HttpUpgrade, json!({"httpupgradeSettings": {"path": "/vpn", "host": "a.example.org"}})),
            ("xhttp", Network::Xhttp, json!({"xhttpSettings": {"path": "/vpn", "host": "a.example.org", "mode": "auto"}})),
            ("splithttp", Network::Xhttp, json!({"splithttpSettings": {"mode": "packet-up"}})),
            ("kcp", Network::Kcp, json!({"kcpSettings": {"seed": "seed", "header": {"type": "srtp"}}})),
            ("quic", Network::Quic, json!({"quicSettings": {"key": "key", "header": {"type": "none"}}})),
        ] {
            let mut stream = options;
            stream["network"] = json!(network);
            let mut p = Profile::default();
            parse_stream(&mut p, &stream).expect("transport");
            assert_eq!(p.transport.network, expected);
            match network {
                "raw" => assert_eq!(p.transport.header_type, "http"),
                "grpc" => assert_eq!(p.transport.service_name, "vpn"),
                "http" | "httpupgrade" | "xhttp" => {
                    assert_eq!(p.transport.path, "/vpn");
                    assert_eq!(p.transport.host, "a.example.org");
                }
                "splithttp" => assert_eq!(p.transport.header_type, "packet-up"),
                "kcp" => assert_eq!(p.transport.path, "seed"),
                "quic" => assert_eq!(p.transport.path, "key"),
                _ => {}
            }
        }
    }

    #[test]
    fn xhttp_extra_survives_import_link_and_config_generation() {
        let extra = json!({"xPaddingBytes": "100-1000", "xPaddingObfsMode": true});
        let configs = json!([{
            "remarks": "XHTTP stream-up",
            "outbounds": [{
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "example.org", "port": 443,
                    "users": [{"id": "uuid", "encryption": "none"}]
                }]},
                "streamSettings": {
                    "network": "xhttp", "security": "tls",
                    "tlsSettings": {"serverName": "example.org"},
                    "xhttpSettings": {
                        "mode": "stream-up", "path": "/vpn",
                        "host": "cdn.example.org", "extra": extra
                    }
                }
            }]
        }]);
        let profiles = import_text(&configs.to_string(), None);
        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!(p.protocol, Some(Protocol::Vless));
        assert_eq!(p.transport.header_type, "stream-up");
        assert_eq!(
            serde_json::from_str::<Value>(&p.transport.extra).expect("extra object"),
            extra
        );

        let link = crate::link::to_link(p).expect("share link");
        let restored = crate::link::parse_link(&link).expect("restore share link");

        // Empty VLESS encryption and "none" are equivalent. Normalize only
        // that default while retaining equality checks for every other field.
        let mut expected = p.clone();
        let mut actual = restored.clone();
        for profile in [&mut expected, &mut actual] {
            if profile.protocol == Some(Protocol::Vless) && profile.method.is_empty() {
                profile.method = "none".into();
            }
        }
        assert_eq!(actual, expected);

        let config = crate::config::xray::build(&restored, &crate::Settings::default())
            .expect("generated configuration");
        assert_eq!(
            config["outbounds"][0]["streamSettings"]["xhttpSettings"],
            configs[0]["outbounds"][0]["streamSettings"]["xhttpSettings"]
        );
    }

    #[test]
    fn xhttp_only_imports_object_extra() {
        for extra in [Value::Null, json!("invalid"), json!([]), json!(true)] {
            let mut p = Profile::default();
            parse_stream(
                &mut p,
                &json!({
                    "network": "xhttp",
                    "xhttpSettings": {"mode": "stream-up", "extra": extra}
                }),
            )
            .expect("transport");
            assert!(p.transport.extra.is_empty());
            assert_eq!(p.transport.header_type, "stream-up");
        }
    }
}
