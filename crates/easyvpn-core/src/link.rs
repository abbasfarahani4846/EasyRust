//! Import and export V2Ray-family share links.

use crate::profile::{Network, Profile, Protocol, Security};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde_json::{json, Value};
use std::collections::HashMap;
use url::Url;

// RFC 3986 unreserved characters are safe in userinfo, query values and fragments.
// Encode all other bytes so delimiters cannot change the structure of a link.
const COMPONENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

fn decode64(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        &general_purpose::STANDARD,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(&s) {
            return Ok(bytes);
        }
    }
    bail!("invalid base64")
}

fn decode64_text(s: &str) -> Result<String> {
    String::from_utf8(decode64(s)?).context("base64 content is not UTF-8")
}

fn unescape(s: &str) -> Result<String> {
    Ok(percent_decode_str(s).decode_utf8()?.into_owned())
}

fn escape(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT_ENCODE_SET).to_string()
}

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

fn network(s: &str) -> Result<Network> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "" | "tcp" => Network::Tcp,
        "ws" => Network::Ws,
        "grpc" => Network::Grpc,
        "h2" | "http" => Network::H2,
        "httpupgrade" => Network::HttpUpgrade,
        "xhttp" | "splithttp" => Network::Xhttp,
        "kcp" | "mkcp" => Network::Kcp,
        "quic" => Network::Quic,
        _ => bail!("unsupported transport: {s}"),
    })
}

fn network_name(n: Network) -> &'static str {
    match n {
        Network::Tcp => "tcp",
        Network::Ws => "ws",
        Network::Grpc => "grpc",
        Network::H2 => "h2",
        Network::HttpUpgrade => "httpupgrade",
        Network::Xhttp => "xhttp",
        Network::Kcp => "kcp",
        Network::Quic => "quic",
    }
}

fn security(s: &str) -> Result<Security> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "" | "none" => Security::None,
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        _ => bail!("unsupported security: {s}"),
    })
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::None => "none",
        Security::Tls => "tls",
        Security::Reality => "reality",
    }
}

fn truthy(s: &str) -> bool {
    s == "1" || s.eq_ignore_ascii_case("true")
}

fn validate(p: &Profile) -> Result<()> {
    if p.address.is_empty() || p.port == 0 {
        bail!("share link requires a server and a nonzero port");
    }
    Ok(())
}

fn json_text(v: &Value, key: &str) -> String {
    match &v[key] {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn parse_vmess(body: &str) -> Result<Profile> {
    let v: Value = serde_json::from_slice(&decode64(body)?).context("invalid vmess JSON")?;
    if !v.is_object() {
        bail!("vmess payload must be a JSON object");
    }
    let port = json_text(&v, "port").parse().context("invalid vmess port")?;
    let aid = json_text(&v, "aid");
    let mut p = Profile {
        protocol: Some(Protocol::Vmess),
        name: json_text(&v, "ps"),
        address: json_text(&v, "add"),
        port,
        uuid: json_text(&v, "id"),
        alter_id: if aid.is_empty() {
            0
        } else {
            aid.parse().context("invalid alter ID")?
        },
        method: json_text(&v, "scy"),
        ..Profile::default()
    };
    p.transport.network = network(&json_text(&v, "net"))?;
    p.transport.header_type = if p.transport.network == Network::Xhttp && v.get("mode").is_some() {
        json_text(&v, "mode")
    } else {
        json_text(&v, "type")
    };
    p.transport.extra = match &v["extra"] {
        Value::String(s) => s.clone(),
        Value::Object(_) => v["extra"].to_string(),
        _ => String::new(),
    };
    p.transport.host = json_text(&v, "host");
    p.transport.path = json_text(&v, "path");
    p.transport.service_name = json_text(&v, "serviceName");
    // v2rayN traditionally stores the gRPC service name in `path`.
    if p.transport.network == Network::Grpc && p.transport.service_name.is_empty() {
        p.transport.service_name = p.transport.path.clone();
        p.transport.path.clear();
    }
    p.tls.security = security(&json_text(&v, "tls"))?;
    p.tls.sni = json_text(&v, "sni");
    p.tls.alpn = csv(&json_text(&v, "alpn"));
    p.tls.fingerprint = json_text(&v, "fp");
    p.tls.allow_insecure = truthy(&json_text(&v, "allowInsecure"))
        || v["allowInsecure"].as_bool() == Some(true);
    validate(&p)?;
    Ok(p)
}

/// Parse one share link. HTTP(S) URLs here are interpreted as proxy endpoints,
/// never fetched as subscriptions.
pub fn parse_link(s: &str) -> Result<Profile> {
    let s = s.trim();
    let (scheme, body) = s.split_once("://").context("missing share-link scheme")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme == "vmess" {
        return parse_vmess(body);
    }
    let protocol = match scheme.as_str() {
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        "ss" => Protocol::Shadowsocks,
        "socks" | "socks5" => Protocol::Socks,
        "http" | "https" => Protocol::Http,
        "hysteria2" | "hy2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        "wireguard" | "wg" => Protocol::Wireguard,
        "ssh" => Protocol::Ssh,
        "anytls" => Protocol::AnyTls,
        "hysteria" => Protocol::Hysteria,
        _ => bail!("unsupported share-link scheme: {scheme}"),
    };

    // Legacy Shadowsocks encodes the entire authority rather than just userinfo.
    let (before_fragment, fragment) = body.split_once('#').unwrap_or((body, ""));
    let (authority, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    let normalized = if protocol == Protocol::Shadowsocks && !authority.contains('@') {
        format!(
            "ss://{}{}{}{}{}",
            decode64_text(&unescape(authority)?)?,
            if query.is_empty() { "" } else { "?" },
            query,
            if fragment.is_empty() { "" } else { "#" },
            fragment
        )
    } else {
        format!("{scheme}://{body}")
    };
    let url = Url::parse(&normalized).context("invalid proxy URL")?;
    let address = url
        .host_str()
        .context("missing proxy host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url.port_or_known_default().context("missing proxy port")?;
    let mut p = Profile {
        protocol: Some(protocol),
        address,
        port,
        name: unescape(url.fragment().unwrap_or(""))?,
        ..Profile::default()
    };
    let user = unescape(url.username())?;
    let password = url.password().map(unescape).transpose()?;
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let get = |key: &str| q.get(key).map(String::as_str).unwrap_or("");

    match protocol {
        Protocol::Vless => {
            p.uuid = user;
            p.flow = get("flow").into();
        }
        Protocol::Trojan | Protocol::Hysteria2 | Protocol::AnyTls => {
            // A colon in a password should normally be percent encoded, but
            // tolerate its unescaped form as well.
            p.password = match password {
                Some(pass) => format!("{user}:{pass}"),
                None => user,
            };
        }
        Protocol::Shadowsocks => {
            let credentials = match password {
                Some(pass) => format!("{user}:{pass}"),
                None => decode64_text(&user).context("invalid Shadowsocks userinfo")?,
            };
            let (method, pass) = credentials
                .split_once(':')
                .context("Shadowsocks credentials require method:password")?;
            p.method = method.into();
            p.password = pass.into();
            let (plugin, opts) = get("plugin")
                .split_once(';')
                .unwrap_or((get("plugin"), ""));
            p.plugin = plugin.into();
            p.plugin_opts = opts.into();
        }
        Protocol::Socks | Protocol::Http => {
            if let Some(pass) = password {
                p.username = user;
                p.password = pass;
            } else if !user.is_empty() {
                // SOCKS links commonly use base64 credentials; HTTP usernames
                // without a password remain ordinary usernames.
                if protocol == Protocol::Socks {
                    if let Ok(decoded) = decode64_text(&user) {
                        if let Some((name, pass)) = decoded.split_once(':') {
                            p.username = name.into();
                            p.password = pass.into();
                        } else {
                            p.username = user;
                        }
                    } else {
                        p.username = user;
                    }
                } else {
                    p.username = user;
                }
            }
        }
        Protocol::Tuic => {
            p.uuid = user;
            p.password = password.unwrap_or_default();
            p.congestion_control = get("congestion_control").into();
        }
        Protocol::Wireguard => {
            p.private_key = match password {
                Some(pass) => format!("{user}:{pass}"),
                None => user,
            };
            p.public_key = get("publickey").into();
            p.pre_shared_key = get("presharedkey").into();
            p.local_address = csv(get("address"));
            if !get("mtu").is_empty() {
                p.mtu = get("mtu").parse().context("invalid WireGuard MTU")?;
            }
            if !get("reserved").is_empty() {
                p.reserved = csv(get("reserved"))
                    .iter()
                    .map(|s| s.parse::<u8>().context("invalid WireGuard reserved byte"))
                    .collect::<Result<_>>()?;
            }
        }
        Protocol::Ssh => {
            p.username = user;
            p.password = password.unwrap_or_default();
            if !get("pk").is_empty() {
                p.ssh_private_key =
                    decode64_text(get("pk")).context("invalid SSH private key encoding")?;
            }
            p.ssh_private_key_passphrase = get("pkp").into();
            p.ssh_host_key = csv(get("hk"));
        }
        Protocol::Hysteria => {
            if !get("protocol").is_empty() && !get("protocol").eq_ignore_ascii_case("udp") {
                bail!("hysteria v1 supports only protocol=udp");
            }
            p.password = get("auth").into();
        }
        Protocol::Vmess | Protocol::OpenVpn | Protocol::Custom => {
            bail!("unsupported URL protocol")
        }
    }

    p.transport.network = network(get("type"))?;
    p.transport.path = get("path").into();
    p.transport.host = get("host").into();
    p.transport.service_name = get("serviceName").into();
    p.transport.header_type = if p.transport.network == Network::Xhttp && q.contains_key("mode") {
        get("mode").into()
    } else {
        get("headerType").into()
    };
    if matches!(protocol, Protocol::Vless | Protocol::Vmess | Protocol::Trojan) {
        // query_pairs already percent-decodes the value; preserve the JSON text as-is.
        p.transport.extra = get("extra").into();
    }
    p.tls.security = if q.contains_key("security") {
        security(get("security"))?
    } else if matches!(
        protocol,
        Protocol::Trojan
            | Protocol::Hysteria2
            | Protocol::Tuic
            | Protocol::AnyTls
            | Protocol::Hysteria
    ) || scheme == "https"
    {
        Security::Tls
    } else {
        Security::None
    };
    p.tls.sni = if protocol == Protocol::Hysteria && q.contains_key("peer") {
        get("peer").into()
    } else {
        get("sni").into()
    };
    p.tls.fingerprint = get("fp").into();
    p.tls.alpn = csv(get("alpn"));
    p.tls.allow_insecure = truthy(get("allowInsecure"))
        || truthy(get("allow_insecure"))
        || truthy(get("insecure"));
    p.tls.reality_public_key = get("pbk").into();
    p.tls.reality_short_id = get("sid").into();
    p.tls.reality_spider_x = get("spx").into();
    p.obfs = if protocol == Protocol::Hysteria {
        get("obfsParam").into()
    } else {
        get("obfs").into()
    };
    p.obfs_password = get("obfs-password").into();
    if !get("upmbps").is_empty() {
        p.up_mbps = get("upmbps").parse().context("invalid upload rate")?;
    }
    if !get("downmbps").is_empty() {
        p.down_mbps = get("downmbps").parse().context("invalid download rate")?;
    }
    validate(&p)?;
    Ok(p)
}

/// Serialize a profile to a share link. Local IDs and subscription membership
/// are deliberately not included.
pub fn to_link(p: &Profile) -> Result<String> {
    let protocol = p.protocol.ok_or_else(|| anyhow!("profile has no protocol"))?;
    if matches!(protocol, Protocol::OpenVpn | Protocol::Custom) {
        bail!("not shareable as a link");
    }
    validate(p)?;
    if protocol == Protocol::Vmess {
        let mut v = json!({
            "v": "2", "ps": p.name, "add": p.address, "port": p.port.to_string(),
            "id": p.uuid, "aid": p.alter_id.to_string(), "scy": p.method,
            "net": network_name(p.transport.network), "type": p.transport.header_type,
            "host": p.transport.host, "path": p.transport.path,
            "serviceName": p.transport.service_name,
            "tls": if p.tls.security == Security::None { "" } else { security_name(p.tls.security) },
            "sni": p.tls.sni, "alpn": p.tls.alpn.join(","), "fp": p.tls.fingerprint,
            "allowInsecure": p.tls.allow_insecure
        });
        if !p.transport.extra.is_empty() {
            v["extra"] = json!(p.transport.extra);
        }
        if p.transport.network == Network::Xhttp {
            v["mode"] = json!(p.transport.header_type);
        }
        return Ok(format!(
            "vmess://{}",
            general_purpose::STANDARD.encode(serde_json::to_vec(&v)?)
        ));
    }
    let (scheme, credentials) = match protocol {
        Protocol::Vless => ("vless", escape(&p.uuid)),
        Protocol::Trojan => ("trojan", escape(&p.password)),
        Protocol::Shadowsocks => (
            "ss",
            general_purpose::URL_SAFE_NO_PAD.encode(format!("{}:{}", p.method, p.password)),
        ),
        Protocol::Socks => (
            "socks5",
            format!("{}:{}", escape(&p.username), escape(&p.password)),
        ),
        Protocol::Http => (
            if p.tls.security == Security::Tls {
                "https"
            } else {
                "http"
            },
            format!("{}:{}", escape(&p.username), escape(&p.password)),
        ),
        Protocol::Hysteria2 => ("hysteria2", escape(&p.password)),
        Protocol::Tuic => (
            "tuic",
            format!("{}:{}", escape(&p.uuid), escape(&p.password)),
        ),
        Protocol::Wireguard => ("wireguard", escape(&p.private_key)),
        Protocol::Ssh => (
            "ssh",
            format!("{}:{}", escape(&p.username), escape(&p.password)),
        ),
        Protocol::AnyTls => ("anytls", escape(&p.password)),
        Protocol::Hysteria => ("hysteria", String::new()),
        Protocol::Vmess | Protocol::OpenVpn | Protocol::Custom => {
            bail!("not shareable as a link")
        }
    };
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut add = |key: &str, value: &str| {
        if !value.is_empty() {
            pairs.push((key.into(), value.into()));
        }
    };
    add("type", network_name(p.transport.network));
    add("security", security_name(p.tls.security));
    add(
        if protocol == Protocol::Hysteria {
            "peer"
        } else {
            "sni"
        },
        &p.tls.sni,
    );
    add("fp", &p.tls.fingerprint);
    add("alpn", &p.tls.alpn.join(","));
    add("pbk", &p.tls.reality_public_key);
    add("sid", &p.tls.reality_short_id);
    add("spx", &p.tls.reality_spider_x);
    add("flow", &p.flow);
    add("path", &p.transport.path);
    add("host", &p.transport.host);
    add("serviceName", &p.transport.service_name);
    add(
        if p.transport.network == Network::Xhttp {
            "mode"
        } else {
            "headerType"
        },
        &p.transport.header_type,
    );
    if matches!(protocol, Protocol::Vless | Protocol::Trojan) {
        add("extra", &p.transport.extra);
    }
    if p.tls.allow_insecure {
        add(
            match protocol {
                Protocol::Hysteria2 | Protocol::AnyTls | Protocol::Hysteria => "insecure",
                Protocol::Tuic => "allow_insecure",
                _ => "allowInsecure",
            },
            "1",
        );
    }
    if !p.plugin.is_empty() {
        let plugin = if p.plugin_opts.is_empty() {
            p.plugin.clone()
        } else {
            format!("{};{}", p.plugin, p.plugin_opts)
        };
        add("plugin", &plugin);
    }
    add(
        if protocol == Protocol::Hysteria {
            "obfsParam"
        } else {
            "obfs"
        },
        &p.obfs,
    );
    add("obfs-password", &p.obfs_password);
    if p.up_mbps != 0 {
        add("upmbps", &p.up_mbps.to_string());
    }
    if p.down_mbps != 0 {
        add("downmbps", &p.down_mbps.to_string());
    }
    if protocol == Protocol::Hysteria {
        add("auth", &p.password);
        add("protocol", "udp");
    }
    if protocol == Protocol::Ssh {
        if !p.ssh_private_key.is_empty() {
            add(
                "pk",
                &general_purpose::URL_SAFE_NO_PAD.encode(p.ssh_private_key.as_bytes()),
            );
        }
        add("pkp", &p.ssh_private_key_passphrase);
        add("hk", &p.ssh_host_key.join(","));
    }
    add("congestion_control", &p.congestion_control);
    add("publickey", &p.public_key);
    add("presharedkey", &p.pre_shared_key);
    add("address", &p.local_address.join(","));
    if p.mtu != 0 {
        add("mtu", &p.mtu.to_string());
    }
    add(
        "reserved",
        &p.reserved
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(","),
    );
    let query = pairs
        .iter()
        .map(|(key, value)| format!("{}={}", escape(key), escape(value)))
        .collect::<Vec<_>>()
        .join("&");
    let host = if p.address.contains(':') {
        format!(
            "[{}]",
            p.address.trim_start_matches('[').trim_end_matches(']')
        )
    } else {
        p.address.clone()
    };
    let userinfo = if protocol == Protocol::Hysteria {
        String::new()
    } else {
        format!("{credentials}@")
    };
    Ok(format!(
        "{scheme}://{userinfo}{host}:{}?{query}#{}",
        p.port,
        escape(&p.name)
    ))
}

/// Parse a plain or base64-encoded subscription, ignoring individual bad lines.
pub fn parse_many(text: &str) -> Vec<Profile> {
    let text = text.trim().trim_start_matches('\u{feff}');
    let decoded;
    let body = if text.contains("://") {
        text
    } else {
        decoded = match decode64_text(text) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        &decoded
    };
    body.lines()
        .filter_map(|line| parse_link(line).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(link: &str) -> Profile {
        let p = parse_link(link).expect("parse fixture");
        let encoded = to_link(&p).expect("serialize fixture");
        assert_eq!(
            parse_link(&encoded).expect("parse serialized link"),
            p,
            "{encoded}"
        );
        p
    }

    #[test]
    fn uuid_dashes_remain_readable() {
        let uuid = "9706e33d-a122-4123-8123-123456789abc";
        for scheme in ["vless", "tuic"] {
            let credentials = if scheme == "tuic" {
                format!("{uuid}:password")
            } else {
                uuid.to_owned()
            };
            let p = round_trip(&format!("{scheme}://{credentials}@example.org:443"));
            let encoded = to_link(&p).expect("serialize");
            assert!(encoded.starts_with(&format!("{scheme}://{uuid}")));
            assert!(!encoded.contains("%2D"));
            assert_eq!(p.uuid, uuid);
        }

        let p = Profile {
            protocol: Some(Protocol::Vmess),
            address: "example.org".into(),
            port: 443,
            uuid: uuid.into(),
            ..Profile::default()
        };
        let encoded = to_link(&p).expect("serialize VMess");
        let payload = decode64_text(
            encoded.strip_prefix("vmess://").expect("VMess scheme"),
        )
        .expect("decode VMess");
        let value: Value = serde_json::from_str(&payload).expect("VMess JSON");
        assert_eq!(value["id"], uuid);
        assert_eq!(parse_link(&encoded).expect("parse VMess"), p);
    }

    #[test]
    fn unreserved_characters_and_reserved_delimiters() {
        assert_eq!(escape("AZaz09-._~"), "AZaz09-._~");
        assert_eq!(
            escape(" :@/?#[]&=+%"),
            "%20%3A%40%2F%3F%23%5B%5D%26%3D%2B%25"
        );

        let mut p = parse_link("ssh://user@example.org:22").expect("fixture");
        p.username = "user-._~".into();
        p.password = " :@/?#[]&=+% ایران".into();
        p.ssh_private_key_passphrase = "key-._~ :@/?#[]&=+%".into();
        p.name = "name-._~ ایران + #".into();
        let encoded = to_link(&p).expect("serialize");
        assert!(encoded.starts_with("ssh://user-._~:"));
        assert!(encoded.contains("pkp=key-._~%20%3A%40%2F%3F%23%5B%5D%26%3D%2B%25"));
        assert_eq!(parse_link(&encoded).expect("parse"), p);

        let mut p = parse_link("vless://id@example.org:443").expect("fixture");
        p.flow = "xtls-rprx-vision".into();
        p.transport.path = "/path-._~?x=one+two&y=100%#fragment".into();
        let encoded = to_link(&p).expect("serialize");
        assert!(encoded.contains("flow=xtls-rprx-vision"));
        assert!(encoded.contains(
            "path=%2Fpath-._~%3Fx%3Done%2Btwo%26y%3D100%25%23fragment"
        ));
        assert_eq!(parse_link(&encoded).expect("parse"), p);
    }

    #[test]
    fn vmess_round_trip_and_numeric_fields() {
        let v = json!({
            "v": "2", "ps": "ایران / test", "add": "example.org", "port": 443,
            "id": "uuid", "aid": 4, "scy": "auto", "net": "ws", "type": "none",
            "host": "cdn.example.org", "path": "/a?b=c", "tls": "tls",
            "sni": "example.org", "alpn": "h2,http/1.1", "fp": "chrome",
            "allowInsecure": true
        });
        let p = round_trip(&format!(
            "vmess://{}",
            general_purpose::STANDARD.encode(v.to_string())
        ));
        assert_eq!(p.alter_id, 4);
        assert_eq!(p.transport.network, Network::Ws);
        assert!(p.tls.allow_insecure);
    }

    #[test]
    fn vmess_grpc_v2rayn_path() {
        let v = json!({"add":"example.org","port":"443","id":"id","net":"grpc","path":"service"});
        let p = round_trip(&format!(
            "vmess://{}",
            general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        ));
        assert_eq!(p.transport.service_name, "service");
        assert!(p.transport.path.is_empty());
    }

    #[test]
    fn vless_reality_ipv6_round_trip() {
        let p = round_trip("vless://uuid@[2001:db8::1]:443?type=tcp&security=reality&sni=example.org&fp=chrome&pbk=public%2Bkey&sid=ab12&spx=%2Fhello&flow=xtls-rprx-vision&alpn=h2,http%2F1.1&allowInsecure=true#My%20server");
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.name, "My server");
        assert_eq!(p.tls.security, Security::Reality);
        assert_eq!(p.tls.reality_public_key, "public+key");
        assert_eq!(p.flow, "xtls-rprx-vision");
    }

    #[test]
    fn trojan_grpc_round_trip() {
        let p = round_trip("trojan://p%40ss%3Aword@example.org:443?type=grpc&serviceName=my%2Fservice&sni=example.org#Trojan");
        assert_eq!(p.password, "p@ss:word");
        assert_eq!(p.tls.security, Security::Tls);
        assert_eq!(p.transport.service_name, "my/service");
    }

    #[test]
    fn shadowsocks_forms_and_plugin() {
        let credentials = "aes-256-gcm:p@ss:word";
        let encoded = general_purpose::STANDARD.encode(credentials);
        let p = round_trip(&format!("ss://{encoded}@example.org:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.org#SS"));
        assert_eq!(p.method, "aes-256-gcm");
        assert_eq!(p.password, "p@ss:word");
        assert_eq!(p.plugin, "obfs-local");
        assert_eq!(p.plugin_opts, "obfs=http;obfs-host=example.org");

        let plain = round_trip("ss://aes-256-gcm:p%40ss%3Aword@example.org:8388#SS");
        assert_eq!(plain.password, p.password);
        let legacy = general_purpose::STANDARD.encode(format!("{credentials}@[::1]:8388"));
        let legacy = round_trip(&format!("ss://{legacy}#Legacy%20SS"));
        assert_eq!(legacy.address, "::1");
        assert_eq!(legacy.password, p.password);
        assert_eq!(legacy.name, "Legacy SS");
    }

    #[test]
    fn socks_forms_round_trip() {
        for scheme in ["socks", "socks5"] {
            let p = round_trip(&format!("{scheme}://user:p%3A%40ss@localhost:1080#SOCKS"));
            assert_eq!(p.username, "user");
            assert_eq!(p.password, "p:@ss");
            let encoded = general_purpose::URL_SAFE_NO_PAD.encode("user:p:@ss");
            let q = round_trip(&format!("{scheme}://{encoded}@localhost:1080#SOCKS"));
            assert_eq!(p, q);
        }
        let p = round_trip("socks5://localhost:1080");
        assert!(p.username.is_empty());
    }

    #[test]
    fn http_and_https_round_trip() {
        for scheme in ["http", "https"] {
            let p = round_trip(&format!("{scheme}://user:p%40ss@example.org:8080#HTTP"));
            assert_eq!(p.protocol, Some(Protocol::Http));
            assert_eq!(p.tls.security == Security::Tls, scheme == "https");
        }
        assert_eq!(round_trip("https://example.org").port, 443);
        assert_eq!(round_trip("http://example.org").port, 80);
    }

    #[test]
    fn hysteria2_aliases_round_trip() {
        for scheme in ["hy2", "hysteria2"] {
            let p = round_trip(&format!("{scheme}://pass%2Bword@example.org:443?sni=example.org&insecure=1&obfs=salamander&obfs-password=secret%2Bvalue&alpn=h3&upmbps=20&downmbps=100#HY2"));
            assert_eq!(p.protocol, Some(Protocol::Hysteria2));
            assert_eq!(p.password, "pass+word");
            assert_eq!(p.obfs, "salamander");
            assert_eq!(p.obfs_password, "secret+value");
            assert_eq!(p.up_mbps, 20);
            assert!(p.tls.allow_insecure);
        }
    }

    #[test]
    fn tuic_round_trip() {
        let p = round_trip("tuic://uuid:pass%3Aword@example.org:443?sni=example.org&alpn=h3&congestion_control=bbr&allow_insecure=1#TUIC");
        assert_eq!(p.uuid, "uuid");
        assert_eq!(p.password, "pass:word");
        assert_eq!(p.congestion_control, "bbr");
        assert!(p.tls.allow_insecure);
    }

    #[test]
    fn wireguard_aliases_round_trip() {
        for scheme in ["wg", "wireguard"] {
            let p = round_trip(&format!("{scheme}://private%2Bkey%2F%3D@[::1]:51820?publickey=public%2Bkey%3D&presharedkey=psk%3D&address=10.0.0.2%2F32,fd00%3A%3A2%2F128&mtu=1420&reserved=1,2,255#WG"));
            assert_eq!(p.private_key, "private+key/=");
            assert_eq!(p.local_address, ["10.0.0.2/32", "fd00::2/128"]);
            assert_eq!(p.reserved, [1, 2, 255]);
            assert_eq!(p.mtu, 1420);
        }
    }

    #[test]
    fn ssh_password_and_key_round_trip() {
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nkey+/=\n-----END OPENSSH PRIVATE KEY-----\n";
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(key);
        let p = round_trip(&format!(
            "ssh://us%40er:p%3A%2B%40ss@[2001:db8::1]:22?pk={encoded}&pkp=key%20phrase%2B&hk=ssh-ed25519%20AAAA,ssh-rsa%20BBBB#SSH%20ایران"
        ));
        assert_eq!(p.protocol, Some(Protocol::Ssh));
        assert_eq!(p.username, "us@er");
        assert_eq!(p.password, "p:+@ss");
        assert_eq!(p.ssh_private_key, key);
        assert_eq!(p.ssh_private_key_passphrase, "key phrase+");
        assert_eq!(p.ssh_host_key, ["ssh-ed25519 AAAA", "ssh-rsa BBBB"]);
        assert_eq!(p.address, "2001:db8::1");
        assert_eq!(p.name, "SSH ایران");

        let p = round_trip("ssh://user@example.org:22#Key%20only");
        assert_eq!(p.username, "user");
        assert!(p.password.is_empty());
        assert!(p.ssh_private_key.is_empty());
        assert!(p.ssh_host_key.is_empty());

        let padded = general_purpose::URL_SAFE.encode(key);
        let p = round_trip(&format!("ssh://user@example.org:2222?pk={padded}"));
        assert_eq!(p.ssh_private_key, key);
    }

    #[test]
    fn anytls_round_trip() {
        let p = round_trip("anytls://p%40ss%3A%2Bword@example.org:443?sni=tls.example.org&insecure=1&fp=chrome&alpn=h2,http%2F1.1#Any%20TLS");
        assert_eq!(p.protocol, Some(Protocol::AnyTls));
        assert_eq!(p.password, "p@ss:+word");
        assert_eq!(p.tls.security, Security::Tls);
        assert_eq!(p.tls.sni, "tls.example.org");
        assert_eq!(p.tls.fingerprint, "chrome");
        assert_eq!(p.tls.alpn, ["h2", "http/1.1"]);
        assert!(p.tls.allow_insecure);
        assert_eq!(p.name, "Any TLS");
        assert_eq!(
            round_trip("anytls://secret@example.org:443").tls.security,
            Security::Tls
        );
    }

    #[test]
    fn hysteria_v1_round_trip() {
        let p = round_trip("hysteria://[2001:db8::2]:443?auth=p%40ss%3A%2B&peer=tls.example.org&insecure=1&upmbps=25&downmbps=100&obfsParam=obfs%2Bsecret&alpn=h3&protocol=udp#HY%201");
        assert_eq!(p.protocol, Some(Protocol::Hysteria));
        assert_eq!(p.password, "p@ss:+");
        assert_eq!(p.address, "2001:db8::2");
        assert_eq!(p.tls.security, Security::Tls);
        assert_eq!(p.tls.sni, "tls.example.org");
        assert!(p.tls.allow_insecure);
        assert_eq!(p.tls.alpn, ["h3"]);
        assert_eq!(p.up_mbps, 25);
        assert_eq!(p.down_mbps, 100);
        assert_eq!(p.obfs, "obfs+secret");
        let link = to_link(&p).expect("serialize");
        assert!(link.starts_with("hysteria://["));
        assert!(link.contains("auth="));
        assert!(link.contains("peer="));
        assert!(link.contains("obfsParam="));
        assert!(link.contains("protocol=udp"));
        round_trip("hysteria://example.org:443");
        assert!(parse_link("hysteria://example.org:443?protocol=tcp").is_err());
        assert!(parse_link("hysteria://example.org:443?protocol=faketcp").is_err());
    }

    #[test]
    fn raw_profiles_are_not_shareable() {
        for protocol in [Protocol::OpenVpn, Protocol::Custom] {
            let p = Profile {
                protocol: Some(protocol),
                ..Profile::default()
            };
            assert_eq!(
                to_link(&p).expect_err("raw config is not a link").to_string(),
                "not shareable as a link"
            );
        }
    }

    #[test]
    fn all_transports_and_aliases() {
        for (name, expected) in [
            ("tcp", Network::Tcp),
            ("ws", Network::Ws),
            ("grpc", Network::Grpc),
            ("h2", Network::H2),
            ("http", Network::H2),
            ("httpupgrade", Network::HttpUpgrade),
            ("xhttp", Network::Xhttp),
            ("splithttp", Network::Xhttp),
            ("kcp", Network::Kcp),
            ("mkcp", Network::Kcp),
            ("quic", Network::Quic),
        ] {
            let p = round_trip(&format!("vless://id@example.org:443?type={name}&path=%2Fa%3Fb%3Dc&host=cdn.example.org&serviceName=svc&headerType=http&mode=auto"));
            assert_eq!(p.transport.network, expected);
            assert_eq!(
                p.transport.header_type,
                if expected == Network::Xhttp {
                    "auto"
                } else {
                    "http"
                }
            );
        }
    }

    #[test]
    fn xhttp_extra_and_stream_up_round_trip() {
        let extra = r#"{"xPaddingBytes":"100-1000","xPaddingObfsMode":true}"#;
        let encoded = "%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22xPaddingObfsMode%22%3Atrue%7D";
        for scheme in ["vless", "trojan"] {
            let p = round_trip(&format!(
                "{scheme}://credential@example.org:443?type=xhttp&mode=stream-up&extra={encoded}"
            ));
            assert_eq!(p.transport.extra, extra);
            assert_eq!(p.transport.header_type, "stream-up");
            let link = to_link(&p).expect("serialize");
            assert!(link.contains(&format!("extra={encoded}")));
            assert!(link.contains("mode=stream-up"));
        }

        // VMess uses base64 JSON rather than URL query parameters.
        for extra_value in [json!(extra), serde_json::from_str::<Value>(extra).expect("object")] {
            let v = json!({
                "add": "example.org", "port": 443, "id": "uuid",
                "net": "xhttp", "mode": "stream-up", "extra": extra_value
            });
            let p = round_trip(&format!(
                "vmess://{}",
                general_purpose::STANDARD.encode(v.to_string())
            ));
            assert_eq!(
                serde_json::from_str::<Value>(&p.transport.extra).expect("extra"),
                serde_json::from_str::<Value>(extra).expect("expected extra")
            );
            assert_eq!(p.transport.header_type, "stream-up");
        }
    }

    #[test]
    fn subscriptions_all_base64_variants_and_plain() {
        let body = "\n# comment\nvless://id@example.org:443#One\ninvalid\nss://YWVzLTEyOC1nY206cGFzcw@example.org:8388#Two\n";
        assert_eq!(parse_many(body).len(), 2);
        for engine in [
            &general_purpose::STANDARD,
            &general_purpose::STANDARD_NO_PAD,
            &general_purpose::URL_SAFE,
            &general_purpose::URL_SAFE_NO_PAD,
        ] {
            let encoded = engine.encode(body);
            assert_eq!(parse_many(&encoded), parse_many(body));
            let wrapped = encoded
                .as_bytes()
                .chunks(17)
                .map(|chunk| std::str::from_utf8(chunk).expect("ASCII"))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(parse_many(&wrapped), parse_many(body));
        }
        assert!(parse_many("not a subscription").is_empty());
        assert_eq!(parse_many("\u{feff}vless://id@example.org:443").len(), 1);
    }

    #[test]
    fn subscriptions_with_new_schemes() {
        let body = "ssh://user:pass@example.org:22\nanytls://pass@example.org:443\nhysteria://example.org:443?auth=pass\n";
        let profiles = parse_many(body);
        assert_eq!(profiles.len(), 3);
        assert_eq!(profiles[0].protocol, Some(Protocol::Ssh));
        assert_eq!(profiles[1].protocol, Some(Protocol::AnyTls));
        assert_eq!(profiles[2].protocol, Some(Protocol::Hysteria));
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(body);
        assert_eq!(parse_many(&encoded), profiles);
    }

    #[test]
    fn rejects_bad_input_without_panicking() {
        for link in [
            "",
            "no scheme",
            "ftp://example.org:21",
            "vmess://!!!",
            "vmess://W10=",
            "vless://id@:443",
            "vless://id@example.org",
            "vless://id@example.org:0",
            "vless://id@example.org:99999",
            "vless://id@example.org:443?type=unknown",
            "vless://id@example.org:443?security=unknown",
            "ss://not-base64@example.org:8388",
            "ss://!!!",
            "wg://key@example.org:51820?reserved=256",
            "wg://key@example.org:51820?mtu=no",
            "hy2://pass@example.org:443?upmbps=no",
            "ssh://user@example.org:22?pk=!!!",
            "ssh://user@example.org:22?pk=_w",
            "ssh://user@example.org:0",
            "anytls://pass@example.org",
            "hysteria://example.org:443?upmbps=no",
            "hysteria://example.org:443?downmbps=-1",
        ] {
            assert!(parse_link(link).is_err(), "{link}");
        }
        assert!(to_link(&Profile::default()).is_err());
    }

    #[test]
    fn local_metadata_is_not_exported() {
        let mut p = parse_link("vless://uuid@example.org:443#Name").expect("fixture");
        p.id = "12345678".into();
        p.subscription_id = Some("subscription".into());
        let q = parse_link(&to_link(&p).expect("export")).expect("import");
        assert!(q.id.is_empty());
        assert!(q.subscription_id.is_none());
        p.id.clear();
        p.subscription_id = None;
        assert_eq!(p, q);
    }
}
