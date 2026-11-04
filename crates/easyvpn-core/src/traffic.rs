//! Traffic counters, connectivity checks, and public-IP discovery.
//!
//! Custom configurations do not have app-managed stats or proxy endpoints.
//! Callers with a profile must exclude Custom profiles before calling `totals`.

use crate::{CoreKind, Profile, Protocol, Settings};
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::time::{Duration, Instant};

/// Loopback port of the core's stats endpoint.
pub fn stats_port(s: &Settings) -> u16 {
    s.mixed_port.saturating_add(2)
}

/// Cumulative (upload, download) bytes through the proxy.
///
/// Callers must not invoke this function for Custom configurations.
pub fn totals(kind: CoreKind, s: &Settings) -> Result<(u64, u64)> {
    let path = match kind {
        CoreKind::Xray => "debug/vars",
        CoreKind::SingBox | CoreKind::Mihomo => "connections",
        CoreKind::OpenVpn => bail!("OpenVPN traffic statistics are unsupported"),
    };
    s.mixed_port
        .checked_add(2)
        .context("stats port overflows u16")?;

    let url = format!("http://127.0.0.1:{}/{path}", stats_port(s));
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(1))
        .build();
    let body: Value = agent
        .get(&url)
        .call()
        .context("request core traffic statistics")?
        .into_json()
        .context("decode core traffic statistics")?;

    match kind {
        CoreKind::Xray => parse_xray_totals(&body),
        CoreKind::SingBox | CoreKind::Mihomo => parse_connections_totals(&body),
        CoreKind::OpenVpn => bail!("OpenVPN traffic statistics are unsupported"),
    }
}

fn counter(body: &Value, pointer: &str) -> Result<u64> {
    body.pointer(pointer)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing or invalid traffic counter {pointer}"))
}

fn parse_xray_totals(body: &Value) -> Result<(u64, u64)> {
    Ok((
        counter(body, "/stats/outbound/proxy/uplink")?,
        counter(body, "/stats/outbound/proxy/downlink")?,
    ))
}

fn parse_connections_totals(body: &Value) -> Result<(u64, u64)> {
    Ok((
        counter(body, "/uploadTotal")?,
        counter(body, "/downloadTotal")?,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpInfo {
    pub ip: String,
    pub country: String,
    pub country_code: String,
}

/// Build a fresh agent with no implicit environment/system proxy.
///
/// In particular, `None` must actually test the OS route, not an HTTP_PROXY
/// environment variable. Redirects are disabled so a captive portal cannot
/// turn a redirect into a successful connectivity check.
fn request_agent(proxy: Option<&str>, timeout: Duration) -> Result<ureq::Agent> {
    anyhow::ensure!(!timeout.is_zero(), "request timeout must be nonzero");
    let mut builder = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout(timeout);
    if let Some(url) = proxy {
        let parsed = url::Url::parse(url).context("invalid HTTP proxy URL")?;
        anyhow::ensure!(
            matches!(parsed.scheme(), "http" | "https" | "socks5" | "socks5h"),
            "invalid HTTP proxy URL: unsupported scheme"
        );
        anyhow::ensure!(
            parsed.host_str().is_some() && parsed.port_or_known_default().is_some(),
            "invalid HTTP proxy URL: host and port are required"
        );
        builder = builder.proxy(ureq::Proxy::new(url).context("invalid HTTP proxy URL")?);
    }
    Ok(builder.build())
}

/// Well-known endpoints tried in order, with the status each one answers when reachable.
const PROBE_SITES: [(&str, u16); 5] = [
    ("https://www.gstatic.com/generate_204", 204),
    ("https://cp.cloudflare.com/generate_204", 204),
    ("https://www.google.com/generate_204", 204),
    ("https://www.apple.com/library/test/success.html", 200),
    ("https://www.msftconnecttest.com/connecttest.txt", 200),
];

/// Real connectivity test using a new connection on every call.
///
/// `None` tests the OS route, which is required to verify a full-device tunnel.
/// The timeout is ureq's overall deadline for each site; the sites are tried in
/// order and the first one that answers correctly proves connectivity. Hung
/// sites stop the walk after three timeouts so a dead link fails in bounded time.
pub fn probe(via: Option<&str>, timeout: Duration) -> Result<Duration> {
    let agent = request_agent(via, timeout)?;
    let started = Instant::now();
    let mut last_error = None;
    for (url, expected) in PROBE_SITES {
        if last_error.is_some() && started.elapsed() >= timeout * 3 {
            break;
        }
        let result = agent
            .get(url)
            .set("Cache-Control", "no-cache")
            .set("Connection", "close")
            .call()
            .map_err(anyhow::Error::from)
            .and_then(|response| validate_probe_status(response.status(), expected));
        match result {
            Ok(()) => return Ok(started.elapsed()),
            Err(error) => last_error = Some(error.context(url)),
        }
    }
    Err(last_error
        .expect("PROBE_SITES is not empty")
        .context(format!("connectivity test failed on all {} sites", PROBE_SITES.len())))
}

fn validate_probe_status(status: u16, expected: u16) -> Result<()> {
    anyhow::ensure!(
        status == expected,
        "connectivity test expected HTTP {expected}, received HTTP {status}"
    );
    Ok(())
}

/// Discover the public IP through an HTTP proxy, or directly for a tunnel.
pub fn public_ip(proxy: Option<&str>) -> Result<IpInfo> {
    let body: Value = request_agent(proxy, Duration::from_secs(8))?
        .get("https://ipwho.is/")
        .call()
        .context("request public IP")?
        .into_json()
        .context("decode public IP response")?;
    parse_ip_info(&body)
}

fn parse_ip_info(body: &Value) -> Result<IpInfo> {
    if body.get("success").and_then(Value::as_bool) == Some(false) {
        bail!(
            "public IP lookup failed: {}",
            body.get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    let field = |key: &str| -> Result<String> {
        body.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .with_context(|| format!("missing or invalid public IP field {key}"))
    };
    let ip = field("ip")?;
    ip.parse::<std::net::IpAddr>()
        .context("invalid public IP address")?;
    Ok(IpInfo {
        ip,
        country: field("country")?,
        country_code: field("country_code")?,
    })
}

/// App-managed local HTTP proxy URL, absent for tunnels and raw configurations.
pub fn local_http_proxy(kind: CoreKind, p: &Profile, s: &Settings) -> Option<String> {
    if kind.is_tunnel() || matches!(p.protocol, Some(Protocol::Custom | Protocol::OpenVpn)) {
        return None;
    }
    let port = match kind {
        CoreKind::Xray => s.mixed_port.checked_add(1)?,
        _ => s.mixed_port,
    };
    if port == 0 {
        return None;
    }
    Some(format!("http://127.0.0.1:{port}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_204_proves_connectivity() {
        assert!(validate_probe_status(204, 204).is_ok());
        assert!(validate_probe_status(200, 200).is_ok());
        for status in [200, 201, 301, 302, 307, 400, 403, 500, 503] {
            assert!(validate_probe_status(status, 204).is_err());
        }
    }

    #[test]
    fn invalid_probe_options_fail_without_network_access() {
        assert!(probe(None, Duration::ZERO).is_err());
        assert!(request_agent(Some("not a proxy URL"), Duration::from_secs(1)).is_err());
    }

    #[test]
    fn xray_counters() {
        let body = json!({
            "stats": {
                "outbound": {
                    "proxy": {"uplink": 1234, "downlink": 9876},
                    "direct": {"uplink": 99999, "downlink": 99999}
                }
            }
        });
        assert_eq!(parse_xray_totals(&body).expect("counters"), (1234, 9876));
        assert_eq!(
            parse_xray_totals(&json!({
                "stats":{"outbound":{"proxy":{"uplink":0,"downlink":u64::MAX}}}
            }))
            .expect("large counters"),
            (0, u64::MAX)
        );
    }

    #[test]
    fn connections_counters() {
        let body = json!({"uploadTotal":42,"downloadTotal":2048,"connections":[]});
        assert_eq!(parse_connections_totals(&body).expect("counters"), (42, 2048));
    }

    #[test]
    fn invalid_counters_are_errors() {
        for body in [
            json!({}),
            json!({"uploadTotal": -1, "downloadTotal": 0}),
            json!({"uploadTotal": "1", "downloadTotal": 0}),
            json!({"uploadTotal": 1.5, "downloadTotal": 0}),
            json!({"uploadTotal": 1}),
        ] {
            assert!(parse_connections_totals(&body).is_err());
        }
        assert!(parse_xray_totals(&json!({})).is_err());
        assert!(parse_xray_totals(&json!({
            "stats":{"outbound":{"proxy":{"uplink":0,"downlink":null}}}
        }))
        .is_err());
    }

    #[test]
    fn public_ip_response() {
        let info = parse_ip_info(&json!({
            "success":true,"ip":"203.0.113.10","country":"Example","country_code":"EX"
        }))
        .expect("IP info");
        assert_eq!(info.ip, "203.0.113.10");
        assert_eq!(info.country, "Example");
        assert_eq!(info.country_code, "EX");
        assert!(parse_ip_info(&json!({"success":false,"message":"rate limited"})).is_err());
        assert!(parse_ip_info(&json!({})).is_err());
        assert!(parse_ip_info(&json!({
            "ip":"not an IP","country":"Example","country_code":"EX"
        }))
        .is_err());
    }

    #[test]
    fn endpoint_ports_and_proxy_urls() {
        let s = Settings::default();
        let mut p = Profile {
            protocol: Some(Protocol::Vless),
            ..Profile::default()
        };
        assert_eq!(stats_port(&s), s.mixed_port + 2);
        assert_eq!(
            local_http_proxy(CoreKind::Xray, &p, &s),
            Some(format!("http://127.0.0.1:{}", s.mixed_port + 1))
        );
        for kind in [CoreKind::SingBox, CoreKind::Mihomo] {
            assert_eq!(
                local_http_proxy(kind, &p, &s),
                Some(format!("http://127.0.0.1:{}", s.mixed_port))
            );
        }
        assert!(local_http_proxy(CoreKind::OpenVpn, &p, &s).is_none());
        p.protocol = Some(Protocol::Custom);
        for kind in CoreKind::ALL {
            assert!(local_http_proxy(kind, &p, &s).is_none());
        }
        assert!(totals(CoreKind::OpenVpn, &s).is_err());
        let overflow = Settings {
            mixed_port: u16::MAX,
            ..s
        };
        assert_eq!(stats_port(&overflow), u16::MAX);
        p.protocol = Some(Protocol::Vless);
        assert!(local_http_proxy(CoreKind::Xray, &p, &overflow).is_none());
        assert!(totals(CoreKind::Xray, &overflow).is_err());
    }
}
