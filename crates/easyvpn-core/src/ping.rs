use crate::{Profile, Protocol};
use anyhow::{anyhow, bail, Context, Result};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// The first remote can override the global protocol. OpenVPN defaults to UDP.
fn openvpn_uses_tcp(config: &str) -> bool {
    let mut global_proto = None;
    let mut remote_proto = None;
    let mut found_remote = false;
    let mut inline_block = false;

    for line in config.lines() {
        let line = line.trim();
        // Do not interpret embedded certificates, keys, or other inline data as options.
        if line.starts_with("</") {
            inline_block = false;
            continue;
        }
        if line.starts_with('<') {
            inline_block = true;
            continue;
        }
        if inline_block || line.starts_with(['#', ';']) {
            continue;
        }

        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("proto") => global_proto = fields.next(),
            Some("remote") if !found_remote => {
                if fields.next().is_some() {
                    found_remote = true;
                    // remote host [port] [proto]
                    let port_or_proto = fields.next();
                    remote_proto = match port_or_proto {
                        Some(value) if value.parse::<u16>().is_ok() => fields.next(),
                        Some(value) if !value.starts_with(['#', ';']) => Some(value),
                        _ => None,
                    };
                    if remote_proto.is_some_and(|value| value.starts_with(['#', ';'])) {
                        remote_proto = None;
                    }
                }
            }
            _ => {}
        }
    }

    found_remote
        && matches!(
            remote_proto.or(global_proto),
            Some("tcp" | "tcp-client" | "tcp4" | "tcp4-client" | "tcp6" | "tcp6-client")
        )
}

pub fn tcp_ping(p: &Profile, timeout: Duration) -> Result<Duration> {
    match p.protocol {
        Some(
            Protocol::Hysteria
            | Protocol::Hysteria2
            | Protocol::Tuic
            | Protocol::Wireguard,
        ) => {
            bail!("TCP ping is not available for UDP-only protocols")
        }
        Some(Protocol::OpenVpn) if !openvpn_uses_tcp(&p.raw_config) => bail!("udp"),
        Some(Protocol::Custom) => bail!("custom config"),
        None => bail!("profile has no protocol"),
        _ => {}
    }
    if timeout.is_zero() {
        bail!("ping timeout must be positive");
    }

    let start = Instant::now();
    let addresses: Vec<_> = (p.address.as_str(), p.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}:{}", p.address, p.port))?
        .collect();
    let mut last_error = None;
    for address in addresses {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            bail!("TCP ping timed out");
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(_stream) => return Ok(start.elapsed()),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error).context("TCP ping failed"),
        None => Err(anyhow!("hostname resolved to no addresses")),
    }
}

pub fn ping_all(profiles: &[Profile], timeout: Duration) -> Vec<(String, Option<u128>)> {
    let mut results = Vec::with_capacity(profiles.len());
    // Scoped batches bound both active connections and thread count. Joining in
    // input order means completion order cannot reorder the returned results.
    for batch in profiles.chunks(32) {
        std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|profile| {
                    scope.spawn(move || tcp_ping(profile, timeout).ok().map(|d| d.as_millis()))
                })
                .collect();
            for (profile, handle) in batch.iter().zip(handles) {
                results.push((profile.id.clone(), handle.join().unwrap_or(None)));
            }
        });
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_order_across_batches() {
        let profiles: Vec<_> = (0..75)
            .rev()
            .map(|index| Profile {
                id: format!("id-{index}"),
                protocol: Some(match index % 4 {
                    0 => Protocol::Hysteria2,
                    1 => Protocol::Tuic,
                    2 => Protocol::Wireguard,
                    _ => Protocol::Hysteria,
                }),
                address: "invalid.example".into(),
                port: 443,
                ..Profile::default()
            })
            .collect();
        let results = ping_all(&profiles, Duration::from_millis(10));
        assert_eq!(results.len(), profiles.len());
        for ((id, latency), profile) in results.iter().zip(&profiles) {
            assert_eq!(id, &profile.id);
            assert!(latency.is_none());
        }
        assert!(ping_all(&[], Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn pings_local_tcp_listener() -> Result<()> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let profile = Profile {
            protocol: Some(Protocol::Socks),
            address: "127.0.0.1".into(),
            port: listener.local_addr()?.port(),
            ..Profile::default()
        };
        assert!(tcp_ping(&profile, Duration::from_secs(2)).is_ok());
        assert!(tcp_ping(&profile, Duration::ZERO).is_err());
        Ok(())
    }

    #[test]
    fn detects_openvpn_tcp_protocol() {
        for config in [
            "client\nproto tcp\nremote example.com 1194",
            "client\nproto tcp-client\nremote example.com",
            "remote example.com 443 tcp",
            "remote example.com 443 tcp-client\nproto udp",
            "remote [::1] 443 tcp6-client",
            "# proto udp\nproto tcp\nremote example.com 443 # comment",
        ] {
            assert!(openvpn_uses_tcp(config), "{config}");
        }
        for config in [
            "",
            "proto tcp",
            "client\nremote example.com 1194",
            "proto udp\nremote example.com 1194",
            "proto tcp\nremote example.com 1194 udp",
            "# remote example.com 443 tcp\nremote example.com 1194",
            "remote example.com 1194\nremote example.com 443 tcp",
            "<key>\nproto tcp\n</key>\nremote example.com",
        ] {
            assert!(!openvpn_uses_tcp(config), "{config}");
        }
    }

    #[test]
    fn openvpn_pings_only_tcp_and_custom_is_rejected() -> Result<()> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let mut profile = Profile {
            protocol: Some(Protocol::OpenVpn),
            address: "127.0.0.1".into(),
            port: listener.local_addr()?.port(),
            raw_config: "client\nproto tcp-client\nremote 127.0.0.1".into(),
            ..Profile::default()
        };
        assert!(tcp_ping(&profile, Duration::from_secs(2)).is_ok());
        profile.raw_config = "client\nremote 127.0.0.1 1194 udp".into();
        assert_eq!(
            tcp_ping(&profile, Duration::from_secs(2))
                .expect_err("UDP remote")
                .to_string(),
            "udp"
        );
        profile.protocol = Some(Protocol::Custom);
        assert_eq!(
            tcp_ping(&profile, Duration::from_secs(2))
                .expect_err("custom profile")
                .to_string(),
            "custom config"
        );
        Ok(())
    }
}
