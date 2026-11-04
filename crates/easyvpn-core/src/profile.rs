//! Shared data model.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vmess,
    Vless,
    Trojan,
    Shadowsocks,
    Socks,
    Http,
    Hysteria2,
    Tuic,
    Wireguard,
    Ssh,
    #[serde(rename = "anytls")]
    AnyTls,
    Hysteria,
    #[serde(rename = "openvpn")]
    OpenVpn,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Tcp,
    Ws,
    Grpc,
    H2,
    HttpUpgrade,
    Xhttp,
    Kcp,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    #[default]
    None,
    Tls,
    Reality,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Transport {
    pub network: Network,
    pub path: String,
    pub host: String,
    pub service_name: String,
    pub header_type: String,
    pub extra: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tls {
    pub security: Security,
    pub sni: String,
    pub alpn: Vec<String>,
    pub fingerprint: String,
    pub allow_insecure: bool,
    pub reality_public_key: String,
    pub reality_short_id: String,
    pub reality_spider_x: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub protocol: Option<Protocol>,
    pub address: String,
    pub port: u16,
    pub uuid: String,
    pub password: String,
    pub username: String,
    pub method: String,
    pub alter_id: u32,
    pub flow: String,
    pub plugin: String,
    pub plugin_opts: String,
    pub obfs: String,
    pub obfs_password: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub congestion_control: String,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: String,
    pub local_address: Vec<String>,
    pub mtu: u32,
    pub reserved: Vec<u8>,
    pub ssh_private_key: String,
    pub ssh_private_key_passphrase: String,
    pub ssh_host_key: Vec<String>,
    pub ssh_client_version: String,
    pub raw_config: String,
    pub custom_core: Option<CoreKind>,
    pub transport: Transport,
    pub tls: Tls,
    pub subscription_id: Option<String>,
}

impl Profile {
    pub fn supported_cores(&self) -> Vec<CoreKind> {
        match self.protocol {
            Some(Protocol::Custom) => self.custom_core.into_iter().collect(),
            Some(protocol) => CoreKind::ALL
                .into_iter()
                .filter(|core| core.supports(protocol))
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn pick_core(&self, preferred: CoreKind) -> Option<CoreKind> {
        let supported = self.supported_cores();
        if supported.contains(&preferred) {
            Some(preferred)
        } else {
            supported.first().copied()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoreKind {
    #[default]
    Xray,
    SingBox,
    Mihomo,
    #[serde(rename = "openvpn")]
    OpenVpn,
}

impl CoreKind {
    pub const ALL: [CoreKind; 4] = [
        CoreKind::Xray,
        CoreKind::SingBox,
        CoreKind::Mihomo,
        CoreKind::OpenVpn,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Xray => "xray",
            Self::SingBox => "sing-box",
            Self::Mihomo => "mihomo",
            Self::OpenVpn => "openvpn",
        }
    }

    pub fn supports(self, p: Protocol) -> bool {
        use Protocol::*;
        match self {
            Self::Xray => matches!(
                p,
                Vmess | Vless | Trojan | Shadowsocks | Socks | Http | Wireguard | Custom
            ),
            Self::SingBox | Self::Mihomo => p != OpenVpn,
            Self::OpenVpn => p == OpenVpn,
        }
    }

    pub fn is_tunnel(self) -> bool {
        self == Self::OpenVpn
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    #[default]
    Global,
    BypassIran,
    BypassLan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    #[default]
    Local,
    System,
    Tun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    #[default]
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    #[default]
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub id: String,
    pub kind: RuleKind,
    pub value: String,
    pub action: RuleAction,
    pub enabled: bool,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            id: String::new(),
            kind: RuleKind::Domain,
            value: String::new(),
            action: RuleAction::Proxy,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultRoute {
    #[default]
    Proxy,
    Direct,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub core: CoreKind,
    pub listen: String,
    pub mixed_port: u16,
    pub routing: RoutingMode,
    pub mode: ProxyMode,
    #[serde(skip_serializing)]
    pub system_proxy: bool,
    #[serde(skip_serializing)]
    pub tun: bool,
    pub remote_dns: String,
    pub direct_dns: String,
    pub allow_lan: bool,
    pub log_level: String,
    pub rules: Vec<Rule>,
    pub default_route: DefaultRoute,
    pub bypass: crate::rules::BypassSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            core: CoreKind::Xray,
            listen: "127.0.0.1".into(),
            mixed_port: 10808,
            routing: RoutingMode::BypassLan,
            mode: ProxyMode::Local,
            system_proxy: false,
            tun: false,
            remote_dns: "https://1.1.1.1/dns-query".into(),
            direct_dns: "8.8.8.8".into(),
            allow_lan: false,
            log_level: "warning".into(),
            rules: Vec::new(),
            default_route: DefaultRoute::Proxy,
            bypass: crate::rules::BypassSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_settings_and_rule_defaults() {
        let settings: Settings = serde_json::from_str("{}").expect("settings");
        assert!(settings.rules.is_empty());
        assert_eq!(settings.default_route, DefaultRoute::Proxy);
        let rule: Rule = serde_json::from_str(r#"{"kind":"domain-suffix","value":"example.org"}"#)
            .expect("rule");
        assert!(rule.enabled);
        assert_eq!(rule.action, RuleAction::Proxy);
        assert_eq!(rule.kind, RuleKind::DomainSuffix);
    }
}
