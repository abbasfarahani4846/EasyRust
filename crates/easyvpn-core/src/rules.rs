//! Downloadable, normalized bypass lists. Parsing and merging never access the network.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFormat {
    #[default]
    Domains,
    Cidrs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BypassSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: SourceFormat,
    pub enabled: bool,
    pub builtin: bool,
    pub updated_at: u64,
    pub entries: usize,
}

impl Default for BypassSource {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            format: SourceFormat::Domains,
            enabled: true,
            builtin: false,
            updated_at: 0,
            entries: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BypassSettings {
    pub enabled: bool,
    pub country: String,
    pub sources: Vec<BypassSource>,
    pub tld_suffix: bool,
}

impl Default for BypassSettings {
    fn default() -> Self {
        Self {
            // Legacy routing modes remain authoritative until explicitly enabled.
            enabled: false,
            country: String::new(),
            sources: Vec::new(),
            tld_suffix: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleEntries {
    pub suffixes: Vec<String>,
    pub full: Vec<String>,
    pub keywords: Vec<String>,
    pub cidrs: Vec<String>,
}

impl RuleEntries {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.suffixes.len() + self.full.len() + self.keywords.len() + self.cidrs.len()
    }

    fn normalize(&mut self) {
        for values in [
            &mut self.suffixes,
            &mut self.full,
            &mut self.keywords,
            &mut self.cidrs,
        ] {
            values.sort_unstable();
            values.dedup();
        }
    }

    fn extend(&mut self, other: Self) {
        self.suffixes.extend(other.suffixes);
        self.full.extend(other.full);
        self.keywords.extend(other.keywords);
        self.cidrs.extend(other.cidrs);
    }
}

fn country_code(country: &str) -> Option<String> {
    let country = country.trim();
    (country.len() == 2 && country.bytes().all(|b| b.is_ascii_alphabetic()))
        .then(|| country.to_ascii_lowercase())
}

/// A fresh agent with no configured proxy; bypass discovery must be direct.
pub fn detect_country() -> Result<String> {
    let response: serde_json::Value = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build()
        .get("https://ipwho.is/")
        .call()
        .context("detecting country directly")?
        .into_json()
        .context("decoding country response")?;
    if response.get("success").and_then(|v| v.as_bool()) == Some(false) {
        bail!("country lookup failed");
    }
    response["country_code"]
        .as_str()
        .and_then(country_code)
        .context("country lookup returned no valid country_code")
}

pub fn recommended_sources(country: &str) -> Vec<BypassSource> {
    let Some(cc) = country_code(country) else {
        return Vec::new();
    };
    let make = |name: String, url: String, format, enabled| BypassSource {
        id: crate::store::new_id(),
        name,
        url,
        format,
        enabled,
        builtin: true,
        ..BypassSource::default()
    };
    let mut sources = vec![make(
        format!("IP ranges ({})", cc.to_ascii_uppercase()),
        format!("https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone"),
        SourceFormat::Cidrs,
        true,
    )];
    match cc.as_str() {
        "ir" => {
            sources.push(make(
                "Iran domains (Chocolate4U)".into(),
                "https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/ir.txt".into(),
                SourceFormat::Domains,
                true,
            ));
            sources.push(make(
                "Iran hosted domains (bootmortis, large)".into(),
                "https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt"
                    .into(),
                SourceFormat::Domains,
                false,
            ));
        }
        "cn" => sources.push(make(
            "China domains (felixonmars)".into(),
            "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf".into(),
            SourceFormat::Domains,
            true,
        )),
        _ => {}
    }
    sources
}

fn cache_path(src: &BypassSource) -> Result<PathBuf> {
    if src.id.is_empty()
        || !src.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid bypass source id");
    }
    Ok(crate::store::data_dir().join("rules").join(format!("{}.txt", src.id)))
}

fn domain(value: &str) -> Option<String> {
    let value = value.trim().trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
    let ascii = url::Host::parse(value).ok()?;
    let url::Host::Domain(value) = ascii else {
        return None;
    };
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn cidr(value: &str) -> Option<String> {
    let (ip, prefix) = value.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    match ip {
        IpAddr::V4(ip) if prefix <= 32 => {
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Some(format!("{}/{}", std::net::Ipv4Addr::from(u32::from(ip) & mask), prefix))
        }
        IpAddr::V6(ip) if prefix <= 128 => {
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            Some(format!("{}/{}", std::net::Ipv6Addr::from(u128::from(ip) & mask), prefix))
        }
        _ => None,
    }
}

/// Plain domains are suffixes. Invalid records and unsupported regexps are
/// deliberately skipped rather than broadened into unintended bypass rules.
pub fn parse(text: &str, format: SourceFormat) -> RuleEntries {
    let mut entries = RuleEntries::default();
    for line in text.trim_start_matches('\u{feff}').lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with("//") {
            continue;
        }
        if format == SourceFormat::Cidrs {
            if let Some(value) = cidr(line) {
                entries.cidrs.push(value);
            }
            continue;
        }
        if line.starts_with("regexp:") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("server=/") {
            // dnsmasq also allows server=/a.example/b.example/1.1.1.1.
            if let Some((domains, _server)) = rest.rsplit_once('/') {
                for value in domains.split('/') {
                    if let Some(value) = domain(value) {
                        entries.suffixes.push(value);
                    }
                }
            }
            continue;
        }
        let (kind, value) = if let Some(value) = line.strip_prefix("domain:") {
            ("suffix", value)
        } else if let Some(value) = line.strip_prefix("full:") {
            ("full", value)
        } else if let Some(value) = line.strip_prefix("keyword:") {
            ("keyword", value)
        } else {
            ("suffix", line)
        };
        // v2fly lists can annotate records with whitespace-separated @attributes.
        let value = value.split_whitespace().next().unwrap_or("");
        if kind == "keyword" {
            if !value.is_empty() && !value.chars().any(char::is_control) {
                entries.keywords.push(value.to_lowercase());
            }
        } else if let Some(value) = domain(value) {
            if kind == "full" {
                entries.full.push(value);
            } else {
                entries.suffixes.push(value);
            }
        }
    }
    entries.normalize();
    entries
}

/// Cache uses the same text formats accepted by `parse`, preserving exact and
/// keyword semantics rather than flattening every domain into a suffix.
fn cache_text(entries: &RuleEntries, format: SourceFormat) -> String {
    let mut lines = Vec::new();
    match format {
        SourceFormat::Domains => {
            lines.extend(entries.suffixes.iter().map(|v| format!("domain:{v}")));
            lines.extend(entries.full.iter().map(|v| format!("full:{v}")));
            lines.extend(entries.keywords.iter().map(|v| format!("keyword:{v}")));
        }
        SourceFormat::Cidrs => lines.extend(entries.cidrs.iter().cloned()),
    }
    let mut text = lines.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text
}

pub fn update_source(src: &mut BypassSource) -> Result<usize> {
    let path = cache_path(src)?;
    let url = url::Url::parse(&src.url).context("invalid bypass source URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("bypass source must use HTTP or HTTPS");
    }
    let response = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(60))
        .build()
        .get(url.as_str())
        .call()
        .with_context(|| format!("downloading bypass source {}", src.name))?;
    // Bound memory consumption even for accidentally selected binary downloads.
    const LIMIT: u64 = 64 * 1024 * 1024;
    let mut bytes = Vec::new();
    response.into_reader().take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        bail!("bypass source exceeds 64 MiB");
    }
    let text = String::from_utf8(bytes).context("bypass source is not UTF-8 text")?;
    let entries = parse(&text, src.format);
    if entries.is_empty() && !text.trim().is_empty() {
        bail!("bypass source contains no valid entries; previous cache retained");
    }
    let parent = path.parent().context("bypass cache has no parent")?;
    std::fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}-{}.tmp", src.id, crate::store::new_id()));
    let result = (|| -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true).create_new(true).open(&temporary)?;
        file.write_all(cache_text(&entries, src.format).as_bytes())?;
        file.sync_all()?;
        drop(file);
        replace(&temporary, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result.context("saving bypass cache")?;
    src.entries = entries.len();
    src.updated_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    Ok(src.entries)
}

#[cfg(not(windows))]
fn replace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

#[cfg(windows)]
fn replace(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn load_entries(src: &BypassSource) -> Result<RuleEntries> {
    let path = cache_path(src)?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading bypass cache {}", path.display()))?;
    Ok(parse(&text, src.format))
}

pub fn bypass_entries(b: &BypassSettings) -> RuleEntries {
    if !b.enabled {
        return RuleEntries::default();
    }
    let mut entries = RuleEntries::default();
    for source in b.sources.iter().filter(|s| s.enabled) {
        if let Ok(cached) = load_entries(source) {
            entries.extend(cached);
        }
    }
    if b.tld_suffix {
        if let Some(cc) = country_code(&b.country) {
            entries.suffixes.push(cc);
        }
    }
    entries.normalize();
    entries
}

/// Effective settings for legacy BypassIran mode. An empty country retains the
/// historical Iranian fallback until country discovery has completed.
pub(crate) fn effective_entries(s: &crate::Settings) -> RuleEntries {
    let mut bypass = s.bypass.clone();
    if s.routing == crate::RoutingMode::BypassIran {
        bypass.enabled = true;
    }
    bypass_entries(&bypass)
}

pub(crate) fn legacy_iran(s: &crate::Settings, entries: &RuleEntries) -> bool {
    s.routing == crate::RoutingMode::BypassIran
        && (s.bypass.country.is_empty() || s.bypass.country.eq_ignore_ascii_case("ir"))
        && entries.cidrs.is_empty()
        && entries.full.is_empty()
        && entries.keywords.is_empty()
        && entries.suffixes.iter().all(|s| s == "ir")
}

pub(crate) fn classical(entries: &RuleEntries) -> String {
    let mut lines = BTreeSet::new();
    for (prefix, values) in [
        ("DOMAIN-SUFFIX", &entries.suffixes),
        ("DOMAIN", &entries.full),
        ("DOMAIN-KEYWORD", &entries.keywords),
    ] {
        for value in values {
            lines.insert(format!("{prefix},{value}"));
        }
    }
    for value in &entries.cidrs {
        let kind = if value.contains(':') { "IP-CIDR6" } else { "IP-CIDR" };
        lines.insert(format!("{kind},{value},no-resolve"));
    }
    let mut text = lines.into_iter().collect::<Vec<_>>().join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_comments_and_normalization() {
        let e = parse(
            "\u{feff}# comment\nExample.COM.\n*.example.com\n.local\n; comment\n// comment\nbad/path\n",
            SourceFormat::Domains,
        );
        assert_eq!(e.suffixes, ["example.com", "local"]);
    }

    #[test]
    fn v2fly_preserves_match_types() {
        let e = parse(
            "domain:Example.COM @ir\nfull:Login.Example.com # note\nkeyword:BANK\nregexp:.*\\.ir\n",
            SourceFormat::Domains,
        );
        assert_eq!(e.suffixes, ["example.com"]);
        assert_eq!(e.full, ["login.example.com"]);
        assert_eq!(e.keywords, ["bank"]);
        assert_eq!(parse(&cache_text(&e, SourceFormat::Domains), SourceFormat::Domains), e);
    }

    #[test]
    fn dnsmasq() {
        let e = parse(
            "server=/Example.cn/114.114.114.114\nserver=/a.cn/b.cn/1.1.1.1#5353\n",
            SourceFormat::Domains,
        );
        assert_eq!(e.suffixes, ["a.cn", "b.cn", "example.cn"]);
    }

    #[test]
    fn cidrs_validate_mask_and_deduplicate() {
        let e = parse(
            "# IP list\n192.168.1.20/24\n192.168.1.0/24 # duplicate\n2001:db8::1/32\n0.0.0.0/0\n::/0\n1.2.3.4/33\n::/129\nbad\n",
            SourceFormat::Cidrs,
        );
        assert_eq!(e.cidrs, ["0.0.0.0/0", "192.168.1.0/24", "2001:db8::/32", "::/0"]);
        assert_eq!(parse(&cache_text(&e, SourceFormat::Cidrs), SourceFormat::Cidrs), e);
    }

    #[test]
    fn catalog_and_tld() {
        assert_eq!(recommended_sources("IR").len(), 3);
        assert!(!recommended_sources("ir")[2].enabled);
        assert_eq!(recommended_sources("cn").len(), 2);
        assert_eq!(recommended_sources("de").len(), 1);
        assert!(recommended_sources("../").is_empty());
        let b = BypassSettings { enabled: true, country: "DE".into(), ..Default::default() };
        assert_eq!(bypass_entries(&b).suffixes, ["de"]);
        assert!(bypass_entries(&BypassSettings::default()).is_empty());
    }

    #[test]
    fn unsafe_cache_ids_are_rejected() {
        for id in ["", "../bad", "/tmp/bad", "a\\b"] {
            assert!(cache_path(&BypassSource { id: id.into(), ..Default::default() }).is_err());
        }
    }
}
