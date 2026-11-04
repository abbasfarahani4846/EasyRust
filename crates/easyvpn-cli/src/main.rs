use std::{
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use easyvpn_core::{
    config,
    core::{self, Connection as CoreConnection},
    download, import, link, ping,
    rules::{self, BypassSource, SourceFormat},
    store::{self, Store},
    subscription, sysproxy, CoreKind, DefaultRoute, Profile, Protocol, ProxyMode, RoutingMode,
    Rule, RuleAction, RuleKind, Settings,
};

#[derive(Parser)]
#[command(name = "easyvpn", version, about = "Manage proxy cores and VPN tunnels")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add share links or config text; use '-' to read from stdin.
    Add {
        #[arg(required = true, num_args = 1..)]
        links: Vec<String>,
    },
    /// Import configuration files; use '-' to read config text from stdin.
    Import {
        #[arg(required = true, num_args = 1..)]
        files: Vec<String>,
    },
    /// List saved profiles.
    List,
    /// Remove a profile by ID or 1-based index.
    Remove { id: String },
    /// Select a profile by ID or 1-based index.
    Select { id: String },
    /// Export a profile as a share link.
    Export { id: String },
    /// Manage subscriptions.
    Sub {
        #[command(subcommand)]
        command: SubCommand,
    },
    /// Install or list managed cores.
    Core {
        #[command(subcommand)]
        command: CoreCommand,
    },
    /// Manage ordered split-tunneling rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Manage downloadable country bypass sources.
    Bypass {
        #[command(subcommand)]
        command: BypassCommand,
    },
    /// Print current settings.
    Settings,
    /// Change a setting.
    Set { key: String, value: String },
    /// TCP-ping one profile, or all profiles when omitted.
    Ping { id: Option<String> },
    /// Print the generated core configuration.
    Config {
        id: Option<String>,
        #[arg(long, value_parser = parse_core)]
        core: Option<CoreKind>,
    },
    /// Connect until Ctrl+C or core exit.
    Connect {
        id: Option<String>,
        #[arg(long, value_parser = parse_core)]
        core: Option<CoreKind>,
    },
}

#[derive(Subcommand)]
enum SubCommand {
    Add { name: String, url: String },
    Update { id: Option<String> },
    List,
    Remove { id: String },
}

#[derive(Subcommand)]
enum CoreCommand {
    Install {
        #[arg(value_parser = ["xray", "sing-box", "mihomo", "openvpn", "all"])]
        core: String,
    },
    List,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// List rules in evaluation order.
    List,
    /// Append an enabled rule.
    Add {
        #[arg(value_parser = parse_rule_kind)]
        kind: RuleKind,
        value: String,
        #[arg(value_parser = parse_rule_action)]
        action: RuleAction,
    },
    Remove { id: String },
    /// Choose the route used when no rule matches.
    Default {
        #[arg(value_parser = parse_default_route)]
        route: DefaultRoute,
    },
}

#[derive(Subcommand)]
enum BypassCommand {
    /// Show country bypass settings and sources.
    Status,
    On,
    Off,
    /// Set a two-letter country code, or detect it directly with 'auto'.
    Country { country: String },
    /// Download all enabled sources.
    Update,
    /// Add an enabled custom source.
    Add {
        name: String,
        url: String,
        #[arg(value_parser = parse_source_format)]
        format: SourceFormat,
    },
    Remove { id: String },
}

fn parse_core(value: &str) -> std::result::Result<CoreKind, String> {
    match value {
        "xray" => Ok(CoreKind::Xray),
        "sing-box" => Ok(CoreKind::SingBox),
        "mihomo" => Ok(CoreKind::Mihomo),
        "openvpn" => Ok(CoreKind::OpenVpn),
        _ => Err("expected xray, sing-box, mihomo, or openvpn".into()),
    }
}

fn parse_rule_kind(value: &str) -> std::result::Result<RuleKind, String> {
    match value {
        "domain" => Ok(RuleKind::Domain),
        "suffix" => Ok(RuleKind::DomainSuffix),
        "keyword" => Ok(RuleKind::DomainKeyword),
        "cidr" => Ok(RuleKind::IpCidr),
        "process" => Ok(RuleKind::Process),
        _ => Err("expected domain, suffix, keyword, cidr, or process".into()),
    }
}

fn parse_rule_action(value: &str) -> std::result::Result<RuleAction, String> {
    match value {
        "proxy" => Ok(RuleAction::Proxy),
        "direct" => Ok(RuleAction::Direct),
        "block" => Ok(RuleAction::Block),
        _ => Err("expected proxy, direct, or block".into()),
    }
}

fn parse_default_route(value: &str) -> std::result::Result<DefaultRoute, String> {
    match value {
        "proxy" => Ok(DefaultRoute::Proxy),
        "direct" => Ok(DefaultRoute::Direct),
        _ => Err("expected proxy or direct".into()),
    }
}

fn parse_source_format(value: &str) -> std::result::Result<SourceFormat, String> {
    match value {
        "domains" => Ok(SourceFormat::Domains),
        "cidrs" => Ok(SourceFormat::Cidrs),
        _ => Err("expected domains or cidrs".into()),
    }
}

fn rule_kind_name(kind: RuleKind) -> &'static str {
    match kind {
        RuleKind::Domain => "domain",
        RuleKind::DomainSuffix => "suffix",
        RuleKind::DomainKeyword => "keyword",
        RuleKind::IpCidr => "cidr",
        RuleKind::Process => "process",
    }
}

fn rule_action_name(action: RuleAction) -> &'static str {
    match action {
        RuleAction::Proxy => "proxy",
        RuleAction::Direct => "direct",
        RuleAction::Block => "block",
    }
}

fn default_route_name(route: DefaultRoute) -> &'static str {
    match route {
        DefaultRoute::Proxy => "proxy",
        DefaultRoute::Direct => "direct",
    }
}

fn source_format_name(format: SourceFormat) -> &'static str {
    match format {
        SourceFormat::Domains => "domains",
        SourceFormat::Cidrs => "cidrs",
    }
}

fn protocol_name(protocol: Option<Protocol>) -> &'static str {
    match protocol {
        Some(Protocol::Vmess) => "vmess",
        Some(Protocol::Vless) => "vless",
        Some(Protocol::Trojan) => "trojan",
        Some(Protocol::Shadowsocks) => "shadowsocks",
        Some(Protocol::Socks) => "socks",
        Some(Protocol::Http) => "http",
        Some(Protocol::Hysteria2) => "hysteria2",
        Some(Protocol::Tuic) => "tuic",
        Some(Protocol::Wireguard) => "wireguard",
        Some(Protocol::Ssh) => "ssh",
        Some(Protocol::AnyTls) => "anytls",
        Some(Protocol::Hysteria) => "hysteria",
        Some(Protocol::OpenVpn) => "openvpn",
        Some(Protocol::Custom) => "custom",
        None => "unknown",
    }
}

fn endpoint(profile: &Profile) -> String {
    let host = &profile.address;
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{}", profile.port)
    } else {
        format!("{host}:{}", profile.port)
    }
}

// Keep user-controlled labels on one terminal line.
fn label(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn resolve_profile<'a>(store: &'a Store, key: Option<&str>) -> Result<&'a Profile> {
    match key {
        Some(key) => store
            .find(key)
            .ok_or_else(|| anyhow!("profile not found: {key}")),
        None => store
            .selected_profile()
            .ok_or_else(|| anyhow!("no profile selected; run `easyvpn select <ID>`")),
    }
}

fn check_support(kind: CoreKind, profile: &Profile) -> Result<()> {
    let supported = profile.supported_cores();
    if !supported.contains(&kind) {
        if supported.is_empty() {
            bail!(
                "no core is configured to support this {} profile",
                protocol_name(profile.protocol)
            );
        }
        let alternatives = supported
            .into_iter()
            .map(|candidate| candidate.name())
            .collect::<Vec<_>>()
            .join(" or ");
        bail!(
            "{} does not support this {} profile; use --core {}",
            kind.name(),
            protocol_name(profile.protocol),
            alternatives
        );
    }
    Ok(())
}

fn choose_core(profile: &Profile, preferred: CoreKind, explicit: Option<CoreKind>) -> Result<CoreKind> {
    if let Some(kind) = explicit {
        check_support(kind, profile)?;
        return Ok(kind);
    }
    profile.pick_core(preferred).ok_or_else(|| {
        anyhow!(
            "no core is configured to support this {} profile",
            protocol_name(profile.protocol)
        )
    })
}

fn parse_switch(value: &str) -> Result<bool> {
    match value {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => bail!("expected on or off"),
    }
}

fn set_setting(settings: &mut Settings, key: &str, value: &str) -> Result<()> {
    match key {
        "core" => settings.core = parse_core(value).map_err(anyhow::Error::msg)?,
        "listen" => {
            value
                .parse::<std::net::IpAddr>()
                .context("listen must be an IPv4 or IPv6 address")?;
            settings.listen = value.into();
        }
        "port" => {
            let port: u16 = value.parse().context("port must be between 1 and 65535")?;
            if port == 0 {
                bail!("port must be between 1 and 65535");
            }
            settings.mixed_port = port;
        }
        "routing" => {
            settings.routing = match value {
                "global" => RoutingMode::Global,
                "bypass-lan" => RoutingMode::BypassLan,
                "bypass-iran" => RoutingMode::BypassIran,
                _ => bail!("routing must be global, bypass-lan, or bypass-iran"),
            };
        }
        "mode" => {
            settings.mode = match value {
                "local" => ProxyMode::Local,
                "system" => ProxyMode::System,
                "tun" => ProxyMode::Tun,
                _ => bail!("mode must be local, system, or tun"),
            };
        }
        "system-proxy" => {
            settings.mode = if parse_switch(value)? {
                ProxyMode::System
            } else {
                ProxyMode::Local
            };
        }
        "tun" => {
            settings.mode = if parse_switch(value)? {
                ProxyMode::Tun
            } else {
                ProxyMode::Local
            };
        }
        "allow-lan" => settings.allow_lan = parse_switch(value)?,
        "remote-dns" | "direct-dns" => {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                bail!("DNS address must be nonempty and contain no control characters");
            }
            if key == "remote-dns" {
                settings.remote_dns = value.into();
            } else {
                settings.direct_dns = value.into();
            }
        }
        "log-level" => {
            match value {
                "trace" | "debug" | "info" | "warning" | "error" | "fatal" | "panic"
                | "none" | "silent" => {}
                _ => bail!("invalid log level"),
            }
            settings.log_level = value.into();
        }
        _ => bail!(
            "unknown setting {key:?}; keys: core, listen, port, routing, mode, \
             system-proxy, tun, remote-dns, direct-dns, allow-lan, log-level"
        ),
    }
    Ok(())
}

fn print_settings(settings: &Settings) {
    println!("core: {}", settings.core.name());
    println!("listen: {}", settings.listen);
    println!("port: {}", settings.mixed_port);
    println!(
        "routing: {}",
        match settings.routing {
            RoutingMode::Global => "global",
            RoutingMode::BypassLan => "bypass-lan",
            RoutingMode::BypassIran => "bypass-iran",
        }
    );
    println!(
        "mode: {}",
        match settings.mode {
            ProxyMode::Local => "local",
            ProxyMode::System => "system",
            ProxyMode::Tun => "tun",
        }
    );
    println!("allow-lan: {}", if settings.allow_lan { "on" } else { "off" });
    println!("remote-dns: {}", settings.remote_dns);
    println!("direct-dns: {}", settings.direct_dns);
    println!("log-level: {}", settings.log_level);
}

fn run_rules(store: &mut Store, command: RulesCommand) -> Result<()> {
    match command {
        RulesCommand::List => {
            println!(
                "default: {}",
                default_route_name(store.settings.default_route)
            );
            println!("ID\tKIND\tVALUE\tACTION\tENABLED");
            for rule in &store.settings.rules {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    label(&rule.id),
                    rule_kind_name(rule.kind),
                    label(&rule.value),
                    rule_action_name(rule.action),
                    if rule.enabled { "on" } else { "off" }
                );
            }
            println!("App rules work in TUN mode.");
        }
        RulesCommand::Add { kind, value, action } => {
            let value = value.trim();
            if value.is_empty() || value.chars().any(char::is_control) {
                bail!("rule value must be nonempty and contain no control characters");
            }
            let id = store::new_id();
            store.settings.rules.push(Rule {
                id: id.clone(),
                kind,
                value: value.into(),
                action,
                enabled: true,
            });
            store.save()?;
            println!("Added rule {id}");
            if kind == RuleKind::Process {
                println!("App rules work in TUN mode.");
            }
        }
        RulesCommand::Remove { id } => {
            let index = store
                .settings
                .rules
                .iter()
                .position(|rule| rule.id == id)
                .ok_or_else(|| anyhow!("rule not found: {id}"))?;
            store.settings.rules.remove(index);
            store.save()?;
            println!("Removed rule {}", label(&id));
        }
        RulesCommand::Default { route } => {
            store.settings.default_route = route;
            store.save()?;
            println!("default: {}", default_route_name(route));
        }
    }
    Ok(())
}

fn normalize_country(value: &str) -> Result<String> {
    if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_alphabetic()) {
        bail!("country must be a two-letter ISO country code or auto");
    }
    Ok(value.to_ascii_lowercase())
}

fn run_bypass(store: &mut Store, command: BypassCommand) -> Result<()> {
    match command {
        BypassCommand::Status => {
            let bypass = &store.settings.bypass;
            println!("bypass: {}", if bypass.enabled { "on" } else { "off" });
            if store.settings.routing == RoutingMode::BypassIran && !bypass.enabled {
                println!("Legacy bypass-iran routing also enables country bypass.");
            }
            println!(
                "country: {}",
                if bypass.country.is_empty() {
                    "auto (not detected)"
                } else {
                    &bypass.country
                }
            );
            println!("tld-suffix: {}", if bypass.tld_suffix { "on" } else { "off" });
            println!("ID\tNAME\tFORMAT\tENABLED\tBUILTIN\tENTRIES\tUPDATED (UNIX SECONDS)\tURL");
            for source in &bypass.sources {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    label(&source.id),
                    label(&source.name),
                    source_format_name(source.format),
                    if source.enabled { "on" } else { "off" },
                    if source.builtin { "yes" } else { "no" },
                    source.entries,
                    source.updated_at,
                    label(&source.url)
                );
            }
        }
        BypassCommand::On => {
            store.settings.bypass.enabled = true;
            store.save()?;
            println!("bypass: on");
            if store.settings.bypass.country.is_empty() {
                println!("Run `easyvpn bypass country auto` to detect a country and configure sources.");
            }
        }
        BypassCommand::Off => {
            store.settings.bypass.enabled = false;
            // Legacy BypassIran implicitly enables country bypass in the generators.
            if store.settings.routing == RoutingMode::BypassIran {
                store.settings.routing = RoutingMode::BypassLan;
            }
            store.save()?;
            println!("bypass: off");
        }
        BypassCommand::Country { country } => {
            let country = if country == "auto" {
                normalize_country(&rules::detect_country().context("detecting bypass country")?)?
            } else {
                normalize_country(&country)?
            };
            let sources = rules::recommended_sources(&country);
            store.settings.bypass.country = country.clone();
            store.settings.bypass.sources = sources;
            store.save()?;
            println!(
                "country: {country}; configured {} recommended sources",
                store.settings.bypass.sources.len()
            );
            println!("Run `easyvpn bypass update` to download enabled sources.");
        }
        BypassCommand::Update => {
            let mut failures = 0;
            let mut updated = 0;
            for source in store.settings.bypass.sources.iter_mut().filter(|s| s.enabled) {
                match rules::update_source(source) {
                    Ok(count) => {
                        updated += 1;
                        println!("{} ({}): {count} entries", label(&source.name), label(&source.id));
                    }
                    Err(error) => {
                        failures += 1;
                        eprintln!("{} ({}): {error:#}", label(&source.name), label(&source.id));
                    }
                }
            }
            // Persist successful updates even when another source failed.
            store.save()?;
            println!("Updated {updated} source(s).");
            if failures != 0 {
                bail!("{failures} bypass source update(s) failed");
            }
        }
        BypassCommand::Add { name, url, format } => {
            let name = name.trim();
            if name.is_empty() || name.chars().any(char::is_control) {
                bail!("source name must be nonempty and contain no control characters");
            }
            if url.trim().is_empty() || url.chars().any(char::is_control) {
                bail!("source URL must be nonempty and contain no control characters");
            }
            let id = store::new_id();
            store.settings.bypass.sources.push(BypassSource {
                id: id.clone(),
                name: name.into(),
                url,
                format,
                enabled: true,
                builtin: false,
                ..BypassSource::default()
            });
            store.save()?;
            println!("Added bypass source {id}");
        }
        BypassCommand::Remove { id } => {
            let index = store
                .settings
                .bypass
                .sources
                .iter()
                .position(|source| source.id == id)
                .ok_or_else(|| anyhow!("bypass source not found: {id}"))?;
            store.settings.bypass.sources.remove(index);
            store.save()?;
            println!("Removed bypass source {}", label(&id));
        }
    }
    Ok(())
}

fn run_sub(store: &mut Store, command: SubCommand) -> Result<()> {
    match command {
        SubCommand::Add { name, url } => {
            let id = store.add_subscription(&name, &url);
            store.save()?;
            println!("Added subscription {id}");
        }
        SubCommand::List => {
            println!("ID\tNAME\tURL\tUPDATED (UNIX SECONDS)");
            for sub in &store.subscriptions {
                println!(
                    "{}\t{}\t{}\t{}",
                    sub.id,
                    label(&sub.name),
                    label(&sub.url),
                    sub.updated_at
                );
            }
        }
        SubCommand::Remove { id } => {
            if !store.remove_subscription(&id) {
                bail!("subscription not found: {id}");
            }
            store.save()?;
            println!("Removed subscription {id}");
        }
        SubCommand::Update { id: Some(id) } => {
            let count = subscription::update(store, &id)?;
            store.save()?;
            println!("{id}: updated {count} profiles");
        }
        SubCommand::Update { id: None } => {
            let results = subscription::update_all(store);
            // Persist successful updates even if other subscriptions failed.
            store.save()?;
            let mut failed = 0;
            for (id, result) in results {
                match result {
                    Ok(count) => println!("{id}: updated {count} profiles"),
                    Err(error) => {
                        failed += 1;
                        eprintln!("{id}: {error:#}");
                    }
                }
            }
            if failed != 0 {
                bail!("{failed} subscription update(s) failed");
            }
        }
    }
    Ok(())
}

fn run_core(command: CoreCommand) -> Result<()> {
    match command {
        CoreCommand::List => {
            for kind in CoreKind::ALL {
                if kind == CoreKind::OpenVpn {
                    println!(
                        "{}\t{}\t{}",
                        kind.name(),
                        if core::is_installed(kind) {
                            "installed"
                        } else {
                            "not installed"
                        },
                        core::binary_path(kind).display()
                    );
                } else if core::is_installed(kind) {
                    let path = core::binary_path(kind).with_file_name("version.txt");
                    let version = std::fs::read_to_string(path)
                        .map(|text| label(text.trim()))
                        .unwrap_or_else(|_| "unknown version".into());
                    println!("{}\tinstalled\t{}", kind.name(), version);
                } else {
                    println!("{}\tnot installed", kind.name());
                }
            }
        }
        CoreCommand::Install { core } => {
            // OpenVPN is installed through the OS, not the managed downloader.
            let kinds = if core == "all" {
                CoreKind::ALL
                    .into_iter()
                    .filter(|kind| !kind.is_tunnel())
                    .collect()
            } else {
                vec![parse_core(&core).map_err(anyhow::Error::msg)?]
            };
            let mut failures = 0;
            for kind in kinds {
                eprintln!("Installing {}...", kind.name());
                match download::install(kind, &mut |message| eprintln!("{message}")) {
                    Ok(path) => println!("{}: {}", kind.name(), path.display()),
                    Err(error) => {
                        failures += 1;
                        eprintln!("{}: {error:#}", kind.name());
                    }
                }
            }
            if failures != 0 {
                bail!("{failures} core installation(s) failed");
            }
        }
    }
    Ok(())
}

fn run_ping(store: &Store, id: Option<&str>) -> Result<()> {
    let timeout = Duration::from_secs(3);
    if let Some(id) = id {
        let profile = resolve_profile(store, Some(id))?;
        let elapsed = ping::tcp_ping(profile, timeout)?;
        println!(
            "{}\t{}\t{} ms",
            profile.id,
            label(&profile.name),
            elapsed.as_millis()
        );
    } else {
        let results = ping::ping_all(&store.profiles, timeout);
        let mut rows: Vec<_> = results.into_iter().enumerate().collect();
        rows.sort_by_key(|(index, (_, millis))| (millis.is_none(), *millis, *index));
        for (index, (id, millis)) in rows {
            let name = store
                .profiles
                .get(index)
                .map(|profile| label(&profile.name))
                .unwrap_or_default();
            match millis {
                Some(ms) => println!("{id}\t{name}\t{ms} ms"),
                None => println!("{id}\t{name}\tunreachable / unsupported"),
            }
        }
    }
    Ok(())
}

/// Cleanup also runs when enabling the system proxy partially fails or output fails.
struct Connection {
    process: CoreConnection,
    restore_proxy: bool,
}

impl Drop for Connection {
    fn drop(&mut self) {
        if self.restore_proxy {
            if let Err(error) = sysproxy::disable() {
                eprintln!("Failed to disable system proxy: {error:#}");
            }
        }
        self.process.stop();
    }
}

fn write_new_logs(
    process: &CoreConnection,
    previous: &mut Vec<String>,
    output: &mut impl Write,
) -> Result<()> {
    let current = process.logs();
    // The core keeps a bounded buffer; find the surviving suffix of the last snapshot.
    let overlap = (0..=previous.len().min(current.len()))
        .rev()
        .find(|&count| previous[previous.len() - count..] == current[..count])
        .unwrap_or(0);
    for line in &current[overlap..] {
        writeln!(output, "{line}")?;
    }
    output.flush()?;
    *previous = current;
    Ok(())
}

fn connect(kind: CoreKind, profile: &Profile, settings: &Settings) -> Result<()> {
    check_support(kind, profile)?;
    if settings.mode == ProxyMode::Tun && !core::is_elevated() {
        bail!("TUN mode needs Administrator/root");
    }

    let custom = profile.protocol == Some(Protocol::Custom);
    if kind.is_tunnel() {
        eprintln!("OpenVPN is a full-device tunnel and requires administrator/root privileges.");
        eprintln!("System proxy will not be enabled for a full-device tunnel.");
    } else if custom {
        eprintln!(
            "Custom config is used as-is; system proxy will not be enabled because its local proxy port is unknown."
        );
    }
    if settings.mode == ProxyMode::Tun && !kind.is_tunnel() {
        eprintln!("TUN mode requires administrator/root privileges.");
    }

    let interrupted = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&interrupted);
    ctrlc::set_handler(move || signal.store(true, Ordering::SeqCst))
        .context("installing Ctrl+C handler")?;

    let process = CoreConnection::start(kind, profile, settings)?;
    let mut connection = Connection {
        process,
        restore_proxy: false,
    };
    if settings.mode == ProxyMode::System && !kind.is_tunnel() && !custom {
        // Wildcard bind addresses are not suitable as system proxy destinations.
        let host = match settings.listen.as_str() {
            _ if settings.allow_lan => "127.0.0.1",
            "0.0.0.0" => "127.0.0.1",
            "::" | "[::]" => "::1",
            host => host,
        };
        connection.restore_proxy = true;
        // Xray exposes HTTP on the port following its SOCKS inbound.
        let port = if kind == CoreKind::Xray {
            settings
                .mixed_port
                .checked_add(1)
                .context("xray HTTP port would exceed 65535")?
        } else {
            settings.mixed_port
        };
        sysproxy::enable(host, port).context("enabling system proxy")?;
    }

    eprintln!(
        "Connected using {} to {}. Press Ctrl+C to disconnect.",
        kind.name(),
        label(&profile.name)
    );
    let mut previous = Vec::new();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    loop {
        write_new_logs(&connection.process, &mut previous, &mut output)?;
        if interrupted.load(Ordering::SeqCst) {
            break;
        }
        if !connection.process.is_running() {
            // Give the stdout/stderr reader threads time to drain the final lines.
            thread::sleep(Duration::from_millis(100));
            write_new_logs(&connection.process, &mut previous, &mut output)?;
            bail!("{} connection exited unexpectedly", kind.name());
        }
        thread::sleep(Duration::from_millis(100));
    }
    drop(connection);
    eprintln!("Disconnected.");
    Ok(())
}

fn read_stdin_once(already_read: &mut bool) -> Result<String> {
    if *already_read {
        bail!("stdin ('-') may only be specified once");
    }
    *already_read = true;
    let mut text = String::new();
    io::stdin().read_to_string(&mut text)?;
    Ok(text)
}

fn parse_add_input(text: &str) -> Vec<Profile> {
    let profiles = link::parse_many(text);
    if profiles.is_empty() {
        import::import_text(text, None)
    } else {
        profiles
    }
}

fn save_profiles(store: &mut Store, profiles: Vec<Profile>) -> Result<()> {
    if profiles.is_empty() {
        bail!("no valid profiles found");
    }
    let ids: Vec<_> = profiles
        .into_iter()
        .map(|profile| store.add_profile(profile))
        .collect();
    store.save()?;
    for id in ids {
        println!("Added {id}");
    }
    Ok(())
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // Core installation and discovery do not require a valid profile store.
    if let Command::Core { command } = cli.command {
        return run_core(command);
    }

    let mut store = Store::load().context("loading profile store")?;
    match cli.command {
        Command::Add { links } => {
            let mut profiles = Vec::new();
            let mut read_stdin = false;
            for input in links {
                let text = if input == "-" {
                    read_stdin_once(&mut read_stdin)?
                } else {
                    input
                };
                let parsed = parse_add_input(&text);
                if parsed.is_empty() {
                    bail!("no valid profiles found in add input");
                }
                profiles.extend(parsed);
            }
            save_profiles(&mut store, profiles)?;
        }
        Command::Import { files } => {
            let mut profiles = Vec::new();
            let mut read_stdin = false;
            for file in files {
                if file == "-" {
                    let text = read_stdin_once(&mut read_stdin)?;
                    let parsed = import::import_text(&text, None);
                    if parsed.is_empty() {
                        bail!("no valid profiles found in stdin");
                    }
                    profiles.extend(parsed);
                } else {
                    profiles.extend(
                        import::import_file(std::path::Path::new(&file))
                            .with_context(|| format!("importing {file}"))?,
                    );
                }
            }
            save_profiles(&mut store, profiles)?;
        }
        Command::List => {
            println!(" \tINDEX\tID\tPROTOCOL\tNAME\tADDRESS\tCORE");
            for (index, profile) in store.profiles.iter().enumerate() {
                let selected = store.selected.as_deref() == Some(profile.id.as_str());
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    if selected { "*" } else { " " },
                    index + 1,
                    profile.id,
                    protocol_name(profile.protocol),
                    label(&profile.name),
                    label(&endpoint(profile)),
                    profile
                        .pick_core(store.settings.core)
                        .map(CoreKind::name)
                        .unwrap_or("none")
                );
            }
        }
        Command::Remove { id } => {
            let actual_id = resolve_profile(&store, Some(&id))?.id.clone();
            if !store.remove_profile(&actual_id) {
                bail!("profile not found: {id}");
            }
            if store.selected.as_deref() == Some(actual_id.as_str()) {
                store.selected = None;
            }
            store.save()?;
            println!("Removed {actual_id}");
        }
        Command::Select { id } => {
            let actual_id = resolve_profile(&store, Some(&id))?.id.clone();
            store.selected = Some(actual_id.clone());
            store.save()?;
            println!("Selected {actual_id}");
        }
        Command::Export { id } => {
            println!("{}", link::to_link(resolve_profile(&store, Some(&id))?)?);
        }
        Command::Sub { command } => run_sub(&mut store, command)?,
        Command::Rules { command } => run_rules(&mut store, command)?,
        Command::Bypass { command } => run_bypass(&mut store, command)?,
        Command::Settings => print_settings(&store.settings),
        Command::Set { key, value } => {
            set_setting(&mut store.settings, &key, &value)?;
            store.save()?;
            println!("{key}: {value}");
        }
        Command::Ping { id } => run_ping(&store, id.as_deref())?,
        Command::Config { id, core } => {
            let profile = resolve_profile(&store, id.as_deref())?;
            let kind = choose_core(profile, store.settings.core, core)?;
            println!("{}", config::build(kind, profile, &store.settings)?);
        }
        Command::Connect { id, core } => {
            let profile = resolve_profile(&store, id.as_deref())?;
            let kind = choose_core(profile, store.settings.core, core)?;
            connect(kind, profile, &store.settings)?;
        }
        Command::Core { command } => run_core(command)?,
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_validation() {
        let mut settings = Settings::default();
        assert!(set_setting(&mut settings, "port", "0").is_err());
        assert!(set_setting(&mut settings, "port", "65536").is_err());
        set_setting(&mut settings, "port", "12345").expect("valid port");
        assert_eq!(settings.mixed_port, 12345);
        set_setting(&mut settings, "routing", "bypass-iran").expect("valid routing");
        assert_eq!(settings.routing, RoutingMode::BypassIran);
        set_setting(&mut settings, "core", "openvpn").expect("valid core");
        assert_eq!(settings.core, CoreKind::OpenVpn);
        assert!(set_setting(&mut settings, "tun", "yes").is_err());
        assert!(set_setting(&mut settings, "unknown", "value").is_err());
    }

    #[test]
    fn connection_mode_settings() {
        let mut settings = Settings::default();
        assert_eq!(settings.mode, ProxyMode::Local);

        for (value, expected) in [
            ("local", ProxyMode::Local),
            ("system", ProxyMode::System),
            ("tun", ProxyMode::Tun),
        ] {
            set_setting(&mut settings, "mode", value).expect("valid mode");
            assert_eq!(settings.mode, expected);
        }

        assert!(set_setting(&mut settings, "mode", "invalid").is_err());
        assert_eq!(settings.mode, ProxyMode::Tun);

        for (key, enabled_mode) in [
            ("system-proxy", ProxyMode::System),
            ("tun", ProxyMode::Tun),
        ] {
            set_setting(&mut settings, key, "on").expect("enable alias");
            assert_eq!(settings.mode, enabled_mode);
            assert!(set_setting(&mut settings, key, "yes").is_err());
            assert_eq!(settings.mode, enabled_mode);
            set_setting(&mut settings, key, "off").expect("disable alias");
            assert_eq!(settings.mode, ProxyMode::Local);
        }
    }

    #[test]
    fn command_line_parsing() {
        assert!(Cli::try_parse_from(["easyvpn", "add"]).is_err());
        assert!(Cli::try_parse_from(["easyvpn", "add", "-"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "import"]).is_err());
        assert!(Cli::try_parse_from(["easyvpn", "import", "-"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "import", "a.ovpn", "b.conf"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "connect", "--core", "sing-box"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "connect", "--core", "openvpn"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "config", "1", "--core", "bad"]).is_err());
        assert!(Cli::try_parse_from(["easyvpn", "core", "install", "all"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "core", "install", "openvpn"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "sub", "update"]).is_ok());
        assert!(Cli::try_parse_from(["easyvpn", "set", "mode", "tun"]).is_ok());
    }

    #[test]
    fn rules_command_parsing() {
        for (kind, expected) in [
            ("domain", RuleKind::Domain),
            ("suffix", RuleKind::DomainSuffix),
            ("keyword", RuleKind::DomainKeyword),
            ("cidr", RuleKind::IpCidr),
            ("process", RuleKind::Process),
        ] {
            for (action, expected_action) in [
                ("proxy", RuleAction::Proxy),
                ("direct", RuleAction::Direct),
                ("block", RuleAction::Block),
            ] {
                let cli = Cli::try_parse_from([
                    "easyvpn", "rules", "add", kind, "example", action,
                ])
                .expect("valid rule");
                match cli.command {
                    Command::Rules {
                        command: RulesCommand::Add { kind, value, action },
                    } => {
                        assert_eq!(kind, expected);
                        assert_eq!(value, "example");
                        assert_eq!(action, expected_action);
                    }
                    _ => panic!("expected rules add"),
                }
            }
        }
        for args in [
            vec!["easyvpn", "rules", "list"],
            vec!["easyvpn", "rules", "remove", "abcd1234"],
            vec!["easyvpn", "rules", "default", "proxy"],
            vec!["easyvpn", "rules", "default", "direct"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for args in [
            vec!["easyvpn", "rules"],
            vec!["easyvpn", "rules", "add", "unknown", "x", "proxy"],
            vec!["easyvpn", "rules", "add", "domain", "x", "unknown"],
            vec!["easyvpn", "rules", "add", "domain", "x"],
            vec!["easyvpn", "rules", "default", "block"],
            vec!["easyvpn", "rules", "remove"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn bypass_command_parsing() {
        for args in [
            vec!["easyvpn", "bypass", "status"],
            vec!["easyvpn", "bypass", "on"],
            vec!["easyvpn", "bypass", "off"],
            vec!["easyvpn", "bypass", "country", "auto"],
            vec!["easyvpn", "bypass", "country", "ir"],
            vec!["easyvpn", "bypass", "update"],
            vec!["easyvpn", "bypass", "remove", "abcd1234"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok());
        }
        for (format, expected) in [
            ("domains", SourceFormat::Domains),
            ("cidrs", SourceFormat::Cidrs),
        ] {
            let cli = Cli::try_parse_from([
                "easyvpn",
                "bypass",
                "add",
                "My source",
                "https://example.org/list.txt",
                format,
            ])
            .expect("valid source");
            match cli.command {
                Command::Bypass {
                    command: BypassCommand::Add { name, url, format },
                } => {
                    assert_eq!(name, "My source");
                    assert_eq!(url, "https://example.org/list.txt");
                    assert_eq!(format, expected);
                }
                _ => panic!("expected bypass add"),
            }
        }
        for args in [
            vec!["easyvpn", "bypass"],
            vec!["easyvpn", "bypass", "country"],
            vec!["easyvpn", "bypass", "remove"],
            vec!["easyvpn", "bypass", "add", "name", "url", "unknown"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn country_validation() {
        assert_eq!(normalize_country("IR").expect("country"), "ir");
        assert_eq!(normalize_country("de").expect("country"), "de");
        for value in ["", "i", "iran", "../", "12", "é", " ir", "ir\n"] {
            assert!(normalize_country(value).is_err());
        }
    }

    #[test]
    fn ipv6_endpoint_formatting() {
        let profile = Profile {
            address: "::1".into(),
            port: 443,
            ..Profile::default()
        };
        assert_eq!(endpoint(&profile), "[::1]:443");
    }

    #[test]
    fn core_selection_respects_profile_support() {
        let mut profile = Profile {
            protocol: Some(Protocol::OpenVpn),
            ..Profile::default()
        };
        assert_eq!(
            choose_core(&profile, CoreKind::Xray, None).expect("tunnel core"),
            CoreKind::OpenVpn
        );
        assert!(choose_core(&profile, CoreKind::Xray, Some(CoreKind::Xray)).is_err());

        profile.protocol = Some(Protocol::Ssh);
        assert_eq!(
            choose_core(&profile, CoreKind::Xray, None).expect("SSH core"),
            CoreKind::SingBox
        );

        profile.protocol = Some(Protocol::Custom);
        profile.custom_core = Some(CoreKind::Mihomo);
        assert_eq!(
            choose_core(&profile, CoreKind::Xray, None).expect("custom core"),
            CoreKind::Mihomo
        );
        assert!(choose_core(&profile, CoreKind::Xray, Some(CoreKind::SingBox)).is_err());
        profile.custom_core = None;
        assert!(choose_core(&profile, CoreKind::Xray, None).is_err());
    }

    #[test]
    fn add_falls_back_to_config_import() {
        let profiles = parse_add_input("client\nremote vpn.example.com 1194\n");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].protocol, Some(Protocol::OpenVpn));
    }

    #[test]
    fn new_protocol_labels() {
        for (protocol, expected) in [
            (Protocol::Ssh, "ssh"),
            (Protocol::AnyTls, "anytls"),
            (Protocol::Hysteria, "hysteria"),
            (Protocol::OpenVpn, "openvpn"),
            (Protocol::Custom, "custom"),
        ] {
            assert_eq!(protocol_name(Some(protocol)), expected);
        }
    }
}
