use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use anyhow::{Context, Result};
use easyvpn_core::{
    core::{self, Connection},
    download, import, link, ping,
    rules::{self, BypassSource},
    store::{self, Store},
    subscription, sysproxy, traffic, update, CoreKind, DefaultRoute, Profile, Protocol, ProxyMode,
    RoutingMode, Rule, RuleAction, RuleKind, Settings,
};
use eframe::egui;
use crate::{
    flags::FlagCache, pages, platform::{self, Platform, VpnStatus},
    text::display_name, theme, window::WindowState,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Home, Servers, Subscriptions, Settings, Logs, About, Import, AddSubscription,
    Editor, Rules, Sources,
}
impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Self::Home => "EasyVpn", Self::Servers => "Servers", Self::Subscriptions => "Subscriptions",
            Self::Settings => "Settings", Self::Logs => "Logs", Self::About => "About",
            Self::Import => "Import", Self::AddSubscription => "Add subscription",
            Self::Editor => "Add config", Self::Rules => "Rules", Self::Sources => "Bypass sources",
        }
    }
}
#[derive(Debug, Clone)]
pub enum ConnState {
    Disconnected, Connecting { since: Instant }, Verifying { attempt: usize },
    Connected { rtt_ms: u128 }, Lost { since: Instant }, Failed,
}
impl ConnState {
    pub fn verified(&self) -> bool { matches!(self, Self::Connected { .. }) }
    pub fn busy(&self) -> bool { matches!(self, Self::Connecting { .. } | Self::Verifying { .. }) }
}
fn health_transition(state: &ConnState, failures: &mut u8, result: &std::result::Result<u128, String>, now: Instant) -> ConnState {
    if !matches!(state, ConnState::Connected { .. } | ConnState::Lost { .. }) { return state.clone(); }
    match result {
        Ok(rtt_ms) => { *failures = 0; ConnState::Connected { rtt_ms: *rtt_ms } }
        Err(_) => {
            *failures = failures.saturating_add(1);
            if *failures >= 2 {
                match state {
                    ConnState::Lost { since } => ConnState::Lost { since: *since },
                    _ => ConnState::Lost { since: now },
                }
            } else { state.clone() }
        }
    }
}
type ProbeResult = std::result::Result<u128, String>;
enum Event {
    Progress(String),
    Installed(std::result::Result<String, String>),
    Imported(Vec<Profile>, Vec<String>),
    Subscriptions(Vec<(String, std::result::Result<Store, String>)>),
    Pings(Vec<(String, Option<u128>)>, usize),
    Started(u64, std::result::Result<(Connection, Settings, Profile), String>),
    Verifying(u64, usize), Verified(u64, ProbeResult), Health(u64, ProbeResult),
    Speed(u64, f64, f64),
    Location(u64, u64, std::result::Result<traffic::IpInfo, String>),
    Country(u64, std::result::Result<String, String>),
    SourceProgress(String),
    SourceUpdated(BypassSource, std::result::Result<BypassSource, String>),
    CleanupError(String),
    UpdateChecked(std::result::Result<Option<update::Update>, String>),
    UpdateProgress(String),
    UpdateDownloaded(std::result::Result<PathBuf, String>),
}
struct Toast {
    message: String, since: Instant, color: egui::Color32, restart_as_admin: bool, see_logs: bool,
}
type ProxyOwner = Arc<Mutex<Option<u64>>>;
fn release_proxy(owner: &ProxyOwner, generation: u64) -> Result<()> {
    let mut guard = owner.lock().unwrap_or_else(|e| e.into_inner());
    if *guard == Some(generation) {
        sysproxy::disable().context("Could not disable system proxy")?;
        *guard = None;
    }
    Ok(())
}
fn acquire_proxy(owner: &ProxyOwner, generation: u64, cancel: &AtomicBool, profile: &Profile, settings: &Settings) -> Result<()> {
    if !uses_system_proxy(profile, settings) { return Ok(()); }
    let mut guard = owner.lock().unwrap_or_else(|e| e.into_inner());
    if cancel.load(Ordering::Acquire) { anyhow::bail!("Connection cancelled"); }
    let host = if settings.allow_lan || matches!(settings.listen.as_str(), "0.0.0.0" | "::") {
        "127.0.0.1"
    } else { &settings.listen };
    let port = if settings.core == CoreKind::Xray { settings.mixed_port.checked_add(1) }
        else { Some(settings.mixed_port) }.context("HTTP proxy port overflows u16")?;
    *guard = Some(generation);
    sysproxy::enable(host, port).context("System proxy setup failed")
}
fn retire_connection(process: Option<Connection>, owner: ProxyOwner, generation: u64, sender: Sender<Event>, ctx: egui::Context) {
    thread::spawn(move || {
        let cleanup = release_proxy(&owner, generation);
        if let Some(mut process) = process { process.stop(); }
        if let Err(error) = cleanup { let _ = sender.send(Event::CleanupError(format!("{error:#}"))); }
        ctx.request_repaint();
    });
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProbeRoute { proxy: Option<String>, tunnel: bool }
fn probe_route(kind: CoreKind, profile: &Profile, settings: &Settings) -> ProbeRoute {
    let tunnel = kind.is_tunnel() || settings.mode == ProxyMode::Tun;
    let proxy = traffic::local_http_proxy(kind, profile, settings).or_else(|| {
        (profile.protocol == Some(Protocol::Custom) && !tunnel && settings.mixed_port != 0)
            .then(|| format!("http://127.0.0.1:{}", settings.mixed_port))
    });
    ProbeRoute { proxy, tunnel }
}
fn active_probe_route(mobile: bool, kind: CoreKind, profile: &Profile, settings: &Settings) -> ProbeRoute {
    if mobile {
        let local = Settings { mode: ProxyMode::Local, ..settings.clone() };
        probe_route(kind, profile, &local)
    } else { probe_route(kind, profile, settings) }
}
fn android_app_lists(settings: &Settings) -> (Vec<String>, Vec<String>) {
    let mut allowed = Vec::new();
    let mut disallowed = Vec::new();
    for rule in &settings.rules {
        if !rule.enabled || rule.kind != RuleKind::Process { continue; }
        let value = rule.value.trim();
        if value.is_empty() { continue; }
        let destination = match rule.action {
            RuleAction::Direct => &mut disallowed,
            RuleAction::Proxy if settings.default_route == DefaultRoute::Direct => &mut allowed,
            _ => continue,
        };
        if !destination.iter().any(|existing| existing == value) { destination.push(value.to_owned()); }
    }
    (allowed, disallowed)
}
fn process_settings(settings: &Settings, mobile: bool) -> Settings {
    let mut result = settings.clone();
    if mobile {
        result.mode = ProxyMode::Local;
        result.system_proxy = false;
        result.tun = false;
        result.rules.retain(|rule| rule.kind != RuleKind::Process);
        if settings.mode == ProxyMode::Tun { result.default_route = DefaultRoute::Proxy; }
    }
    result
}
fn tunnel_result(direct: ProbeResult, proxy_worked: bool) -> ProbeResult {
    direct.map_err(|error| if proxy_worked {
        format!("Server works but TUN is not routing traffic — see Logs. {error}")
    } else { error })
}
fn run_probe(route: &ProbeRoute, timeout: Duration) -> ProbeResult {
    if !route.tunnel {
        return match route.proxy.as_deref() {
            Some(proxy) => traffic::probe(Some(proxy), timeout).map(|rtt| rtt.as_millis()).map_err(|e| format!("{e:#}")),
            None => Err("Cannot verify this config: no local HTTP proxy is known — see Logs".into()),
        };
    }
    thread::scope(|scope| {
        let proxy = route.proxy.as_deref().map(|url| scope.spawn(move || traffic::probe(Some(url), timeout).is_ok()));
        let direct = traffic::probe(None, timeout).map(|rtt| rtt.as_millis()).map_err(|e| format!("{e:#}"));
        let proxy_worked = proxy.map(|handle| handle.join().unwrap_or(false)).unwrap_or(false);
        tunnel_result(direct, proxy_worked)
    })
}
fn wait_cancelled(cancel: &AtomicBool, duration: Duration) -> bool {
    let until = Instant::now() + duration;
    while Instant::now() < until {
        if cancel.load(Ordering::Acquire) { return true; }
        thread::sleep(Duration::from_millis(50));
    }
    cancel.load(Ordering::Acquire)
}
fn probe_worker(generation: u64, route: ProbeRoute, cancel: Arc<AtomicBool>, sender: Sender<Event>, ctx: egui::Context) {
    thread::spawn(move || {
        let mut last_error = "Connectivity test failed".to_owned();
        let mut proxy_only_error = None;
        let mut verified = false;
        for (index, seconds) in [3, 3, 4, 5].into_iter().enumerate() {
            // A refused connection fails instantly; give a slow-starting core time to open its port.
            if index > 0 && wait_cancelled(&cancel, Duration::from_millis(1500)) { return; }
            if cancel.load(Ordering::Acquire) { return; }
            if sender.send(Event::Verifying(generation, index + 1)).is_err() { return; }
            ctx.request_repaint();
            let result = run_probe(&route, Duration::from_secs(seconds));
            if cancel.load(Ordering::Acquire) { return; }
            match result {
                Ok(rtt) => {
                    if sender.send(Event::Verified(generation, Ok(rtt))).is_err() { return; }
                    ctx.request_repaint();
                    verified = true;
                    break;
                }
                Err(error) => {
                    if error.contains("Server works but TUN") { proxy_only_error = Some(error.clone()); }
                    last_error = error;
                }
            }
        }
        if !verified {
            let _ = sender.send(Event::Verified(generation, Err(proxy_only_error.unwrap_or(last_error))));
            ctx.request_repaint();
            return;
        }
        let interval = Duration::from_secs(5);
        let mut next = Instant::now() + interval;
        loop {
            if wait_cancelled(&cancel, next.saturating_duration_since(Instant::now())) { return; }
            let started = Instant::now();
            let result = run_probe(&route, Duration::from_secs(3));
            if cancel.load(Ordering::Acquire) { return; }
            if sender.send(Event::Health(generation, result)).is_err() { return; }
            ctx.request_repaint();
            next = started + interval;
        }
    });
}

pub struct App {
    pub store: Store,
    pub window: WindowState,
    pub platform: Arc<dyn Platform>,
    sender: Sender<Event>,
    receiver: Receiver<Event>,
    pub process: Option<Connection>,
    proxy_owner: ProxyOwner,
    pub connecting: bool,
    pub conn_state: ConnState,
    pub failed_at: Option<Instant>,
    health_failures: u8,
    connection_cancel: Option<Arc<AtomicBool>>,
    active_config: Option<(CoreKind, Profile, Settings)>,
    pending_vpn: Option<(Instant, u128)>,
    platform_vpn_active: bool,
    pub installing: bool,
    pub installing_core: Option<CoreKind>,
    pub install_progress: String,
    pub importing_files: bool,
    pub updating_subscriptions: bool,
    pub updating_ids: Vec<String>,
    queued_subscription_ids: Vec<String>,
    smart_subscription_ids: Vec<String>,
    qr_pending: bool,
    pub update: Option<update::Update>,
    pub update_busy: bool,
    pub update_status: String,
    pub pinging: bool,
    pub pings: HashMap<String, Option<u128>>,
    pub logs: Vec<String>,
    last_core_logs: Vec<String>,
    pub status: String,
    toast: Option<Toast>,
    pub page: Page,
    pub editor: Option<crate::pages::profile_editor::EditorState>,
    pub rule_draft: Rule,
    pub source_draft: BypassSource,
    pub detecting_country: bool,
    pub updating_sources: Vec<String>,
    country_request: u64,
    automatic_country_attempted: bool,
    location_request: u64,
    pub search: String,
    pub server_filter: String,
    pub log_filter: String,
    pub log_autoscroll: bool,
    pub confirm_delete: Option<(String, Instant)>,
    pub import_text: String,
    pub subscription_name: String,
    pub subscription_url: String,
    pub session_start: Option<Instant>,
    pub upload_speed: f64,
    pub download_speed: f64,
    pub location: String,
    pub location_detail: String,
    pub location_country_code: String,
    pub flags: FlagCache,
    generation: u64,
    telemetry_stop: Option<Arc<AtomicBool>>,
    context: egui::Context,
}
impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, platform: Box<dyn Platform>) -> Self {
        theme::setup(&cc.egui_ctx);
        let mobile = platform.is_mobile();
        let first_run = !easyvpn_core::store::data_dir().join("store.json").exists();
        let (mut store, status) = match Store::load() {
            Ok(store) => (store, String::new()),
            Err(error) => (Store::default(), format!("Could not load store: {error:#}")),
        };
        if mobile && (first_run || store.settings.mode == ProxyMode::System) {
            store.settings.mode = ProxyMode::Tun;
            store.settings.system_proxy = false;
            store.settings.tun = false;
        }
        let window = if mobile { WindowState::default() } else { WindowState::load() };
        let (sender, receiver) = mpsc::channel();
        let mut app = Self {
            store, window, platform: Arc::from(platform), sender, receiver, process: None,
            proxy_owner: Arc::new(Mutex::new(None)),
            connecting: false, conn_state: ConnState::Disconnected, failed_at: None,
            health_failures: 0, connection_cancel: None, active_config: None,
            pending_vpn: None, platform_vpn_active: false,
            installing: false, installing_core: None, install_progress: String::new(),
            importing_files: false, updating_subscriptions: false, updating_ids: Vec::new(),
            queued_subscription_ids: Vec::new(), smart_subscription_ids: Vec::new(), qr_pending: false,
            update: None, update_busy: false, update_status: String::new(),
            pinging: false, pings: HashMap::new(), logs: Vec::new(), last_core_logs: Vec::new(),
            status, toast: None, page: Page::Home, editor: None,
            rule_draft: Rule::default(), source_draft: BypassSource::default(),
            detecting_country: false, updating_sources: Vec::new(), country_request: 0,
            automatic_country_attempted: false, location_request: 0,
            search: String::new(), server_filter: "all".into(),
            log_filter: "All".into(), log_autoscroll: true,
            confirm_delete: None, import_text: String::new(),
            subscription_name: String::new(), subscription_url: String::new(),
            session_start: None, upload_speed: 0.0_f64, download_speed: 0.0_f64,
            location: "Disconnected".into(), location_detail: String::new(),
            location_country_code: String::new(), flags: FlagCache::default(),
            generation: 0, telemetry_stop: None, context: cc.egui_ctx.clone(),
        };
        platform::install_clipboard(&cc.egui_ctx, app.platform.clone());
        update::cleanup();
        let wake_ctx = cc.egui_ctx.clone();
        app.platform.set_wake(Arc::new(move || wake_ctx.request_repaint()));
        app.sync_core();
        if mobile && first_run { app.save(); }
        app.ensure_bypass_country(&cc.egui_ctx);
        app
    }
    pub fn save(&mut self) {
        if let Err(error) = self.store.save() { self.status = format!("Could not save store: {error:#}"); }
    }
    pub fn sync_core(&mut self) {
        let mut changed = false;
        if self.store.selected_profile().is_none() {
            let selected = self.store.profiles.first().map(|p| p.id.clone());
            if selected != self.store.selected { self.store.selected = selected; changed = true; }
        }
        if let Some(kind) = self.store.selected_profile().and_then(|p| p.pick_core(self.store.settings.core)) {
            if kind != self.store.settings.core { self.store.settings.core = kind; changed = true; }
        }
        if changed { self.save(); }
    }
    pub fn ensure_bypass_country(&mut self, ctx: &egui::Context) {
        if !self.store.settings.bypass.enabled { self.automatic_country_attempted = false; return; }
        if self.store.settings.bypass.country.is_empty() && !self.automatic_country_attempted && !self.detecting_country {
            self.detect_bypass_country(ctx);
        }
    }
    pub fn detect_bypass_country(&mut self, ctx: &egui::Context) {
        if self.detecting_country { return; }
        self.detecting_country = true;
        self.automatic_country_attempted = true;
        self.country_request = self.country_request.wrapping_add(1);
        let request = self.country_request;
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        self.status = "Detecting bypass country directly…".into();
        thread::spawn(move || {
            let result = rules::detect_country().map_err(|e| format!("{e:#}"));
            let _ = sender.send(Event::Country(request, result));
            ctx.request_repaint();
        });
    }
    pub fn update_bypass_sources(&mut self, id: Option<String>, ctx: &egui::Context) {
        let sources: Vec<_> = self.store.settings.bypass.sources.iter()
            .filter(|source| match id.as_deref() { Some(id) => source.id == id, None => source.enabled })
            .filter(|source| !self.updating_sources.contains(&source.id)).cloned().collect();
        if sources.is_empty() { return; }
        self.updating_sources.extend(sources.iter().map(|source| source.id.clone()));
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            for source in sources {
                let _ = sender.send(Event::SourceProgress(format!("Downloading {}…", source.name)));
                ctx.request_repaint();
                let mut updated = source.clone();
                let result = rules::update_source(&mut updated).map(|_| updated).map_err(|e| format!("{e:#}"));
                if sender.send(Event::SourceUpdated(source, result)).is_err() { return; }
                ctx.request_repaint();
            }
        });
    }
    pub fn copy_text(&mut self, text: String) {
        self.platform.clipboard_set(&text);
        self.status = "Copied to clipboard".into();
    }
    pub fn copy_profile(&mut self, profile: &Profile) {
        match link::to_link(profile) {
            Ok(text) => self.copy_text(text),
            Err(error) => self.status = format!("Could not copy link: {error:#}"),
        }
    }
    pub fn paste(&mut self) {
        match self.platform.clipboard_get() {
            Some(text) => { self.smart_import(&text); }
            None => self.status = "Clipboard doesn't contain a config or subscription link".into(),
        }
    }

    /// All interactive text imports use the same classification path.
    /// Returns true when the input was accepted, including an asynchronous
    /// subscription update.
    pub fn smart_import(&mut self, text: &str) -> bool {
        match import::classify(text) {
            import::Classified::Subscription(url) => {
                let id = if let Some(existing) = self.store.subscriptions.iter().find(|sub| sub.url == url) {
                    existing.id.clone()
                } else {
                    let name = url::Url::parse(&url).ok()
                        .and_then(|parsed| parsed.host_str().map(str::to_owned))
                        .unwrap_or_else(|| "Subscription".into());
                    self.store.add_subscription(&name, &url)
                };
                if !self.smart_subscription_ids.contains(&id) { self.smart_subscription_ids.push(id.clone()); }
                self.save();
                let ctx = self.context.clone();
                if self.updating_subscriptions {
                    // An update already in flight for this URL also satisfies
                    // the import. Otherwise queue it, never silently drop it.
                    if !self.updating_ids.contains(&id) && !self.queued_subscription_ids.contains(&id) {
                        self.queued_subscription_ids.push(id);
                    }
                } else {
                    self.update_subscriptions(Some(id), &ctx);
                }
                self.status = "Updating subscription…".into();
                true
            }
            import::Classified::Configs(profiles) if !profiles.is_empty() => {
                self.add_imported(profiles, Vec::new());
                true
            }
            import::Classified::Configs(_) | import::Classified::Nothing => {
                self.status = "Clipboard doesn't contain a config or subscription link".into();
                false
            }
        }
    }
    fn start_qr_scan(&mut self) {
        if self.qr_pending { return; }
        match self.platform.start_qr_scan() {
            Ok(()) => { self.qr_pending = true; }
            Err(error) => self.status = format!("QR scan failed: {error:#}"),
        }
    }
    fn poll_qr_scan(&mut self, ctx: &egui::Context) {
        if !self.qr_pending { return; }
        match self.platform.take_qr_result() {
            Some(result) => {
                self.qr_pending = false;
                match result {
                    Ok(text) => {
                        if self.smart_import(&text) { self.page = Page::Home; }
                    }
                    Err(message) if message == "cancelled" => {}
                    Err(message) => self.status = format!("QR scan failed: {message}"),
                }
            }
            None => ctx.request_repaint_after(Duration::from_millis(100)),
        }
    }
    pub fn add_imported(&mut self, profiles: Vec<Profile>, errors: Vec<String>) {
        let count = profiles.len();
        for profile in profiles {
            let id = self.store.add_profile(profile);
            if self.store.selected_profile().is_none() { self.store.selected = Some(id); }
        }
        self.status = if errors.is_empty() {
            if count == 0 { "No supported configurations found".into() } else { format!("{count} configs imported") }
        } else { format!("{count} configs imported; error: {}", errors.join("; ")) };
        if count > 0 { self.sync_core(); self.save(); }
    }
    pub fn import_files(&mut self, paths: Option<Vec<PathBuf>>, ctx: &egui::Context) {
        if paths.is_none() && self.platform.is_mobile() { self.page = Page::Import; return; }
        self.importing_files = true;
        let sender = self.sender.clone();
        let platform = self.platform.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let paths = paths.or_else(|| platform.pick_import_file().map(|path| vec![path]));
            let mut profiles = Vec::new();
            let mut errors = Vec::new();
            if let Some(paths) = paths {
                for path in paths {
                    match import::import_file(&path) {
                        Ok(found) => profiles.extend(found),
                        Err(error) => errors.push(format!("{}: {error:#}", path.display())),
                    }
                }
            }
            let _ = sender.send(Event::Imported(profiles, errors));
            ctx.request_repaint();
        });
    }
    pub fn select_profile(&mut self, id: String) {
        self.store.selected = Some(id); self.sync_core(); self.save(); self.page = Page::Home;
    }
    pub fn delete_profile(&mut self, id: &str) {
        if self.store.remove_profile(id) {
            if self.store.selected.as_deref() == Some(id) { self.store.selected = None; }
            self.pings.remove(id); self.sync_core(); self.save(); self.status = "Server deleted".into();
        }
    }
    pub fn start_ping(&mut self, ctx: &egui::Context) {
        if self.pinging { return; }
        self.pinging = true; self.pings.clear();
        let profiles = self.store.profiles.clone();
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let skipped = profiles.iter().filter(|p| tcp_ping_skipped(p)).count();
            let results = ping::ping_all(&profiles, Duration::from_secs(3));
            let _ = sender.send(Event::Pings(results, skipped));
            ctx.request_repaint();
        });
    }
    /// While connected, our own traffic is outside the tunnel on Android, so go through the local proxy.
    fn tunnel_proxy(&self) -> Option<String> {
        if !matches!(self.conn_state, ConnState::Connected { .. }) { return None; }
        let (kind, profile, settings) = self.active_config.as_ref()?;
        active_probe_route(self.platform.is_mobile(), *kind, profile, settings).proxy
    }
    pub fn check_update(&mut self, ctx: &egui::Context) {
        if self.update_busy { return; }
        self.update_busy = true; self.update = None; self.update_status = "Checking for updates…".into();
        let (proxy, sender, ctx) = (self.tunnel_proxy(), self.sender.clone(), ctx.clone());
        thread::spawn(move || {
            let result = update::check(proxy.as_deref()).map_err(|e| format!("{e:#}"));
            let _ = sender.send(Event::UpdateChecked(result)); ctx.request_repaint();
        });
    }
    pub fn download_update(&mut self, ctx: &egui::Context) {
        let Some(found) = self.update.clone() else { return; };
        if self.update_busy { return; }
        self.update_busy = true; self.update_status = "Downloading update…".into();
        let (proxy, sender, ctx) = (self.tunnel_proxy(), self.sender.clone(), ctx.clone());
        thread::spawn(move || {
            let dest = update::staging_path(&store::data_dir());
            let result = update::download(&found.url, &dest, proxy.as_deref(), &mut |message| {
                let _ = sender.send(Event::UpdateProgress(message)); ctx.request_repaint();
            }).map(|()| dest).map_err(|e| format!("{e:#}"));
            let _ = sender.send(Event::UpdateDownloaded(result)); ctx.request_repaint();
        });
    }
    pub fn install_core(&mut self, kind: CoreKind, ctx: &egui::Context) {
        if self.platform.is_mobile() { self.status = "Cores are bundled with the Android app".into(); return; }
        if self.installing || self.connecting || self.process.is_some() { return; }
        if kind.is_tunnel() { self.status = openvpn_install_hint().into(); return; }
        self.installing = true; self.installing_core = Some(kind); self.install_progress = "Starting download…".into();
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = download::install(kind, &mut |message| {
                let _ = sender.send(Event::Progress(message)); ctx.request_repaint();
            }).map(|path| format!("Installed {} at {}", kind.name(), path.display())).map_err(|e| format!("{e:#}"));
            let _ = sender.send(Event::Installed(result)); ctx.request_repaint();
        });
    }
    pub fn update_subscriptions(&mut self, id: Option<String>, ctx: &egui::Context) {
        if self.updating_subscriptions { return; }
        let ids = id.map(|id| vec![id]).unwrap_or_else(|| self.store.subscriptions.iter().map(|s| s.id.clone()).collect());
        if ids.is_empty() { self.status = "No subscriptions to update".into(); return; }
        self.updating_subscriptions = true;
        self.updating_ids = ids.clone();
        let mut snapshot = self.store.clone();
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let mut results = Vec::new();
            for id in ids {
                let result = subscription::update(&mut snapshot, &id).map(|_| snapshot.clone()).map_err(|e| format!("{e:#}"));
                results.push((id, result));
            }
            let _ = sender.send(Event::Subscriptions(results)); ctx.request_repaint();
        });
    }
    fn merge_subscription(&mut self, id: &str, updated: Store) -> usize {
        let Some(index) = self.store.subscriptions.iter().position(|s| s.id == id) else { return 0; };
        let selected_key = self.store.selected_profile().filter(|p| p.subscription_id.as_deref() == Some(id))
            .map(|p| (p.name.clone(), p.address.clone()));
        let replacements: Vec<_> = updated.profiles.into_iter().filter(|p| p.subscription_id.as_deref() == Some(id)).collect();
        let count = replacements.len();
        if let Some((name, address)) = selected_key {
            self.store.selected = replacements.iter().find(|p| p.name == name && p.address == address).map(|p| p.id.clone());
        }
        self.store.profiles.retain(|p| p.subscription_id.as_deref() != Some(id));
        self.store.profiles.extend(replacements);
        if let Some(sub) = updated.subscriptions.into_iter().find(|s| s.id == id) { self.store.subscriptions[index] = sub; }
        count
    }
    pub fn add_subscription(&mut self) {
        let name = self.subscription_name.trim();
        let url = self.subscription_url.trim();
        if name.is_empty() || url.is_empty() { return; }
        self.store.add_subscription(name, url);
        self.subscription_name.clear(); self.subscription_url.clear();
        self.status = "Subscription added".into(); self.save(); self.page = Page::Subscriptions;
    }
    pub fn remove_subscription(&mut self, id: &str) {
        self.store.remove_subscription(id);
        self.queued_subscription_ids.retain(|queued| queued != id);
        self.smart_subscription_ids.retain(|queued| queued != id);
        if self.store.selected_profile().is_none() { self.store.selected = None; }
        if self.server_filter == id { self.server_filter = "all".into(); }
        self.confirm_delete = None; self.sync_core(); self.save(); self.status = "Subscription deleted".into();
    }
    pub fn toggle_connection(&mut self, ctx: &egui::Context) {
        if self.connecting || self.process.is_some() { self.disconnect(); } else { self.connect(ctx); }
    }
    fn connect(&mut self, ctx: &egui::Context) {
        if self.installing { return; }
        self.sync_core();
        let Some(profile) = self.store.selected_profile().cloned() else {
            self.status = "Add and select a configuration first".into(); return;
        };
        let mobile = self.platform.is_mobile();
        let mut settings = self.store.settings.clone();
        if !profile.supported_cores().contains(&settings.core) {
            self.status = "No supported core is configured for this profile".into(); return;
        }
        if mobile && settings.core.is_tunnel() { self.status = "OpenVPN is not supported on Android".into(); return; }
        if mobile && settings.mode == ProxyMode::System { settings.mode = ProxyMode::Tun; }
        if !core::is_installed(settings.core) {
            self.status = if mobile {
                format!("Bundled {} core is missing — reinstall the app", settings.core.name())
            } else if settings.core.is_tunnel() { openvpn_install_hint().into() }
            else { format!("Install {} in Settings first", settings.core.name()) };
            return;
        }
        settings.system_proxy = false; settings.tun = false;
        if settings.core.is_tunnel() { settings.mode = ProxyMode::Local; }
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let cancel = Arc::new(AtomicBool::new(false));
        self.connection_cancel = Some(cancel.clone());
        self.pending_vpn = None; self.platform_vpn_active = false; self.connecting = true;
        self.conn_state = ConnState::Connecting { since: Instant::now() };
        self.failed_at = None; self.health_failures = 0; self.active_config = None;
        self.logs.clear(); self.last_core_logs.clear(); self.location = "Checking…".into();
        self.location_detail.clear(); self.location_country_code.clear(); self.status.clear();
        let sender = self.sender.clone();
        let owner = self.proxy_owner.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let result = (|| -> Result<(Connection, Settings, Profile)> {
                if !mobile && (settings.mode == ProxyMode::Tun || settings.core.is_tunnel()) && !core::is_elevated() {
                    anyhow::bail!(if settings.core.is_tunnel() { "OpenVPN needs Administrator/root" } else { "TUN mode needs Administrator/root" });
                }
                if cancel.load(Ordering::Acquire) { anyhow::bail!("Connection cancelled"); }
                let core_settings = process_settings(&settings, mobile);
                let process = Connection::start(settings.core, &profile, &core_settings)?;
                if cancel.load(Ordering::Acquire) { anyhow::bail!("Connection cancelled"); }
                if !mobile { acquire_proxy(&owner, generation, &cancel, &profile, &settings)?; }
                if cancel.load(Ordering::Acquire) { anyhow::bail!("Connection cancelled"); }
                Ok((process, settings, profile))
            })().map_err(|e| format!("{e:#}"));
            if result.is_err() || cancel.load(Ordering::Acquire) { let _ = release_proxy(&owner, generation); }
            if cancel.load(Ordering::Acquire) { drop(result); return; }
            let _ = sender.send(Event::Started(generation, result)); ctx.request_repaint();
        });
    }
    pub fn disconnect(&mut self) {
        if self.platform.is_mobile() { self.platform.stop_vpn(); }
        self.pending_vpn = None; self.platform_vpn_active = false;
        let old_generation = self.generation;
        self.generation = self.generation.wrapping_add(1);
        self.connecting = false; self.conn_state = ConnState::Disconnected; self.failed_at = None;
        if let Some(cancel) = self.connection_cancel.take() { cancel.store(true, Ordering::Release); }
        if let Some(stop) = self.telemetry_stop.take() { stop.store(true, Ordering::Release); }
        let process = self.process.take();
        if let Some(process) = &process { self.append_logs(process.logs()); }
        retire_connection(process, self.proxy_owner.clone(), old_generation, self.sender.clone(), self.context.clone());
        self.active_config = None; self.session_start = None;
        self.upload_speed = 0.0_f64; self.download_speed = 0.0_f64;
        self.location = "Disconnected".into(); self.location_detail.clear(); self.location_country_code.clear(); self.status.clear();
    }
    fn fail_connection(&mut self, error: String) {
        self.logs.push(format!("[error] {error}")); self.disconnect();
        self.conn_state = ConnState::Failed; self.failed_at = Some(Instant::now());
        self.status = format!("Connection failed: {error} — see Logs");
    }
    fn complete_verification(&mut self, rtt_ms: u128, ctx: &egui::Context) {
        if !self.process.as_mut().is_some_and(Connection::is_running) { self.fail_connection("Core stopped — see Logs".into()); return; }
        self.pending_vpn = None; self.connecting = false; self.conn_state = ConnState::Connected { rtt_ms };
        self.session_start = Some(Instant::now());
        self.logs.push(format!("[info] Connection verified: {rtt_ms} ms"));
        if let Some((kind, profile, settings)) = self.active_config.clone() { self.start_telemetry(kind, profile, settings, ctx); }
    }
    fn begin_platform_vpn(&mut self, rtt_ms: u128) {
        let Some((_, _, settings)) = &self.active_config else { return; };
        let (allowed, disallowed) = android_app_lists(settings);
        let port = settings.mixed_port;
        self.pending_vpn = Some((Instant::now(), rtt_ms)); self.platform_vpn_active = true;
        self.logs.push("[info] Requesting Android VPN permission and starting VPN".into());
        if let Err(error) = self.platform.start_vpn(port, &allowed, &disallowed) {
            self.fail_connection(format!("Could not start Android VPN: {error:#}"));
        }
    }
    fn poll_platform_vpn(&mut self, ctx: &egui::Context) {
        if !self.platform.is_mobile() || !self.platform_vpn_active { return; }
        let status = self.platform.vpn_status();
        if let Some((since, rtt_ms)) = self.pending_vpn {
            match status {
                VpnStatus::Running => self.complete_verification(rtt_ms, ctx),
                VpnStatus::PermissionDenied => self.fail_connection("VPN permission denied".into()),
                VpnStatus::Failed(message) => self.fail_connection(format!("Android VPN: {message}")),
                VpnStatus::Idle | VpnStatus::Starting => {
                    if since.elapsed() >= Duration::from_secs(15) {
                        self.fail_connection("Android VPN did not start within 15 seconds".into());
                    } else { ctx.request_repaint_after(Duration::from_millis(50)); }
                }
            }
        } else {
            match status {
                VpnStatus::PermissionDenied => self.fail_connection("VPN permission denied".into()),
                VpnStatus::Failed(message) => self.fail_connection(format!("Android VPN: {message}")),
                VpnStatus::Idle => self.fail_connection("Android VPN stopped — see Logs".into()),
                VpnStatus::Starting | VpnStatus::Running => {}
            }
        }
    }
    fn refresh_location(&mut self, ctx: &egui::Context) {
        let Some((kind, profile, settings)) = &self.active_config else { return; };
        let route = active_probe_route(self.platform.is_mobile(), *kind, profile, settings);
        let proxy = if route.tunnel { None } else { route.proxy };
        self.location_request = self.location_request.wrapping_add(1);
        let request = self.location_request;
        let generation = self.generation;
        let cancel = self.connection_cancel.clone();
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        self.location = "Checking…".into(); self.location_detail.clear(); self.location_country_code.clear();
        thread::spawn(move || {
            let result = traffic::public_ip(proxy.as_deref()).map_err(|e| format!("{e:#}"));
            if cancel.as_ref().is_some_and(|cancel| cancel.load(Ordering::Acquire)) { return; }
            let _ = sender.send(Event::Location(generation, request, result)); ctx.request_repaint();
        });
    }
    fn start_telemetry(&mut self, kind: CoreKind, profile: Profile, settings: Settings, ctx: &egui::Context) {
        self.refresh_location(ctx);
        let generation = self.generation;
        let stop = Arc::new(AtomicBool::new(false));
        self.telemetry_stop = Some(stop.clone());
        if kind.is_tunnel() || profile.protocol == Some(Protocol::Custom) { return; }
        let sender = self.sender.clone();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let mut previous: Option<(Instant, u64, u64)> = None;
            let mut next = Instant::now();
            while !stop.load(Ordering::Acquire) {
                if Instant::now() < next { thread::sleep(Duration::from_millis(50)); continue; }
                let now = Instant::now();
                next = now + Duration::from_secs(1);
                let (upload, download) = match traffic::totals(kind, &settings) {
                    Ok((up, down)) => {
                        let speeds = previous.map(|(time, old_up, old_down)| {
                            let seconds = now.duration_since(time).as_secs_f64().max(0.001_f64);
                            (up.saturating_sub(old_up) as f64 / seconds, down.saturating_sub(old_down) as f64 / seconds)
                        }).unwrap_or((0.0_f64, 0.0_f64));
                        previous = Some((now, up, down)); speeds
                    }
                    Err(_) => { previous = None; (0.0_f64, 0.0_f64) }
                };
                if stop.load(Ordering::Acquire) { break; }
                if sender.send(Event::Speed(generation, upload, download)).is_err() { break; }
                ctx.request_repaint();
            }
        });
    }
    fn receive_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.receiver.try_recv() {
            match event {
                Event::Progress(message) => self.install_progress = message,
                Event::Installed(result) => {
                    self.installing = false; self.installing_core = None; self.install_progress.clear();
                    self.status = result.unwrap_or_else(|e| format!("Install failed: {e}"));
                }
                Event::UpdateProgress(message) => self.update_status = message,
                Event::UpdateChecked(result) => {
                    self.update_busy = false;
                    self.update_status = match result {
                        Ok(Some(found)) => { let text = format!("Version {} is available", found.version); self.update = Some(found); text }
                        Ok(None) => "You are on the latest version".into(),
                        Err(error) => format!("Update check failed: {error}"),
                    };
                }
                Event::UpdateDownloaded(result) => {
                    self.update_busy = false;
                    self.update_status = match result.and_then(|path| self.platform.install_update(&path).map_err(|e| format!("{e:#}"))) {
                        Ok(()) => "Installing update… confirm in the system dialog".into(),
                        Err(error) => format!("Update failed: {error}"),
                    };
                }
                Event::Imported(profiles, errors) => { self.importing_files = false; self.add_imported(profiles, errors); }
                Event::Pings(results, skipped) => {
                    self.pinging = false; self.pings = results.into_iter().collect(); self.status = ping_complete_message(skipped);
                }
                Event::Country(request, result) if request == self.country_request => {
                    self.detecting_country = false;
                    match result {
                        Ok(country) => {
                            let bypass = &mut self.store.settings.bypass;
                            let changed_country = bypass.country != country;
                            bypass.country = country;
                            if changed_country || bypass.sources.is_empty() {
                                let custom: Vec<_> = bypass.sources.iter().filter(|source| !source.builtin).cloned().collect();
                                bypass.sources = rules::recommended_sources(&bypass.country); bypass.sources.extend(custom);
                            }
                            self.status = format!("Detected bypass country: {}", bypass.country.to_ascii_uppercase());
                            self.save(); self.update_bypass_sources(None, ctx);
                        }
                        Err(error) => {
                            self.status = format!("Country detection failed: {error}"); self.logs.push(format!("[error] {}", self.status));
                        }
                    }
                }
                Event::Country(..) => {}
                Event::SourceProgress(message) => { self.logs.push(format!("[info] {message}")); self.status = message; }
                Event::SourceUpdated(original, result) => {
                    self.updating_sources.retain(|id| id != &original.id);
                    let current = self.store.settings.bypass.sources.iter_mut().find(|source| {
                        source.id == original.id && source.url == original.url && source.format == original.format
                    });
                    if let Some(current) = current {
                        match result {
                            Ok(updated) => {
                                current.entries = updated.entries; current.updated_at = updated.updated_at;
                                self.status = format!("Updated {}: {} entries", current.name, current.entries);
                                self.logs.push(format!("[info] {}", self.status)); self.save();
                            }
                            Err(error) => {
                                self.status = format!("Source update failed ({}): {error}", current.name);
                                self.logs.push(format!("[error] {}", self.status));
                            }
                        }
                    }
                }
                Event::Subscriptions(results) => {
                    self.updating_subscriptions = false; self.updating_ids.clear();
                    let mut count = 0;
                    let mut smart = false;
                    let mut errors = Vec::new();
                    for (id, result) in results {
                        smart |= self.smart_subscription_ids.contains(&id);
                        self.smart_subscription_ids.retain(|pending| pending != &id);
                        match result {
                            Ok(updated) => count += self.merge_subscription(&id, updated),
                            Err(e) => errors.push(format!("{id}: {e}")),
                        }
                    }
                    self.status = if smart { format!("Subscription added · {count} servers") } else { format!("Updated {count} servers") };
                    if !errors.is_empty() { self.status.push_str(&format!("; error: {}", errors.join("; "))); }
                    self.sync_core(); self.save();
                    self.queued_subscription_ids.retain(|id| self.store.subscriptions.iter().any(|sub| &sub.id == id));
                    if !self.queued_subscription_ids.is_empty() {
                        let next = self.queued_subscription_ids.remove(0);
                        self.update_subscriptions(Some(next), ctx);
                    }
                }
                Event::Started(generation, result) => {
                    if generation != self.generation {
                        if let Ok((process, _, _)) = result {
                            retire_connection(Some(process), self.proxy_owner.clone(), generation, self.sender.clone(), ctx.clone());
                        }
                        continue;
                    }
                    match result {
                        Ok((mut process, settings, profile)) => {
                            if !process.is_running() {
                                self.append_logs(process.logs());
                                retire_connection(Some(process), self.proxy_owner.clone(), generation, self.sender.clone(), ctx.clone());
                                self.fail_connection("Core stopped — see Logs".into()); continue;
                            }
                            let kind = process.kind();
                            let route = active_probe_route(self.platform.is_mobile(), kind, &profile, &settings);
                            self.active_config = Some((kind, profile, settings)); self.process = Some(process);
                            self.conn_state = ConnState::Verifying { attempt: 1 };
                            if let Some(cancel) = &self.connection_cancel {
                                probe_worker(generation, route, cancel.clone(), self.sender.clone(), ctx.clone());
                            }
                        }
                        Err(error) => self.fail_connection(error),
                    }
                }
                Event::Verifying(generation, attempt) if generation == self.generation => self.conn_state = ConnState::Verifying { attempt },
                Event::Verified(generation, result) if generation == self.generation => {
                    match result {
                        Ok(rtt_ms) => {
                            if !self.process.as_mut().is_some_and(Connection::is_running) {
                                self.fail_connection("Core stopped — see Logs".into()); continue;
                            }
                            let needs_vpn = self.platform.is_mobile()
                                && self.active_config.as_ref().is_some_and(|(_, _, settings)| settings.mode == ProxyMode::Tun);
                            if needs_vpn { self.begin_platform_vpn(rtt_ms); } else { self.complete_verification(rtt_ms, ctx); }
                        }
                        Err(error) => self.fail_connection(error),
                    }
                }
                Event::Health(generation, result) if generation == self.generation => {
                    if self.pending_vpn.is_some() || self.conn_state.busy() { continue; }
                    let was_lost = matches!(self.conn_state, ConnState::Lost { .. });
                    if let Err(error) = &result { self.logs.push(format!("[warn] Health check failed: {error}")); }
                    self.conn_state = health_transition(&self.conn_state, &mut self.health_failures, &result, Instant::now());
                    if !was_lost && matches!(self.conn_state, ConnState::Lost { .. }) {
                        self.location_request = self.location_request.wrapping_add(1); self.location = "Connection lost".into();
                        self.location_detail.clear(); self.location_country_code.clear();
                        self.upload_speed = 0.0_f64; self.download_speed = 0.0_f64;
                        self.status = "CONNECTION LOST — retrying; see Logs".into();
                    } else if was_lost && self.conn_state.verified() {
                        self.status = "Connection recovered".into(); self.refresh_location(ctx);
                    }
                }
                Event::Speed(generation, upload, download) if generation == self.generation => {
                    if !matches!(self.conn_state, ConnState::Lost { .. }) { self.upload_speed = upload; self.download_speed = download; }
                }
                Event::Location(generation, request, result) if generation == self.generation && request == self.location_request => {
                    match result {
                        Ok(info) => {
                            self.location = format!("{} · {}", info.country_code.to_uppercase(), info.ip);
                            self.location_country_code = info.country_code.to_ascii_lowercase(); self.location_detail = info.country;
                        }
                        Err(e) => { self.location = "Unavailable".into(); self.location_detail = e; self.location_country_code.clear(); }
                    }
                }
                Event::CleanupError(error) => self.status = error,
                Event::Verifying(..) | Event::Verified(..) | Event::Health(..) | Event::Speed(..) | Event::Location(..) => {}
            }
            self.capture_toast();
        }
    }
    fn append_logs(&mut self, current: Vec<String>) {
        let overlap = (0..=self.last_core_logs.len().min(current.len())).rev()
            .find(|&n| self.last_core_logs[self.last_core_logs.len() - n..] == current[..n]).unwrap_or(0);
        self.logs.extend_from_slice(&current[overlap..]);
        if self.logs.len() > 1000 { self.logs.drain(..self.logs.len() - 1000); }
        self.last_core_logs = current;
    }
    fn capture_toast(&mut self) {
        if self.status.is_empty() { return; }
        let message = std::mem::take(&mut self.status);
        let lower = message.to_lowercase();
        let needs_admin = lower.contains("needs administrator/root");
        let color = if needs_admin || ["failed", "error", "could not", "no supported", "connection lost", "permission denied"].iter().any(|s| lower.contains(s)) {
            theme::RED
        } else if ["imported", "updated", "installed", "copied", "deleted", "added", "complete", "recovered"].iter().any(|s| lower.contains(s)) {
            theme::GREEN
        } else { theme::BLUE };
        self.toast = Some(Toast {
            message: display_name(&message).text, since: Instant::now(), color,
            restart_as_admin: cfg!(windows) && !self.platform.is_mobile() && needs_admin,
            see_logs: lower.contains("see logs"),
        });
    }
    #[cfg(windows)]
    fn restart_as_admin(&mut self, ctx: &egui::Context) {
        match launch_elevated() {
            Ok(()) => { self.save(); self.disconnect(); ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
            Err(error) => self.status = format!("Could not restart as administrator: {error:#}"),
        }
    }
    fn window_controls(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.allocate_ui_with_layout(egui::vec2(ui.available_width(), 30.0_f32), egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 4.0_f32;
            if theme::window_control(ui, true).on_hover_text("Close").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
            if theme::window_control(ui, false).on_hover_text("Minimize").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)); }
            if theme::expand_control(ui).on_hover_text("Mini mode").clicked() { self.window.toggle(ctx); }
        });
    }
    fn go_back(&mut self) {
        self.page = match self.page { Page::Rules | Page::Sources => Page::Settings, _ => Page::Home };
    }
    /// Hardware Back: step out of a sub-page, or hide the app (VPN keeps running) from Home.
    fn handle_back(&mut self) {
        if !self.platform.take_back_press() { return; }
        if self.page == Page::Home { self.platform.move_to_background(); } else { self.go_back(); }
    }
    fn navigation(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.page != Page::Home {
            let right = match self.page {
                Page::Servers => Some(theme::Icon::Lightning), Page::Subscriptions => Some(theme::Icon::Refresh), _ => None,
            };
            let (back, action) = theme::top_bar(ui, self.page.title(), right);
            if back.clicked() { self.go_back(); }
            if let Some(action) = action {
                let busy = match self.page { Page::Servers => self.pinging, Page::Subscriptions => self.updating_subscriptions, _ => false };
                if busy {
                    let t = ui.input(|i| i.time) as f32 * 4.0_f32;
                    ui.painter().circle_filled(action.rect.center(), 15.0_f32, theme::GLASS);
                    theme::arc(ui.painter(), action.rect.center(), 9.0_f32, t, t + 4.5_f32, egui::Stroke::new(2.0_f32, theme::BLUE));
                    ctx.request_repaint();
                }
                if action.on_hover_text(if self.page == Page::Servers { "Ping all" } else { "Update all" }).clicked() && !busy {
                    match self.page { Page::Servers => self.start_ping(ctx), Page::Subscriptions => self.update_subscriptions(None, ctx), _ => {} }
                }
            }
            ui.add_space(16.0_f32); return;
        }
        let (bar, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 44.0_f32), egui::Sense::hover());
        if !self.platform.is_mobile() {
            let drag = ui.interact(bar, ui.id().with("title-drag"), egui::Sense::drag());
            if drag.drag_started_by(egui::PointerButton::Primary) && WindowState::can_drag(ctx) {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
        }
        let left = egui::Rect::from_min_size(bar.min, egui::vec2(44.0_f32, 44.0_f32));
        let right = egui::Rect::from_min_size(egui::pos2(bar.right() - 44.0_f32, bar.top()), egui::vec2(44.0_f32, 44.0_f32));
        ui.allocate_new_ui(egui::UiBuilder::new().max_rect(left), |ui| {
            let response = theme::round_button(ui, theme::Icon::Plus);
            theme::dropdown(ui, ui.make_persistent_id("add-menu"), &response, |ui| {
                for (icon, label, action) in [
                    (theme::Icon::Clipboard, "Paste from clipboard", 0),
                    (theme::Icon::File, "Import file…", 1),
                    (theme::Icon::Text, "Import text…", 2),
                    (theme::Icon::Link, "Add subscription…", 3),
                    (theme::Icon::Plus, "Add manually…", 4),
                    (theme::Icon::Camera, "Scan QR code", 5),
                ] {
                    if action == 1 && self.platform.is_mobile() { continue; }
                    if action == 5 && !self.platform.can_scan_qr() { continue; }
                    if theme::menu_row(ui, icon, label, false).clicked() {
                        match action {
                            0 => self.paste(), 1 => self.import_files(None, ctx),
                            2 => self.page = Page::Import, 3 => self.page = Page::AddSubscription,
                            5 => self.start_qr_scan(),
                            _ => { self.editor = Some(pages::profile_editor::EditorState::new(None)); self.page = Page::Editor; }
                        }
                        ui.close_menu();
                    }
                }
            });
        });
        let painter = ui.painter();
        let easy = painter.layout_no_wrap("Easy".into(), theme::bold_font(20.0_f32), theme::TEXT);
        let vpn = painter.layout_no_wrap("Vpn".into(), theme::bold_font(20.0_f32), theme::BLUE);
        let width = 17.0_f32 + easy.size().x + vpn.size().x;
        let start = bar.center().x - width / 2.0_f32;
        let dot = if self.conn_state.verified() { egui::Color32::from_rgb(34, 197, 94) }
            else if matches!(self.conn_state, ConnState::Lost { .. }) { egui::Color32::from_rgb(239, 68, 68) }
            else { theme::MUTED };
        painter.circle_filled(egui::pos2(start + 4.0_f32, bar.center().y), 4.0_f32, dot);
        let x = start + 17.0_f32;
        let vpn_x = x + easy.size().x;
        painter.galley(egui::pos2(x, bar.center().y - easy.size().y / 2.0_f32), easy, theme::TEXT);
        painter.galley(egui::pos2(vpn_x, bar.center().y - vpn.size().y / 2.0_f32), vpn, theme::BLUE);
        ui.allocate_new_ui(egui::UiBuilder::new().max_rect(right), |ui| {
            let response = theme::round_button(ui, theme::Icon::Menu);
            theme::dropdown(ui, ui.make_persistent_id("nav-menu"), &response, |ui| {
                for (page, icon) in [
                    (Page::Servers, theme::Icon::Server), (Page::Subscriptions, theme::Icon::Link),
                    (Page::Settings, theme::Icon::Gear), (Page::Logs, theme::Icon::Terminal), (Page::About, theme::Icon::Info),
                ] {
                    if theme::menu_row(ui, icon, page.title(), false).clicked() { self.page = page; ui.close_menu(); }
                }
            });
        });
        ui.add_space(16.0_f32);
    }
}
impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] { [0.0_f32; 4] }
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if self.platform.is_mobile() { platform::drain_edit_events(ctx, raw_input); }
    }
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mobile = self.platform.is_mobile();
        platform::install_clipboard(ctx, self.platform.clone());
        if !mobile { self.window.begin_frame(ctx); }
        self.receive_events(ctx); self.handle_back(); self.poll_qr_scan(ctx); self.poll_platform_vpn(ctx); self.ensure_bypass_country(ctx);
        let paths: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if !paths.is_empty() { self.import_files(Some(paths), ctx); }
        let mut exited = false;
        if let Some(process) = &mut self.process {
            let logs = process.logs(); exited = !process.is_running(); self.append_logs(logs);
        }
        if exited {
            if self.conn_state.busy() { self.fail_connection("Core stopped — see Logs".into()); }
            else { self.disconnect(); self.status = "Core stopped — see Logs".into(); }
        }
        if self.logs.len() > 1000 { self.logs.drain(..self.logs.len() - 1000); }
        if self.confirm_delete.as_ref().is_some_and(|(_, time)| time.elapsed() > Duration::from_secs(3)) { self.confirm_delete = None; }
        let size = ctx.screen_rect().size();
        let mini = !mobile && self.window.is_mini(size);
        let escape = ctx.input(|i| i.key_pressed(egui::Key::Escape));
        if mini && (escape || self.page != Page::Home) { self.window.restore(ctx); }
        let (safe_top, safe_bottom) = if mobile {
            let (top, bottom) = self.platform.safe_area();
            let sanitize = |value: f32| if value.is_finite() { value.clamp(0.0_f32, size.y.max(0.0_f32) / 2.0_f32) } else { 0.0_f32 };
            (sanitize(top), sanitize(bottom))
        } else { (0.0_f32, 0.0_f32) };
        theme::set_mobile(ctx, mobile, safe_top, safe_bottom);
        self.capture_toast();
        let layout = pages::home::layout_for(size);
        egui::CentralPanel::default().frame(egui::Frame::none()).show(ctx, |ui| {
            let window = ui.max_rect();
            theme::background(ui.painter(), window);
            if !mobile {
                let drag = ui.interact(window, ui.id().with("background-drag"), egui::Sense::drag());
                if drag.drag_started_by(egui::PointerButton::Primary) && WindowState::can_drag(ctx) { ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag); }
            }
            if mini && self.page == Page::Home { pages::home::mini(self, ui, ctx); return; }
            let column = egui::Rect::from_min_size(
                egui::pos2(window.center().x - layout.column_width / 2.0_f32, window.top() + 6.0_f32 + safe_top),
                egui::vec2(layout.column_width, (window.height() - 26.0_f32 - safe_top - safe_bottom).max(0.0_f32)));
            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(column), |ui| {
                if !mobile { self.window_controls(ui, ctx); }
                self.navigation(ui, ctx);
                if self.page == Page::Home { pages::home::show(self, ui, ctx); }
                else {
                    egui::ScrollArea::vertical().id_salt("page-body").auto_shrink([false, false]).show(ui, |ui| {
                        match self.page {
                            Page::Home => {}, Page::Servers => pages::servers::show(self, ui, ctx),
                            Page::Subscriptions => pages::subscriptions::show(self, ui, ctx),
                            Page::Settings => pages::settings::show(self, ui, ctx),
                            Page::Logs => pages::logs::show(self, ui), Page::About => pages::about::show(self, ui),
                            Page::Import => pages::import::show(self, ui),
                            Page::AddSubscription => pages::subscriptions::add_form(self, ui),
                            Page::Editor => pages::profile_editor::show(self, ui, ctx),
                            Page::Rules => pages::rules::show(self, ui, ctx), Page::Sources => pages::sources::show(self, ui, ctx),
                        }
                    });
                }
            });
        });
        self.capture_toast();
        if let Some(toast) = &self.toast {
            if toast.since.elapsed() < Duration::from_secs(3) {
                let restart = toast.restart_as_admin;
                let see_logs = toast.see_logs;
                let action = if restart { Some("Restart as admin") } else if see_logs { Some("See Logs") } else { None };
                let clicked = theme::toast(ctx, &toast.message, toast.color, action);
                if clicked {
                    if see_logs && !restart { if mini { self.window.restore(ctx); } self.page = Page::Logs; }
                    #[cfg(windows)]
                    if restart { self.restart_as_admin(ctx); }
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            } else { self.toast = None; }
        }
        if mobile {
            let copied = ctx.output(|output| output.copied_text.clone());
            if !copied.is_empty() { self.platform.clipboard_set(&copied); }
        }
        if self.process.is_some() || self.connecting || self.installing || self.confirm_delete.is_some()
            || self.detecting_country || !self.updating_sources.is_empty() || self.qr_pending
        {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
}
impl Drop for App {
    fn drop(&mut self) {
        if self.platform.is_mobile() { self.platform.stop_vpn(); } else { self.window.save(); }
        if let Some(cancel) = self.connection_cancel.take() { cancel.store(true, Ordering::Release); }
        if let Some(stop) = self.telemetry_stop.take() { stop.store(true, Ordering::Release); }
        if let Some(mut process) = self.process.take() { process.stop(); }
        let mut owner = self.proxy_owner.lock().unwrap_or_else(|e| e.into_inner());
        if owner.is_some() { let _ = sysproxy::disable(); *owner = None; }
        drop(owner);
        while let Ok(event) = self.receiver.try_recv() {
            if let Event::Started(_, Ok((mut process, _, _))) = event { process.stop(); }
        }
    }
}
fn uses_system_proxy(profile: &Profile, settings: &Settings) -> bool {
    settings.mode == ProxyMode::System && !settings.core.is_tunnel() && profile.protocol != Some(Protocol::Custom)
}
#[cfg(windows)]
fn launch_elevated() -> Result<()> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt};
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(window: *mut c_void, operation: *const u16, file: *const u16,
            parameters: *const u16, directory: *const u16, show: i32) -> *mut c_void;
    }
    let executable = std::env::current_exe().context("Finding current executable")?;
    let file: Vec<u16> = executable.as_os_str().encode_wide().chain(Some(0)).collect();
    let operation: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let result = unsafe {
        ShellExecuteW(std::ptr::null_mut(), operation.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 1)
    } as isize;
    anyhow::ensure!(result > 32, "Windows elevation was cancelled or failed (code {result})");
    Ok(())
}
fn tcp_ping_skipped(profile: &Profile) -> bool {
    match profile.protocol {
        Some(Protocol::Hysteria | Protocol::Hysteria2 | Protocol::Tuic | Protocol::Wireguard | Protocol::Custom) => true,
        Some(Protocol::OpenVpn) => {
            let mut global_proto = None;
            let mut remote_proto = None;
            let mut found_remote = false;
            for line in profile.raw_config.lines() {
                let mut words = line.split_whitespace();
                match words.next() {
                    Some("proto") => global_proto = words.next(),
                    Some("remote") if !found_remote => { found_remote = true; remote_proto = words.nth(2); }
                    _ => {}
                }
            }
            !matches!(remote_proto.or(global_proto), Some("tcp" | "tcp-client"))
        }
        _ => false,
    }
}
fn ping_complete_message(skipped: usize) -> String {
    if skipped == 0 { "Ping complete".into() } else {
        let noun = if skipped == 1 { "profile" } else { "profiles" };
        format!("Ping complete; {skipped} {noun} skipped (UDP-only or raw config)")
    }
}
pub fn openvpn_install_hint() -> &'static str {
    if cfg!(target_os = "windows") { "Install OpenVPN: winget install OpenVPNTechnologies.OpenVPN" }
    else if cfg!(target_os = "macos") { "Install OpenVPN: brew install openvpn" }
    else { "Install OpenVPN: sudo apt install openvpn (Debian/Ubuntu), or sudo dnf install openvpn (Fedora)" }
}
pub fn mode_name(mode: ProxyMode) -> &'static str {
    match mode { ProxyMode::Local => "Local proxy", ProxyMode::System => "System proxy", ProxyMode::Tun => "TUN" }
}
pub fn routing_name(mode: RoutingMode) -> &'static str {
    match mode { RoutingMode::Global => "Global", RoutingMode::BypassLan => "Bypass LAN", RoutingMode::BypassIran => "Bypass country" }
}
pub fn protocol_name(protocol: Option<Protocol>) -> &'static str {
    match protocol {
        Some(Protocol::Vmess) => "VMess", Some(Protocol::Vless) => "VLESS", Some(Protocol::Trojan) => "Trojan",
        Some(Protocol::Shadowsocks) => "Shadowsocks", Some(Protocol::Socks) => "SOCKS", Some(Protocol::Http) => "HTTP",
        Some(Protocol::Hysteria2) => "Hysteria2", Some(Protocol::Tuic) => "TUIC", Some(Protocol::Wireguard) => "WireGuard",
        Some(Protocol::Ssh) => "SSH", Some(Protocol::AnyTls) => "AnyTLS", Some(Protocol::Hysteria) => "Hysteria",
        Some(Protocol::OpenVpn) => "OpenVPN", Some(Protocol::Custom) => "Custom", None => "Unknown",
    }
}
pub fn address(profile: &Profile) -> String {
    if profile.address.is_empty() { return "Raw configuration".into(); }
    if profile.address.contains(':') { format!("[{}]:{}", profile.address, profile.port) }
    else { format!("{}:{}", profile.address, profile.port) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn health_requires_two_consecutive_failures_and_recovers() {
        let now = Instant::now();
        let mut failures = 0;
        let connected = ConnState::Connected { rtt_ms: 42 };
        let first = health_transition(&connected, &mut failures, &Err("timeout".into()), now);
        assert!(first.verified()); assert_eq!(failures, 1);
        let recovered = health_transition(&first, &mut failures, &Ok(25), now);
        assert!(matches!(recovered, ConnState::Connected { rtt_ms: 25 })); assert_eq!(failures, 0);
        let first = health_transition(&recovered, &mut failures, &Err("timeout".into()), now);
        let lost = health_transition(&first, &mut failures, &Err("timeout".into()), now);
        assert!(matches!(lost, ConnState::Lost { since } if since == now));
        let later = now + Duration::from_secs(5);
        let still = health_transition(&lost, &mut failures, &Err("timeout".into()), later);
        assert!(matches!(still, ConnState::Lost { since } if since == now));
        let recovered = health_transition(&still, &mut failures, &Ok(18), later);
        assert!(matches!(recovered, ConnState::Connected { rtt_ms: 18 })); assert_eq!(failures, 0);
    }
    #[test]
    fn failure_counter_saturates() {
        let mut failures = u8::MAX;
        let state = ConnState::Lost { since: Instant::now() };
        let next = health_transition(&state, &mut failures, &Err("timeout".into()), Instant::now());
        assert!(matches!(next, ConnState::Lost { .. })); assert_eq!(failures, u8::MAX);
    }
    #[test]
    fn health_cannot_connect_an_unverified_or_cancelled_session() {
        let now = Instant::now();
        for state in [ConnState::Disconnected, ConnState::Connecting { since: now }, ConnState::Verifying { attempt: 2 }, ConnState::Failed] {
            let mut failures = 0;
            let next = health_transition(&state, &mut failures, &Ok(1), now);
            assert!(!next.verified());
            assert_eq!(std::mem::discriminant(&state), std::mem::discriminant(&next));
        }
    }
    #[test]
    fn tunnel_requires_direct_success_even_when_proxy_works() {
        assert_eq!(tunnel_result(Ok(12), false), Ok(12)); assert_eq!(tunnel_result(Ok(12), true), Ok(12));
        assert!(tunnel_result(Err("timeout".into()), true).expect_err("direct failed").contains("Server works but TUN is not routing"));
        assert_eq!(tunnel_result(Err("timeout".into()), false), Err("timeout".into()));
    }
    #[test]
    fn verification_routes_follow_active_mode_and_core() {
        let p = Profile { protocol: Some(Protocol::Vless), ..Default::default() };
        for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
            let s = Settings { mode, ..Default::default() };
            let route = probe_route(CoreKind::Xray, &p, &s);
            assert_eq!(route.tunnel, mode == ProxyMode::Tun);
            assert_eq!(route.proxy, Some(format!("http://127.0.0.1:{}", s.mixed_port + 1)));
        }
        let s = Settings::default();
        let route = probe_route(CoreKind::OpenVpn, &p, &s);
        assert!(route.tunnel); assert!(route.proxy.is_none());
        let custom = Profile { protocol: Some(Protocol::Custom), ..Default::default() };
        assert_eq!(probe_route(CoreKind::Xray, &custom, &s).proxy, Some(format!("http://127.0.0.1:{}", s.mixed_port)));
        let s = Settings { mode: ProxyMode::Tun, ..s };
        let route = probe_route(CoreKind::Xray, &custom, &s);
        assert!(route.tunnel); assert!(route.proxy.is_none());
    }
    #[test]
    fn mobile_probes_use_proxy_even_in_tun_mode() {
        let p = Profile { protocol: Some(Protocol::Vless), ..Default::default() };
        let s = Settings { mode: ProxyMode::Tun, ..Default::default() };
        let route = active_probe_route(true, CoreKind::Xray, &p, &s);
        assert!(!route.tunnel);
        assert_eq!(route.proxy, Some(format!("http://127.0.0.1:{}", s.mixed_port + 1)));
        assert!(active_probe_route(false, CoreKind::Xray, &p, &s).tunnel);
    }
    #[test]
    fn mobile_process_does_not_start_a_helper_or_apply_package_rules() {
        let s = Settings {
            mode: ProxyMode::Tun, default_route: DefaultRoute::Direct,
            rules: vec![
                Rule { kind: RuleKind::Process, value: "org.telegram.messenger".into(), ..Default::default() },
                Rule { kind: RuleKind::DomainSuffix, value: "example.com".into(), ..Default::default() },
            ], ..Default::default()
        };
        let local = process_settings(&s, true);
        assert_eq!(local.mode, ProxyMode::Local); assert_eq!(local.default_route, DefaultRoute::Proxy);
        assert_eq!(local.rules.len(), 1); assert_eq!(local.rules[0].kind, RuleKind::DomainSuffix);
        assert_eq!(process_settings(&s, false), s);
    }
    #[test]
    fn package_filters_ignore_disabled_block_and_nonprocess_rules() {
        let make = |value: &str, action| Rule { kind: RuleKind::Process, value: value.into(), action, ..Default::default() };
        let mut s = Settings {
            rules: vec![
                make("org.direct", RuleAction::Direct), make("org.proxy", RuleAction::Proxy),
                make("org.block", RuleAction::Block), make("org.direct", RuleAction::Direct),
                Rule { enabled: false, ..make("org.disabled", RuleAction::Direct) },
                Rule { kind: RuleKind::Domain, ..make("example.com", RuleAction::Direct) },
            ], ..Default::default()
        };
        let (allowed, disallowed) = android_app_lists(&s);
        assert!(allowed.is_empty()); assert_eq!(disallowed, ["org.direct"]);
        s.default_route = DefaultRoute::Direct;
        let (allowed, disallowed) = android_app_lists(&s);
        assert_eq!(allowed, ["org.proxy"]); assert_eq!(disallowed, ["org.direct"]);
    }
    #[test]
    fn cancellation_interrupts_health_wait() { assert!(wait_cancelled(&AtomicBool::new(true), Duration::from_secs(5))); }
    #[test]
    fn all_extended_protocols_have_names() {
        for (protocol, name) in [(Protocol::Ssh, "SSH"), (Protocol::AnyTls, "AnyTLS"), (Protocol::Hysteria, "Hysteria"), (Protocol::OpenVpn, "OpenVPN"), (Protocol::Custom, "Custom")] {
            assert_eq!(protocol_name(Some(protocol)), name);
        }
    }
    #[test]
    fn ipv6_address_is_bracketed() {
        let profile = Profile { address: "::1".into(), port: 443, ..Default::default() };
        assert_eq!(address(&profile), "[::1]:443");
    }
    #[test]
    fn only_system_mode_enables_os_proxy() {
        let profile = Profile { protocol: Some(Protocol::Vless), ..Default::default() };
        for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
            let settings = Settings { mode, system_proxy: true, tun: true, ..Default::default() };
            assert_eq!(uses_system_proxy(&profile, &settings), mode == ProxyMode::System);
        }
        let settings = Settings { mode: ProxyMode::System, ..Default::default() };
        let custom = Profile { protocol: Some(Protocol::Custom), ..Default::default() };
        assert!(!uses_system_proxy(&custom, &settings));
        let settings = Settings { core: CoreKind::OpenVpn, ..settings };
        assert!(!uses_system_proxy(&profile, &settings));
    }
    #[test]
    fn ping_message_only_mentions_actual_skips() {
        assert_eq!(ping_complete_message(0), "Ping complete");
        assert_eq!(ping_complete_message(1), "Ping complete; 1 profile skipped (UDP-only or raw config)");
        assert_eq!(ping_complete_message(3), "Ping complete; 3 profiles skipped (UDP-only or raw config)");
    }
    #[test]
    fn tcp_profiles_are_not_counted_as_skipped() {
        for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan, Protocol::Shadowsocks, Protocol::Socks, Protocol::Http, Protocol::Ssh, Protocol::AnyTls] {
            assert!(!tcp_ping_skipped(&Profile { protocol: Some(protocol), ..Default::default() }));
        }
        for protocol in [Protocol::Hysteria, Protocol::Hysteria2, Protocol::Tuic, Protocol::Wireguard, Protocol::Custom] {
            assert!(tcp_ping_skipped(&Profile { protocol: Some(protocol), ..Default::default() }));
        }
    }
    #[test]
    fn openvpn_ping_eligibility_uses_transport() {
        for (raw_config, skipped) in [
            ("client\nremote example.com 1194\n", true), ("proto udp\nremote example.com 1194\n", true),
            ("proto tcp\nremote example.com 443\n", false), ("proto tcp-client\nremote example.com 443\n", false),
            ("proto udp\nremote example.com 443 tcp-client\n", false), ("proto tcp\nremote example.com 1194 udp\n", true),
        ] {
            let profile = Profile { protocol: Some(Protocol::OpenVpn), raw_config: raw_config.into(), ..Default::default() };
            assert_eq!(tcp_ping_skipped(&profile), skipped, "{raw_config}");
        }
    }
}
