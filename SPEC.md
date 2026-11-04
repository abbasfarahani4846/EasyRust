# EasyVpn — spec

Cross-platform (Windows / Linux / macOS) V2Ray-family proxy client written in Rust.
It does not reimplement protocols; it drives the three mainstream cores as managed
child processes: **xray**, **sing-box**, **mihomo** (Clash.Meta). The app downloads
each core into its own data dir, generates the core's config from a `Profile`, runs it,
and exposes a local mixed (socks5+http) proxy, optional system proxy and TUN mode.

Protocols: vmess, vless (incl. REALITY + xtls-rprx-vision), trojan, shadowsocks (SIP002),
socks, http, hysteria2, tuic (v5), wireguard.
Transports: tcp (incl. http header), ws, grpc, h2, httpupgrade, xhttp, kcp, quic.

Rust edition 2021, stable toolchain. Errors: `anyhow::Result`. No `unwrap()` on
external input. No async runtime (plain threads + blocking `ureq`).

## Workspace layout

```
Cargo.toml                         workspace (done)
crates/easyvpn-core/src/
  lib.rs                           (done) declares modules below, `pub use profile::*;`
  profile.rs                       (done) shared data model — READ IT, use it exactly
  link.rs                          share-link parse/serialize
  config/mod.rs, xray.rs, singbox.rs, mihomo.rs
  core.rs                          core process manager
  download.rs                      core downloader
  store.rs                         persistence
  subscription.rs
  sysproxy.rs
  ping.rs
crates/easyvpn-cli/                binary `easyvpn`
crates/easyvpn-gui/                binary `easyvpn-gui` (eframe/egui)
```

Core crate dependencies available (already in its Cargo.toml): anyhow, serde, serde_json,
base64 0.22, url 2, percent-encoding 2, dirs 5, rand 0.8, ureq 2 (json), zip 2 (deflate),
flate2, tar, winreg 0.52 (windows only). If you truly need another crate, say so in a
`NOTES:` line at the top of your answer, with the exact Cargo.toml line.

## Public API (contract between modules — implement exactly these signatures)

### link.rs
```rust
pub fn parse_link(s: &str) -> anyhow::Result<Profile>;   // one share link
pub fn to_link(p: &Profile) -> anyhow::Result<String>;   // inverse
pub fn parse_many(text: &str) -> Vec<Profile>;           // subscription body: base64 (std or url-safe, padded or not) or plain; one link per line; skip bad lines
```
Schemes: `vmess://` (base64 JSON v2rayN format: v,ps,add,port,id,aid,scy,net,type,host,path,tls,sni,alpn,fp),
`vless://uuid@host:port?type=&security=&sni=&fp=&pbk=&sid=&spx=&flow=&path=&host=&serviceName=&headerType=&mode=&alpn=&allowInsecure=#name`,
`trojan://password@host:port?...#name` (same query keys; security defaults to tls),
`ss://` SIP002 (`base64(method:password)@host:port?plugin=...#name`, also userinfo percent-encoded plain form, also legacy `ss://base64(method:password@host:port)#name`),
`socks://` / `socks5://` (`base64(user:pass)@host:port` or plain user:pass), `http://` / `https://` proxies only when used via parse_link,
`hysteria2://` and `hy2://` (`password@host:port?sni=&insecure=1&obfs=salamander&obfs-password=&alpn=#name`),
`tuic://uuid:password@host:port?sni=&alpn=&congestion_control=&allow_insecure=1#name`,
`wireguard://` / `wg://` (`privatekey@host:port?publickey=&presharedkey=&address=10.0.0.2/32,fd00::2/128&mtu=&reserved=1,2,3#name`).
Names are percent-decoded. IPv6 hosts in brackets. Query value `type` maps to `Network` (`tcp`,`ws`,`grpc`,`h2`/`http`,`httpupgrade`,`xhttp`/`splithttp`,`kcp`/`mkcp`,`quic`).
`alpn` comma separated. Include `#[cfg(test)]` round-trip tests for every scheme.

### config/mod.rs
```rust
pub mod xray; pub mod singbox; pub mod mihomo;
pub fn build(core: CoreKind, p: &Profile, s: &Settings) -> anyhow::Result<String>; // pretty JSON text
pub fn file_name(core: CoreKind) -> &'static str; // "config.json" (xray, sing-box), "config.yaml" (mihomo; JSON is valid YAML)
```
Each submodule: `pub fn build(p: &Profile, s: &Settings) -> anyhow::Result<serde_json::Value>`;
returns Err if the core doesn't support the protocol (`CoreKind::supports`).
Every config must: listen a mixed socks5+http inbound on `s.listen:s.mixed_port` (listen 0.0.0.0 if `s.allow_lan`),
with sniffing; route per `s.routing` (Global / BypassLan: private IPs direct / BypassIran: private IPs + `*.ir` domains + geoip IR direct);
remote DNS `s.remote_dns` via proxy, `s.direct_dns` for direct; log level `s.log_level`.
- xray: standard v2fly/xray JSON (inbounds socks w/ udp + http, or one `mixed`-style pair on port and port... use a single `socks` inbound on mixed_port and an `http` inbound on mixed_port+1), streamSettings with tlsSettings/realitySettings, `geoip:private`, `geoip:ir`, `domain:ir`. TUN not supported by xray — ignore `s.tun`.
- sing-box: **1.12+ format**: `dns.servers` new typed format (`{"type":"https","server":"1.1.1.1","tag":"remote","detour":"proxy"}`, `{"type":"udp",...}`), no legacy `dns`/`block` outbounds, route rules with `action` (`sniff`, `hijack-dns`, `route`), `route.default_domain_resolver`, `route.auto_detect_interface: true`. Inbound `mixed`; if `s.tun` add `tun` inbound (`address: ["172.19.0.1/30","fdfe:dcba:9876::1/126"]`, `auto_route`, `strict_route`). Geoip IR via remote rule_set `https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ir.srs` (tag geoip-ir, download_detour proxy). Outbound tag of the server: `proxy`, plus `direct`. Wireguard: 1.12 moved WG to `endpoints` — use an endpoint tagged `proxy`.
- mihomo: Clash.Meta config as JSON: `mixed-port`, `allow-lan`, `bind-address`, `mode: rule`, `log-level` (map warning→warning, etc.), `dns` (enable, enhanced-mode fake-ip only when tun, nameserver), `tun` when `s.tun` (`enable`, `stack: mixed`, `auto-route`, `auto-detect-interface`, `dns-hijack: ["any:53"]`), `proxies: [one proxy named "proxy"]`, `rules`: `GEOIP,LAN,DIRECT,no-resolve`, `DOMAIN-SUFFIX,ir,DIRECT`, `GEOIP,IR,DIRECT`, `MATCH,proxy` per routing mode. Proxy types: vmess, vless (reality-opts, flow), trojan, ss (plugin obfs/v2ray-plugin mapping), socks5, http, hysteria2, tuic, wireguard; network opts `ws-opts`, `grpc-opts`, `h2-opts`, `http-opts`.
Include unit tests that build each core config for a vless-reality, vmess-ws-tls, trojan-grpc, ss, hysteria2 sample and assert key fields.

### store.rs
```rust
pub fn data_dir() -> std::path::PathBuf; // $EASYVPN_HOME or dirs::data_dir()/EasyVpn; create_dir_all
pub fn new_id() -> String;               // 8 lowercase hex chars
#[derive(Debug, Clone, Default, Serialize, Deserialize)] #[serde(default)]
pub struct Store { pub profiles: Vec<Profile>, pub subscriptions: Vec<Subscription>, pub settings: Settings, pub selected: Option<String> }
impl Store {
  pub fn load() -> anyhow::Result<Store>;        // data_dir()/store.json, missing file => Default
  pub fn save(&self) -> anyhow::Result<()>;      // atomic: write tmp then rename
  pub fn add_profile(&mut self, p: Profile) -> String;          // assigns id if empty, returns id
  pub fn remove_profile(&mut self, id: &str) -> bool;
  pub fn find(&self, key: &str) -> Option<&Profile>;            // by id, or 1-based index in list
  pub fn selected_profile(&self) -> Option<&Profile>;
  pub fn add_subscription(&mut self, name: &str, url: &str) -> String;
  pub fn remove_subscription(&mut self, id: &str) -> bool;       // also removes its profiles
}
```

### subscription.rs
```rust
pub fn fetch(url: &str) -> anyhow::Result<Vec<Profile>>;   // ureq GET, UA "v2rayN/7.0", timeout 20s, link::parse_many
pub fn update(store: &mut Store, sub_id: &str) -> anyhow::Result<usize>; // replace profiles of that sub (set subscription_id), set updated_at, keep `selected` if same name+address still exists
pub fn update_all(store: &mut Store) -> Vec<(String, anyhow::Result<usize>)>;
```

### ping.rs
```rust
pub fn tcp_ping(p: &Profile, timeout: std::time::Duration) -> anyhow::Result<std::time::Duration>; // resolve + TcpStream::connect_timeout; UDP-only protocols (hysteria2, tuic, wireguard) => Err
pub fn ping_all(profiles: &[Profile], timeout: std::time::Duration) -> Vec<(String, Option<u128>)>; // (profile id, millis), parallel threads, max 32 at once, same order as input
```

### sysproxy.rs
```rust
pub fn enable(host: &str, port: u16) -> anyhow::Result<()>;
pub fn disable() -> anyhow::Result<()>;
```
Windows: HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings ProxyEnable/ProxyServer/ProxyOverride (`localhost;127.*;10.*;172.16.*;192.168.*;<local>`), then notify via `InternetSetOptionW` (INTERNET_OPTION_SETTINGS_CHANGED=39, INTERNET_OPTION_REFRESH=37) declared with `extern "system"` from `wininet` (`#[link(name = "wininet")]`) — no extra crate.
macOS: `networksetup -listallnetworkservices`, then for each enabled service set web, secure web, and socks proxy (and `...state off` on disable).
Linux: best effort `gsettings` (org.gnome.system.proxy mode manual/none, http/https/socks host+port) and also `kwriteconfig5`/`kwriteconfig6` if present; ignore missing tools, Err only if nothing worked.

### core.rs
```rust
pub fn cores_dir() -> PathBuf;                     // store::data_dir()/cores
pub fn binary_path(kind: CoreKind) -> PathBuf;     // cores_dir()/<kind.name()>/<exe> ; exe = "xray" | "sing-box" | "mihomo" (+ ".exe" on windows)
pub fn is_installed(kind: CoreKind) -> bool;
pub struct CoreProcess { /* child, kind, log buffer */ }
impl CoreProcess {
  pub fn start(kind: CoreKind, p: &Profile, s: &Settings) -> anyhow::Result<CoreProcess>;
  pub fn kind(&self) -> CoreKind;
  pub fn is_running(&mut self) -> bool;
  pub fn stop(&mut self);                        // kill + wait, idempotent
  pub fn logs(&self) -> Vec<String>;             // last <=1000 lines of stdout+stderr
}
impl Drop for CoreProcess { /* stop */ }
```
`start`: check installed (Err "core X not installed, run `easyvpn core install X`"), write `config::build` output to `data_dir()/run/<kind>/<config::file_name>`,
spawn with working dir = the core's folder: xray `run -c <cfg>`; sing-box `run -c <cfg> -D <run dir>`; mihomo `-d <run dir> -f <cfg>`.
Env for xray: `XRAY_LOCATION_ASSET=<core dir>`. Pipe stdout/stderr into a shared `Arc<Mutex<VecDeque<String>>>` via reader threads.
On windows set `CREATE_NO_WINDOW` (0x08000000) via `std::os::windows::process::CommandExt`.
After spawn wait ~800 ms; if the child already exited, return Err containing the last log lines.

### download.rs
```rust
pub fn latest_version(kind: CoreKind) -> anyhow::Result<String>;   // GitHub API releases/latest tag_name
pub fn install(kind: CoreKind, progress: &mut dyn FnMut(String)) -> anyhow::Result<PathBuf>; // returns binary path
pub fn pick_asset(kind: CoreKind, os: &str, arch: &str, names: &[String]) -> Option<String>; // pure, unit-tested
```
Repos: XTLS/Xray-core, SagerNet/sing-box, MetaCubeX/mihomo. `os` = std::env::consts::OS, `arch` = std::env::consts::ARCH.
Asset naming examples:
- xray: `Xray-windows-64.zip`, `Xray-windows-arm64-v8a.zip`, `Xray-linux-64.zip`, `Xray-linux-arm64-v8a.zip`, `Xray-macos-64.zip`, `Xray-macos-arm64-v8a.zip` (ignore `.dgst`).
- sing-box: `sing-box-1.12.4-windows-amd64.zip`, `sing-box-1.12.4-windows-arm64.zip`, `sing-box-1.12.4-linux-amd64.tar.gz`, `sing-box-1.12.4-linux-arm64.tar.gz`, `sing-box-1.12.4-darwin-amd64.tar.gz`, `sing-box-1.12.4-darwin-arm64.tar.gz` (ignore `-legacy-`, `-glibc`, `-musl`, `-purego`, `.deb`, `.rpm`, `.pkg.tar.zst`, `.apk`, `android`, `ios`).
- mihomo: `mihomo-windows-amd64-compatible-v1.19.15.zip` (prefer `compatible` on amd64), `mihomo-windows-arm64-v1.19.15.zip`, `mihomo-linux-amd64-compatible-v1.19.15.gz`, `mihomo-linux-arm64-v1.19.15.gz`, `mihomo-darwin-amd64-compatible-v1.19.15.gz`, `mihomo-darwin-arm64-v1.19.15.gz` (ignore `go1xx`, `-v1-`/`-v2-`/`-v3-` amd64 levels, `.deb`, `.rpm`, `.pkg.tar.zst`, `alpha`).
Extraction: from zip / tar.gz pick the entry whose file name is the core exe (xray.exe / sing-box.exe ...; for mihomo zip the single .exe; for mihomo .gz the whole decompressed stream is the binary). For xray also extract `geoip.dat` and `geosite.dat`. Write into `cores_dir()/<name>/` under the canonical exe name; `chmod 755` on unix. Write `version.txt`. Report progress strings ("downloading ... 45%").
Unit tests for `pick_asset` covering every OS/arch listed above.

### CLI (`crates/easyvpn-cli`, bin name `easyvpn`, clap 4 derive, `ctrlc` crate)
Commands: `add <LINK>...` (`-` = read stdin, uses parse_many), `list` (index, id, protocol, name, address:port, `*` for selected),
`remove <ID>`, `select <ID>`, `export <ID>`, `sub add <NAME> <URL>` / `sub update [ID]` / `sub list` / `sub remove <ID>`,
`core install <xray|sing-box|mihomo|all>` / `core list` (installed + version.txt), `settings` (print), `set <KEY> <VALUE>`
(keys: core, listen, port, routing global|bypass-lan|bypass-iran, system-proxy on/off, tun on/off, remote-dns, direct-dns, allow-lan, log-level),
`ping [ID]` (all if omitted, sorted output), `config [ID] [--core X]` (print generated config),
`connect [ID] [--core X]`: refuse if core doesn't support protocol (suggest one that does), start CoreProcess, enable sysproxy if settings say so,
stream new log lines to stdout, on Ctrl+C or core exit: disable sysproxy (if enabled), stop. Store is saved after mutating commands.

### GUI (`crates/easyvpn-gui`, bin `easyvpn-gui`, eframe 0.29, `arboard` for clipboard)
Single window. Top bar: "Paste links" (clipboard → parse_many → add), "Import…" (multiline text window), "Subscriptions…" (window: list, add name+url, update one/all, remove),
"Ping all", "Update subs". Central: profile table (selectable rows: name, protocol, address, ping ms), right-click menu: Copy link, Delete, Select.
Side panel (right): core ComboBox (show " (not installed)" and disable cores not supporting selected protocol), "Install <core>" button when missing,
routing ComboBox, port DragValue, System proxy checkbox, TUN checkbox (only sing-box / mihomo), big Connect/Disconnect button, status text.
Bottom collapsible log panel (core logs, autoscroll). All blocking work (download, subscription, ping) on std threads, results back via `std::sync::mpsc`;
call `ctx.request_repaint()`. Save Store on every change. On window close: stop core and disable sysproxy if it was enabled.
Fonts: add a system fallback font for Persian/Arabic names if found (`C:\Windows\Fonts\tahoma.ttf`, `/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf`, `/System/Library/Fonts/Supplemental/Arial Unicode.ttf`).
Windows release build: `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`.

---

# v2 extension — more connection methods (IMPLEMENT ON TOP OF EXISTING CODE)

Goal: one app for every "bring your own config" method: all V2Ray/Xray configs (incl. xhttp, REALITY),
WireGuard, OpenVPN, SSH tunnels, Hysteria (v1 and v2), TUIC, AnyTLS, plus full raw core configs.
Existing code compiles and its tests pass — keep existing behaviour and public signatures; only extend.

## profile.rs changes
- `Protocol` gains: `Ssh`, `AnyTls` (serde name "anytls"), `Hysteria` (v1), `OpenVpn` (serde "openvpn"), `Custom`.
- `Profile` gains fields (all `#[serde(default)]` via the struct attr):
  - `ssh_private_key: String` (PEM text), `ssh_private_key_passphrase: String`, `ssh_host_key: Vec<String>`, `ssh_client_version: String`.
    SSH uses `username`/`password` too.
  - `raw_config: String` — full .ovpn text for OpenVpn, full core config text for Custom.
  - `custom_core: Option<CoreKind>` — which core runs a Custom profile.
  - Hysteria v1 reuses `password` (auth_str), `obfs` (obfs password string), `up_mbps`, `down_mbps`, `tls`.
  - AnyTLS reuses `password`, `tls`.
- `CoreKind` gains `OpenVpn` (serde "openvpn", name "openvpn"); `ALL` becomes the 4 kinds.
- `CoreKind::supports(p)`:
  - Xray: vmess, vless, trojan, shadowsocks, socks, http, wireguard, custom.
  - SingBox: everything except OpenVpn (ssh, anytls, hysteria, hysteria2, tuic, wireguard, custom included).
  - Mihomo: everything except OpenVpn.
  - OpenVpn: only OpenVpn.
- New `impl Profile { pub fn supported_cores(&self) -> Vec<CoreKind> }`: for Custom → only `custom_core` (if set);
  otherwise every kind in `ALL` whose `supports(protocol)` is true. And
  `pub fn pick_core(&self, preferred: CoreKind) -> Option<CoreKind>`: preferred if in supported_cores, else first supported.
- `CoreKind::is_tunnel(self) -> bool` — true for OpenVpn (full-device tunnel, no local mixed port, no system proxy, needs admin/root).

## link.rs additions (+ round-trip tests)
- `ssh://user:password@host:port?pk=<base64url of PEM private key>&pkp=<passphrase>&hk=<host key>,<host key>#name`
  (password optional; percent-decode user/password).
- `anytls://password@host:port?sni=&insecure=1&fp=&alpn=#name`
- `hysteria://host:port?auth=&peer=<sni>&insecure=1&upmbps=&downmbps=&obfsParam=&alpn=#name` (protocol=udp only)
- `to_link` for OpenVpn/Custom returns Err("not shareable as a link").

## new module import.rs (add `pub mod import;` to lib.rs)
```rust
/// Detect and import any supported config text. `file_name` (if known) is used for naming and detection.
pub fn import_text(text: &str, file_name: Option<&str>) -> Vec<Profile>;
pub fn import_file(path: &std::path::Path) -> anyhow::Result<Vec<Profile>>; // read + import_text, Err if nothing found
```
Detection order:
1. OpenVPN: extension `.ovpn`/`.conf` with a `remote ` line, or text containing lines `client` and `remote `.
   → Protocol OpenVpn, `raw_config` = text, address/port from the first `remote host [port] [proto]` line (port default 1194), name = file stem or "OpenVPN host".
2. WireGuard wg-quick conf: `[Interface]` and `[Peer]` sections. Map PrivateKey, Address (comma list) → local_address, MTU, PublicKey, PresharedKey,
   Endpoint host:port (IPv6 in brackets), optional `Reserved = 1,2,3`. One profile (first peer). Name = file stem or "WireGuard host".
3. JSON object with `outbounds` array: if any outbound has key `protocol` → Custom/Xray; if key `type` → Custom/SingBox. raw_config = text.
   name = file stem or "Custom xray"/"Custom sing-box". address = first proxy outbound's server if easy to find, else "".
4. Clash/mihomo YAML: text containing a top-level line starting with `proxies:` → Custom/Mihomo with raw_config = text.
5. Otherwise `link::parse_many(text)`.
Tests for each case.

## config changes
- singbox.rs: outbounds for `ssh` (`type: ssh, server, server_port, user, password, private_key, private_key_passphrase, host_key, client_version`),
  `anytls` (`password`, `tls`), `hysteria` v1 (`auth_str`, `obfs`, `up_mbps`, `down_mbps`, `tls`). Tests.
- mihomo.rs: `type: ssh` (`username`, `password`, `private-key`, `private-key-passphrase`, `host-key`), `type: anytls` (`password`, `sni`, `skip-cert-verify`, `client-fingerprint`, `alpn`),
  `type: hysteria` (`auth-str`, `obfs`, `up`, `down` as "N Mbps", `sni`, `skip-cert-verify`, `alpn`). Tests.
- xray.rs: must compile with new enum variants (Err for unsupported). 
- mod.rs `build`: if `p.protocol == Custom` → if `p.custom_core == Some(core)` return `p.raw_config` unchanged, else Err.
  If `core == OpenVpn` → protocol must be OpenVpn, return `p.raw_config` (Err if empty). `file_name(OpenVpn)` = "config.ovpn";
  `file_name` for Custom keeps the core's normal name.
  NOTE: for Custom the local proxy port is whatever the user's config says; the app must not assume `mixed_port`.

## core.rs / download.rs changes
- `binary_path(OpenVpn)`: OpenVPN is not downloadable; search, in order: `cores_dir()/openvpn/openvpn(.exe)`, `PATH` (`openvpn`/`openvpn.exe`),
  `C:\Program Files\OpenVPN\bin\openvpn.exe`, `/usr/sbin/openvpn`, `/usr/local/sbin/openvpn`, `/opt/homebrew/sbin/openvpn`, `/opt/homebrew/bin/openvpn`, `/usr/local/bin/openvpn`.
  Return the first existing; if none, return the cores_dir path (so `is_installed` is false).
- `CoreProcess::start` for OpenVpn: write raw config to `run/openvpn/config.ovpn`; if `p.username` non-empty write `auth.txt` (user\npass) and pass
  `--auth-user-pass <auth.txt>`; args `--config <cfg> --auth-nocache --verb 3`; working dir = run dir. Same log capture. Delete auth.txt on stop.
- `download::install(OpenVpn)`: Err with an install hint per OS: Windows `winget install OpenVPNTechnologies.OpenVPN`,
  Debian/Ubuntu `sudo apt install openvpn`, Fedora `sudo dnf install openvpn`, macOS `brew install openvpn`. `latest_version(OpenVpn)` → Err too.
  `pick_asset` for OpenVpn → None.
- ping.rs: UDP-only protocols now include Hysteria; OpenVpn tcp-pings its remote only if raw_config's remote line says tcp (proto tcp / tcp-client), else Err("udp");
  Custom → Err("custom config").

## CLI changes
- New `import <FILE>...` (`-` = stdin) using `import::import_file` / `import_text`.
- `add` keeps using link parsing but should fall back to `import_text` when nothing parsed.
- Everywhere a core is chosen use `Profile::pick_core(settings.core)` when `--core` not given; with `--core` validate via `supported_cores()`.
- `connect` with a tunnel core (OpenVpn) or a Custom profile: do not enable system proxy (print why), print "requires administrator/root" hint for OpenVpn and TUN.
- `core install openvpn` prints the hint error; `core list` shows OpenVPN as installed/not with its found path.
- Core name parsing accepts `openvpn`.
- `list` shows the core that will be used.

## GUI changes (add `rfd = "0.15"` dependency)
- "Import file…" button (rfd file dialog, filters: all supported `ovpn conf json yaml yml txt`) → `import::import_file`.
- Drag & drop of files onto the window → same import.
- The "Import…" text window uses `import::import_text`.
- Core ComboBox lists only `profile.supported_cores()`; auto-switch to `pick_core` when the selected profile changes.
- For OpenVpn: hide port/system proxy/TUN controls, show "Full-device tunnel — run as Administrator/root". If OpenVPN not installed show the install hint text instead of an Install button.
- For Custom: hide port/system-proxy/routing (config is used as-is), show note.
- Protocol column shows new protocol names.

---

# v3 — compact home screen (reference: docs/design/home-reference.png)

The GUI becomes a small portrait window that looks EXACTLY like the reference image, with the
violet/purple palette replaced by blue. Simple and minimal: everything advanced moves to Settings.

## Palette (blue)
- window background: vertical gradient #0A0F1C (top) → #070B14 (bottom), with a faint blue radial glow behind the power button
- card fill #111827 at ~85% opacity, 1px border #1F2A40, corner radius 18
- round glass icon buttons (top bar): fill #1A2236, border #2A3550, 44px diameter
- accent: #3B82F6 → #1D4ED8 gradient (power button fill), glow rings #3B82F6 at 6–18% alpha
- accent text / chevron: #60A5FA; connected accent: #22D3EE (cyan) mixed with blue
- primary text #F3F6FC, secondary #8A94A8, divider #1F2A40
- download icon green #34D399, upload icon blue #60A5FA

## Home screen layout (top → bottom, window 420×760, min size 380×680, centered content, 20px side padding)
1. Top bar: round "+" button (left), title "● EasyVpn" (dot gray when disconnected, green when connected, "Vpn" part in accent blue) centered, round "≡" button (right).
2. Big bold status: "DISCONNECTED" / "CONNECTING…" / "CONNECTED"; subtitle muted: "Tap to connect" / "Establishing secure tunnel" / "Your connection is protected".
3. Power button ~170px: blue gradient disc, two thin faint concentric rings around it (at ~+22px and ~+44px radius), soft outer glow (draw many translucent circles); white power icon (circle arc open at top + vertical line, stroke ~6px) and label "START" (disconnected), "CANCEL" (connecting, with a spinning bright arc on the outer ring), "STOP" (connected, cyan-blue glow and slowly pulsing rings — request_repaint while animating). Click toggles connect/disconnect. Hover: slightly brighter.
4. "Current config" card: left a 44px rounded tile with a server-stack icon (draw it: three rounded rectangles with small dots), right of it the muted label "Current config", below in bold the profile name (single line, truncated with "…"), below that muted small "<PROTOCOL> · <address>"; a blue chevron ">" on the right. Clicking the card opens the Servers page. No profile: name "No config — tap + to add".
5. Stats card with 4 rows separated by thin dividers: clock icon "Session Time" → "HH:MM:SS"; green down-arrow "Download" → speed; blue up-arrow "Upload" → speed; pin icon "Location" → "Disconnected" / "Checking…" / "<Country> · <IP>". Speeds formatted "0 KB/s", "320 KB/s", "2.4 MB/s".
Draw all icons with the egui Painter (no image files, no emoji — egui has no color emoji font).
Gradients: use `egui::Mesh` with per-vertex colors (e.g. a disc as a triangle fan, colors interpolated top→bottom).

## Other pages (same theme, simple, each with a top bar: round "‹" back button + centered title)
Navigation is a page enum inside the window (no egui::Window popups anymore).
- "+" opens a small dropdown menu (styled card) with: Paste from clipboard, Import file…, Import text…, Add subscription…  
  ("Import text" and "Add subscription" are pages with a text field and a primary button.)
- "≡" opens a dropdown menu: Servers, Subscriptions, Settings, Logs, About.
- Servers page: search field, "Ping all" button, list of rows (name, protocol · address, ping pill right, selected row highlighted with blue left bar); click = select and go back Home; right-click menu Copy link / Delete. Drag & drop of files works on any page.
- Subscriptions page: list with update/delete per item, "Update all", add form.
- Settings page (all advanced options live here): Core (only the selected profile's supported cores, install button / OpenVPN install hint), Routing, Local port, Allow LAN, System proxy, TUN mode (sing-box/mihomo only, note "requires administrator"), Remote DNS, Direct DNS, Log level, Cores section (installed version per core + Install/Update).
- Logs page: monospace log list, auto-scroll, Copy and Clear buttons.
- About page: app name, version (env!("CARGO_PKG_VERSION")), data folder path.
Keep all existing behaviour (store saving, threads + mpsc, sysproxy disable on exit, core stop on exit, OpenVPN/Custom special cases, font fallback for Persian names).
Split the GUI into modules: main.rs (setup), app.rs (state + messages), theme.rs (colors + painter helpers + icons), pages/{home,servers,subscriptions,settings,logs,about,import}.rs.

## Core crate: traffic + IP (new module traffic.rs, add `pub mod traffic;`)
```rust
/// 127.0.0.1 port of the core's stats endpoint = settings.mixed_port + 2.
pub fn stats_port(s: &Settings) -> u16;
/// Cumulative bytes (upload, download) through the proxy since the core started.
/// Xray: GET http://127.0.0.1:<stats_port>/debug/vars → json["stats"]["outbound"]["proxy"]["uplink"/"downlink"].
/// sing-box and mihomo: GET http://127.0.0.1:<stats_port>/connections → "uploadTotal"/"downloadTotal".
/// OpenVpn / Custom profiles: Err (unsupported). 1s timeout.
pub fn totals(kind: CoreKind, s: &Settings) -> anyhow::Result<(u64, u64)>;
pub struct IpInfo { pub ip: String, pub country: String, pub country_code: String }
/// Public IP seen through the local proxy (http proxy: xray → mixed_port+1, others → mixed_port);
/// `None` = direct (OpenVPN tunnel). GET https://ipwho.is/ (fields ip, country, country_code), 8s timeout.
pub fn public_ip(proxy: Option<&str>) -> anyhow::Result<IpInfo>;
/// "http://127.0.0.1:<port>" for the core's local http proxy, None for tunnel cores / Custom.
pub fn local_http_proxy(kind: CoreKind, p: &Profile, s: &Settings) -> Option<String>;
```
Config generators must expose the stats endpoint on 127.0.0.1:stats_port (never on 0.0.0.0, even with allow_lan):
- xray: `"stats": {}`, `"policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}}`,
  `"metrics": {"tag": "metrics", "listen": "127.0.0.1:<stats_port>"}` (xray ≥ 1.8 serves /debug/vars there).
- sing-box: `"experimental": {"clash_api": {"external_controller": "127.0.0.1:<stats_port>"}}`.
- mihomo: `"external-controller": "127.0.0.1:<stats_port>"`.
Unit tests: generated configs contain the endpoint; JSON parsing of sample /debug/vars and /connections bodies (factor the parsers into pure functions).

---

# v4 — all other pages in the home screen's style

The home screen (docs/design/home-current.png, home-connected.png) is the approved look. Every other page
must feel like the same app: same window, background, cards (#111827, border #1F2A40, radius 18),
44px round glass icon buttons, Inter 400/600/700, blue accent gradient, muted secondary text,
icons drawn with the Painter, generous 20px padding, no default-looking egui widgets.

## Shared widgets (theme.rs — build these once, use everywhere)
- `top_bar(ui, title, left: back button, right: optional icon button)` — round "‹" back button left, bold centered title, optional round icon button right.
- primary button: full-width 48px pill, blue gradient fill, bold white text, hover brighter.
- secondary button: pill with #1A2236 fill + border; danger variant with red text.
- toggle switch: 44×24 pill, off #2A3550, on blue gradient, white knob, animated (ctx.animate_bool).
- chip / segmented control: small pills, selected = blue fill, others glass.
- latency pill: <150 ms green #34D399, <300 ms amber #FBBF24, else / timeout red #F87171, untested gray "—".
- text input: rounded 14px, fill #0D1424, border #1F2A40, focus border blue, placeholder muted.
- settings row: label (+ optional muted subtitle) left, control right, thin dividers between rows inside a card.
- section label: small uppercase muted letter-spaced text above a card ("CONNECTION").
- dropdown menu card (for "+" and "≡"): floating card under its button, rows = icon + label, hover highlight, closes on click outside.
- toast: floating pill at the bottom (success green dot / error red dot / info blue), auto-hides after 3 s. Replace plain status texts with toasts.
- window controls: top-right corner of the window, ABOVE the top bar: minimize "–" and close "×" as 30px round buttons, clearly visible (#8A94A8 icon), close turns red (#EF4444 fill, white ×) on hover. Close = normal shutdown (stop core, disable system proxy).

## Pages
- "+" menu: Paste from clipboard, Import file…, Import text…, Add subscription… (icons: clipboard, file, text lines, link).
- "≡" menu: Servers, Subscriptions, Settings, Logs, About (icons: server stack, link/rss, gear, terminal, info).
- Servers: top bar "Servers" + right lightning button "Ping all" (spinner while pinging). Search input. Chips row: All, Manual, one chip per subscription. List of 64px card rows:
  left 40px round tile with protocol initials (VL, VM, TR, SS, HY, TU, WG, OV, SH, AT, CU) tinted per protocol; name bold (truncate), muted "PROTOCOL · address:port";
  right latency pill and a "⋯" button (menu: Copy link, Delete). Selected row: blue border + small check. Click row = select + go Home. Empty state with icon + "No servers yet" + primary "Add config".
- Import text: top bar "Import", large rounded text area (paste links / config text), muted hint of supported formats, primary "Import" → toast "N configs imported".
- Add subscription: top bar "Add subscription", inputs Name + URL, primary "Add & update".
- Subscriptions: top bar "Subscriptions" + right refresh button "Update all". Card per subscription: name bold, URL muted monospace truncated, "N servers · updated 2h ago" (relative time), round icon buttons update (spinner while updating) and delete (confirm by second click: icon turns red "Delete?"). Bottom primary "+ Add subscription". Empty state.
- Settings: sections CONNECTION (Core selector as segmented chips for supported cores, Routing segmented Global / Bypass LAN / Bypass Iran, System proxy toggle, TUN toggle with subtitle "Requires administrator" — disabled when the core can't do TUN, Local port input), CORES (row per core: status dot green/gray, name, version or "Not installed", small pill button Install / Update with progress text; OpenVPN shows install hint text instead), DNS (Remote DNS, Direct DNS inputs), ADVANCED (Allow LAN toggle, Log level segmented). Changes save immediately; note "Applies on next connect" muted under CONNECTION.
- Logs: top bar "Logs" + right buttons copy and clear. Chips All / Info / Warn / Error (filter by text). Dark rounded panel (#070B14) with monospace lines, level word colored (info blue, warn amber, error red), auto-scroll toggle row at the bottom.
- About: centered app logo (gradient blue circle with white power icon), "EasyVpn" bold, version, muted line "Xray · sing-box · mihomo · OpenVPN", card rows: Data folder (path + "Open" button using the OS file manager: explorer / open / xdg-open), Cores folder, Licenses note.
Drag & drop import and every existing behaviour must keep working.

---

# v5 — fixes from the user's first real test

## 1. Text rendering (server names from real subscriptions)
Real names look like `🇺🇸𝗨𝗦𝗔🇮🇷AI🤖`, `🇩🇪🇮🇷هر موقع قطع شد‼بروزرسانی کن`, `abbas4846👤(∞🔋)(∞📆)(✅)`. Today they render as boxes.
- Fonts (crates/easyvpn-gui/assets/fonts): Inter-400/600/700 (Latin), **Vazirmatn-400/700** (Persian/Arabic). Every family's fallback chain:
  Inter → Vazirmatn → egui's default fonts (keep `egui::FontDefinitions::default()` entries such as NotoEmoji-Regular and emoji-icon-font as LAST fallbacks so monochrome emoji like 🔋 ✅ 🎮 🤖 render).
- New `text.rs` in the GUI: `pub fn display_name(raw: &str) -> DisplayName { text: String, flags: Vec<String> /* lowercase ISO codes, in order */ }`:
  1. Extract flag emoji (pairs of Regional Indicator Symbols U+1F1E6..U+1F1FF) → ISO codes, and remove them from the text.
  2. NFKC-normalize (crate `unicode-normalization`) so 𝗚𝗲𝗿𝗺𝗮𝗻𝘆 → Germany.
  3. Persian/Arabic: egui has no shaping/bidi, so shape and reorder before display: crate `ar_reshaper` (reshape to presentation forms) then `unicode-bidi` (BidiInfo, visual reorder per line). Mixed Latin + Persian must read correctly.
  4. Collapse repeated spaces and trim.
  Unit tests for each sample above.
- Use display_name everywhere a profile/subscription name is drawn (home card, servers list, toasts).
- Country for a profile = first flag in its name that is NOT "ir" (many Iranian panels add 🇮🇷 as decoration); if only "ir" exists use it; none → None.

## 2. Flags
- Assets: crates/easyvpn-gui/assets/flags/<iso>.png (40px wide, 252 files, public domain).
- `build.rs` in easyvpn-gui scans assets/flags and generates `$OUT_DIR/flags.rs` with `pub fn flag_png(code: &str) -> Option<&'static [u8]>` (match over include_bytes!). Rerun-if-changed on the folder.
- Decode with the `image` crate (default-features = false, features = ["png"]) into `egui::ColorImage`, cache textures in a HashMap<String, TextureHandle>.
- Draw: home "Current config" tile shows the country flag (rounded 4px, ~28×20, centered in the 44px tile) instead of the server icon when a country is known; servers list rows show the flag left of the name (protocol initials tile stays); Location row shows the flag of `IpInfo.country_code` before "US · 1.2.3.4".

## 3. Dropdown freeze (critical)
Opening the right-side "≡" dropdown freezes the UI thread ("Not Responding"); the left-side "+" one works. The freeze appeared when the dropdown switched to `Area::pivot(Align2::RIGHT_TOP)` + `.constrain_to(bounds)` with content width derived from `ui.available_width()`.
Rewrite `theme::dropdown` without pivot/constrain_to: fixed MENU_WIDTH = 226 (incl. 8px margins); compute the top-left position manually:
x = anchor.right - MENU_WIDTH for right-side anchors, anchor.left for left-side; clamp x into [12, screen.right - 12 - MENU_WIDTH]; y = anchor.bottom + 6.
`menu_row` uses a fixed width (MENU_WIDTH - 16), never `available_width()`. `Area::fixed_pos(pos)` only.

## 4. Connection mode (core crate + CLI + GUI)
- profile.rs: `pub enum ProxyMode { #[default] Local, System, Tun }` (serde lowercase). `Settings.mode: ProxyMode`.
  Backward compat: keep the old `system_proxy` / `tun` fields readable; after `Store::load`, if the stored JSON had no `mode`, derive it (tun → Tun, else system_proxy → System, else Local). Write only `mode` from now on (old fields may stay but are ignored).
- Local = only the local mixed port (apps opt in). System = local port + OS system proxy. Tun = whole system through a TUN device (needs admin/root).
- TUN with xray (xray has no TUN): run xray as usual AND a sing-box helper process (`CoreProcess` for the helper) with config from new `config::singbox::tun_helper(s: &Settings, socks_port: u16) -> serde_json::Value`:
  tun inbound (auto_route, strict_route, stack "mixed", address 172.19.0.1/30 + fdfe:dcba:9876::1/126), outbound `socks` to 127.0.0.1:socks_port (tag proxy), `direct`,
  route rules: action sniff; protocol dns → hijack-dns; `process_name: ["xray.exe","xray"]` → direct (avoid loops); ip_is_private → direct; final proxy; auto_detect_interface true; dns server via the socks outbound (type https 1.1.1.1, detour proxy) + local for direct.
  Requires sing-box installed (else clear error "TUN mode needs the sing-box core — install it in Settings").
  sing-box / mihomo profiles use their native tun (existing code) driven by `mode == Tun`.
- Elevation check: `pub fn is_elevated() -> bool` in core (Windows: `IsUserAnAdmin` from shell32 via extern "system"; Unix: `id -u` == 0). Starting Tun without elevation → error "TUN mode needs Administrator/root". GUI shows a toast with a "Restart as admin" action (Windows: ShellExecuteW "runas" on current exe, then exit; other OS: just the message).
- GUI: Settings → first card "CONNECTION MODE" with a 3-segment control (Local proxy / System proxy / TUN) + one muted line explaining each; home subtitle when disconnected: "Tap to connect · <mode name>"; remove the old System proxy / TUN toggles.
- CLI: `set mode local|system|tun`; keep `set system-proxy` / `set tun` as aliases that set mode; `settings` prints mode.

## 5. Orphaned cores (port already in use after a crash)
After a GUI crash, xray kept running and held the ports, so the next connect failed with "bind: Only one usage of each socket address".
- core.rs: write `run/<kind>/pid` after spawn; before starting a core, if that pid file exists and the process is still alive AND its exe path is inside cores_dir(), kill it (Windows: `taskkill /F /PID`, Unix: `kill -9`); remove the file on stop.
- Windows: put every spawned core into a Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE (extern "system" kernel32: CreateJobObjectW, SetInformationJobObject with JOBOBJECT_EXTENDED_LIMIT_INFORMATION, AssignProcessToJobObject; keep the job HANDLE alive in CoreProcess) so cores die with the app even on crash.
- Before start, check the mixed port and stats port are free (TcpListener::bind); if not, return a clear error "Port 10808 is in use by another program — change Local port in Settings".

---

# v6 — "Connected" only after a real test

User requirement: never show CONNECTED unless traffic really flows; the connected button is GREEN.

## Core: `traffic::probe`
```rust
/// Real connectivity test. Returns round-trip time of GET https://www.gstatic.com/generate_204 (expects HTTP 204).
/// via = Some(proxy url) → through the local http proxy; None → direct (used for TUN / OpenVPN, the OS routes it).
pub fn probe(via: Option<&str>, timeout: std::time::Duration) -> anyhow::Result<std::time::Duration>;
```
Use a fresh ureq agent each call (no connection reuse), timeout applies to the whole request.

## GUI connection state machine (app.rs / home.rs)
`enum ConnState { Disconnected, Connecting { since }, Verifying { attempt }, Connected { rtt_ms }, Degraded { since }, Failed }`
1. START → Connecting: start core(s) on a background thread (never block the UI thread).
2. → Verifying: probe on a background thread, up to 4 attempts over ~15 s (2 s, 3 s, 4 s, 5 s timeouts).
   - Local / System mode: probe through `traffic::local_http_proxy` (xray: mixed_port+1, others: mixed_port).
   - Tun mode and OpenVPN: probe BOTH through the local proxy (if any) AND direct (None); Connected only when the direct probe succeeds (that proves the TUN routes traffic). If only the proxy probe succeeds, the error says "Server works but TUN is not routing traffic — see Logs".
   - Custom profiles (unknown port): direct probe if Tun, else through mixed_port; if impossible, mark Connected with "(unverified)".
3. All attempts failed → stop the core(s), disable system proxy if we enabled it, state Failed: status "Connection failed", toast with the last error and "See Logs". Button back to START.
4. Success → Connected { rtt_ms }: title "CONNECTED", subtitle "Verified · <rtt> ms", fetch public IP for the Location row.
5. While Connected: health probe every 30 s in the background; 2 consecutive failures → Degraded (amber): title "NO TRAFFIC", subtitle "Server not responding — retrying"; a later success returns to Connected. If any core process exits → disconnect with toast "Core stopped — see Logs".
6. STOP at any time cancels the pending probes (shared AtomicBool) and stops cores.

## Visuals
- Connecting / Verifying: button stays blue with the spinning arc, title "CONNECTING…" then "TESTING CONNECTION…", label "CANCEL".
- Connected: button gradient GREEN #22C55E → #16A34A, green glow rings (#22C55E at low alpha), label "STOP", status dot in the top bar green.
- Degraded: amber #F59E0B ring/glow, label "STOP".
- Failed: brief red ring flash (1 s) then normal START.

---

# v7 — resizable, responsive, mini mode

User: "I can resize the window with the mouse; at every size the most important parts show, the minimal look is kept and nothing breaks; plus a mini mode (very small window)."

## Resizing (frameless window)
- 6 px invisible hit zones on all edges + 12 px corners: hover sets the matching resize cursor, primary press sends `ViewportCommand::BeginResize(ResizeDirection::…)`. Resize zones win over drag zones.
- Viewport min size 300×190 (below the compact breakpoint the layout switches to mini automatically), no max.
- Remember window size, position and mini mode in `data_dir()/gui.json` (separate from store.json); restore on start (clamp to a visible monitor area if possible, else default 420×760 centered).

## Responsive home screen (pure function `layout_for(size: Vec2) -> Layout` with unit tests)
Content is a centered column: width = min(window_width − 2×pad, 460); pad = 20 (16 when width < 360). Large windows never stretch cards; extra space stays background.
Breakpoints by available height h (and width w):
- **Full** (h ≥ 660): exactly today's layout.
- **Medium** (520 ≤ h < 660): status title 22px, power button diameter scales, stats card has 3 rows: Session time, "Traffic ↓ 2.4 MB/s ↑ 320 KB/s" (one row), Location.
- **Compact** (360 ≤ h < 520): status title + subtitle, power button ~120 px, config card; stats collapse into ONE muted line under the card: "00:12:47 · ↓ 2.4 MB/s ↑ 320 KB/s · US".
- **Mini** (h < 360, or mini mode on): a single horizontal bar (see below).
Power button diameter = clamp(min(w, h) × 0.40, 96, 190) in Full/Medium; vertical spacing scales with h so nothing overlaps; if content still doesn't fit, the column scrolls vertically (never overlaps or clips mid-widget). Every text that can be long (profile names, addresses, location) is single-line truncated with "…" to its available width (show full text on hover).

## Mini mode
- Window controls (top-right) get a third button "⤢/⤡" (mini ↔ full) left of minimize. Double-click on the mini bar also restores.
- Entering mini: remember the full size, resize viewport to 340×96, set `WindowLevel::AlwaysOnTop`; leaving restores the size and normal level.
- Mini bar layout (left → right, vertically centered, 12 px padding, rounded 18 card with border, draggable background): flag (or server icon) 22 px; two lines: profile name (bold 13, truncated) and status line (muted 11: "Connected · 84 ms · ↓ 2.4 MB/s" / "Not connected" / "Connecting…" — colored dot green/amber/gray); small round power button 44 px (same green/blue/amber states, click = connect/disconnect); tiny expand button; close × is not shown in mini (use expand first) — but Escape or the expand button restores.
- In mini mode other pages are not reachable; opening any page first restores full mode.

## Other pages at small sizes
- Top bar always visible; page bodies inside vertical ScrollArea; rows and cards use full column width; segmented controls wrap to the next line instead of overflowing; the dropdown menus clamp inside the window and get a max height with scrolling.
- Toasts: max width = column width, wrap text.


---

# v8 — split tunneling, bypass sources, manual configs, always-visible status

## 1. Split tunneling (custom rules) — core crate
profile.rs:
```rust
pub enum RuleKind { Domain /*exact*/, DomainSuffix, DomainKeyword, IpCidr, Process /*exe name, e.g. telegram.exe*/ }
pub enum RuleAction { Proxy, Direct, Block }
pub struct Rule { pub id: String, pub kind: RuleKind, pub value: String, pub action: RuleAction, pub enabled: bool }
pub enum DefaultRoute { Proxy /*everything via VPN except rules*/, Direct /*only rules marked Proxy use the VPN*/ }
Settings += { rules: Vec<Rule>, default_route: DefaultRoute /*default Proxy*/, bypass: BypassSettings }
```
(serde lowercase / kebab-case, #[serde(default)], old stores load fine.)
Rule order: user rules (top to bottom) → bypass sources (Direct) → private/LAN Direct → default_route.
Generators:
- xray: routing.rules with domain ("full:", "domain:", "keyword:" prefixes) / ip lists → outboundTag proxy/direct/block (add a `blackhole` outbound tagged block). Process rules are not supported by xray itself: they are applied by the TUN helper (sing-box) when mode == Tun, ignored otherwise.
- sing-box (native and the TUN helper): route rules with domain / domain_suffix / domain_keyword / ip_cidr / process_name → outbound, or `action: reject` for Block. In the TUN helper, Direct → direct outbound, Proxy → socks outbound (to xray), Block → reject; default_route Direct makes `final: direct`.
- mihomo: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR,…,no-resolve / PROCESS-NAME rules → proxy / DIRECT / REJECT; final MATCH per default_route.
Process rules only take effect in TUN mode (they need to see every app's traffic); in Local/System mode apps choose themselves — the GUI shows this note.

## 2. Bypass sources (replace hard-coded "Bypass Iran") — new core module rules.rs
```rust
pub enum SourceFormat { Domains /*plain, one per line; also v2fly prefixes domain:/full:/keyword:; dnsmasq server=/d/ip; '#' comments; skip regexp:*/, Cidrs /*one CIDR per line*/ }
pub struct BypassSource { pub id: String, pub name: String, pub url: String, pub format: SourceFormat, pub enabled: bool, pub builtin: bool, pub updated_at: u64, pub entries: usize }
pub struct BypassSettings { pub enabled: bool, pub country: String /*ISO lowercase, empty = auto*/, pub sources: Vec<BypassSource>, pub tld_suffix: bool /*also bypass .<cc> domains*/ }
pub struct RuleEntries { pub suffixes: Vec<String>, pub full: Vec<String>, pub keywords: Vec<String>, pub cidrs: Vec<String> }
pub fn detect_country() -> anyhow::Result<String>;            // DIRECT (no proxy) GET https://ipwho.is/ → country_code lowercase, 8 s timeout
pub fn recommended_sources(country: &str) -> Vec<BypassSource>; // catalog below
pub fn update_source(src: &mut BypassSource) -> anyhow::Result<usize>; // download (direct, 60 s), parse, normalize, dedupe, save data_dir()/rules/<id>.txt, set updated_at/entries, return count
pub fn load_entries(src: &BypassSource) -> anyhow::Result<RuleEntries>;
pub fn parse(text: &str, format: SourceFormat) -> RuleEntries;  // pure, unit tested
pub fn bypass_entries(b: &BypassSettings) -> RuleEntries;       // merged entries of all enabled, downloaded sources (+ tld suffix)
```
Catalog (all URLs verified live):
- every country: "IP ranges (<CC>)" Cidrs `https://www.ipdeny.com/ipblocks/data/aggregated/<cc>-aggregated.zone` (enabled)
- ir: "Iran domains (Chocolate4U)" Domains `https://raw.githubusercontent.com/Chocolate4U/Iran-v2ray-rules/release/ir.txt` (enabled);
      "Iran hosted domains (bootmortis, large)" Domains `https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt` (disabled by default)
- cn: "China domains (felixonmars)" Domains `https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf` (enabled)
- other countries: only the IP ranges + tld_suffix.
Users can add their own sources (name, URL, format) and edit/disable/delete any source.
RoutingMode keeps Global / BypassLan / BypassIran for compatibility; generators treat `BypassIran` as "bypass my country" using `bypass_entries`. If nothing is downloaded yet and country is ir, fall back to the old built-in behaviour (domain suffix .ir + geoip IR).
Large lists: xray inline (domain:/full:/keyword: lists and ip list); sing-box: write `run/<core>/rules-bypass.json` local rule-set (`{"version":3,"rules":[{"domain_suffix":[…],"domain":[…],"domain_keyword":[…],"ip_cidr":[…]}]}`) and reference it with `route.rule_set: [{type: local, tag: bypass, format: source, path}]`; mihomo: a `rule-providers` entry `type: file, behavior: classical, format: text, path` with lines like `DOMAIN-SUFFIX,x` / `IP-CIDR,y,no-resolve`, used via `RULE-SET,bypass,DIRECT`. Config builders receive RuleEntries as a parameter (pure, testable); CoreProcess writes the side files next to the config.
First run / when country is empty and bypass enabled: detect country, set sources = recommended_sources(country), download them in the background (GUI).

## 3. Manual config entry / edit — GUI
New page "Add config" (from the "+" menu "Add manually…", and the Servers row menu "Edit"):
- Protocol picker: VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, Hysteria2, Hysteria, TUIC, WireGuard, SSH, AnyTLS.
- Only the relevant fields per protocol: name, address, port, uuid/password/username, method, flow, alter id; SSH: user, password, private key (multiline) + passphrase, host key; WireGuard: private key, peer public key, preshared key, local addresses, MTU, reserved; Hysteria/Hysteria2: obfs, obfs password, up/down Mbps; TUIC: congestion control.
- Collapsible "Transport" (network + path/host/serviceName/mode/extra) and "TLS" (none/tls/reality + sni, alpn, fingerprint, allow insecure, reality pbk/sid/spx), only for protocols that use them.
- Validation before save (address non-empty, port 1–65535, required credentials per protocol, valid UUID for vless/vmess/tuic, valid JSON for xhttp extra) with inline red hints. Save adds or replaces in the store and selects it.
Contract: `pages::profile_editor::EditorState` (Default + `fn new(existing: Option<&Profile>) -> Self` + `fn validate(&self) -> Result<Profile, Vec<(String /*field*/, String /*message*/)>>` pure and unit tested) and `pages::profile_editor::show(app: &mut App, ui: &mut egui::Ui, ctx: &egui::Context)`; App has `pub editor: Option<EditorState>` and `Page::Editor`.

## 4. Routing pages — GUI
Settings → card "ROUTING": Default route (segmented "Everything via VPN" / "Only selected via VPN"), row "Rules (N)" → Rules page, row "Bypass sources" → Sources page.
- Rules page: list (kind chip, value, action pill Proxy/Direct/Block colored blue/gray/red, enable toggle, delete), add form (kind select, value input with placeholder per kind e.g. "telegram.exe", "google.com", "10.0.0.0/8", action select). Muted note: "App rules work in TUN mode".
- Sources page: toggle "Bypass my country", detected country with flag + "Detect again", toggle ".<cc> domains", list of sources (name, entries count, updated relative time, enable toggle, update button with spinner, delete for non-builtin), "Update all", add custom source form (name, URL, format Domains / IP ranges), "Reset to recommended".

## 5. Always-visible status — GUI home + mini
- Every breakpoint (Full, Medium, Compact, Mini) shows: current config (flag + name), connection state, live ↓/↑ speed, current public IP + country flag. Compact: one row "[flag] 162.217.x.x · ↓ 2.4 MB/s ↑ 320 KB/s"; Mini second line: "Connected · ↓ 2.4 MB/s ↑ 320 KB/s · US".
- The power button never gets small: Full 190, Medium 168, Compact 148 (minimum 140 outside mini); shrink spacing/cards instead; if still too tight the column scrolls.
- Real-time health: probe every 5 s while connected (GET generate_204 through the active path, 3 s timeout); 2 consecutive failures → "CONNECTION LOST" (red #EF4444 ring + title + toast), auto-recover to Connected when probes succeed again (re-fetch public IP); core exit → disconnect + toast. Full layout also shows a muted "Session ↓ 1.2 GB ↑ 80 MB".


---

# v9 — Android app

Same Rust UI and core as desktop. Android-only pieces: a tiny Java shim (NativeActivity subclass + VpnService — Android requires Java classes for these), a Rust cdylib, and an APK build script that needs NO Gradle (only SDK build-tools + JDK 17 + cargo-ndk).

Environment (Windows dev box): Android SDK `E:\2-Sources\AndroidSdk` (build-tools 36.1.0, platforms android-35/36, NDK 28.2.13676358, platform-tools, emulator, system image android-36 google_apis_playstore x86_64), JDK 17 at `C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot`, cargo-ndk 4.1.2, Rust targets aarch64-linux-android + x86_64-linux-android.
Core binaries are already downloaded: `android/cores/<abi>/libxray.so`, `libsingbox.so`, `libmihomo.so` (abi = arm64-v8a, x86_64; they are executables named lib*.so so Android installs them into nativeLibraryDir) and `android/cores/assets/geoip.dat`, `geosite.dat`.

## Architecture
```
MainActivity (Java, extends android.app.NativeActivity) ── loads libeasyvpn.so → android_main (Rust, eframe/egui UI = the desktop App)
      │ startVpn(socksPort, allowedApps, disallowedApps) / stopVpn()       ▲ Native.onVpnState(state, msg)
      ▼                                                                       │
EasyVpnService (Java, extends VpnService) ── Builder.establish() → fd ── Native.startTun(fd, socksPort, mtu) (Rust: tun2proxy)
Rust UI starts the proxy core (xray / sing-box / mihomo executable from nativeLibraryDir) exactly like desktop "Local proxy" mode;
tun2proxy forwards every TUN packet to socks5://127.0.0.1:<mixed_port>. Our own package is always excluded from the VPN, so the cores' upstream traffic never loops.
```

## A. Core crate (easyvpn-core) — Android support (cfg(target_os = "android"))
- `core::binary_path(kind)`: on Android, if env `EASYVPN_CORE_DIR` is set → `<dir>/libxray.so` | `libsingbox.so` | `libmihomo.so` (OpenVpn → unsupported path that does not exist). Desktop unchanged.
- xray asset dir: env `EASYVPN_ASSET_DIR` if set (else the core dir as today) → `XRAY_LOCATION_ASSET`.
- `download::install` / `latest_version` on Android → Err("cores are bundled with the Android app").
- `sysproxy::enable/disable` on Android → Err("not supported on Android"); `core::is_elevated()` → true on Android.
- `Connection::start` on Android: never starts the sing-box TUN helper (the VPN is done by the platform); mode Tun behaves like Local for the core process.
- Process/job handling: Job Object stays Windows-only; pid-file stale kill uses `kill -9` on unix incl. Android (verify exe path is inside EASYVPN_CORE_DIR or cores_dir()).
- Everything must still compile and pass tests on Windows.

## B. GUI crate becomes a library + desktop binary
- `crates/easyvpn-gui/src/lib.rs` declares all modules (app, theme, text, flags, window, pages, platform) and exposes:
```rust
pub mod platform;
pub use platform::{Platform, VpnStatus};
/// Entry used by both desktop main.rs and the Android crate.
pub fn run_app(options: eframe::NativeOptions, platform: Box<dyn Platform>) -> eframe::Result<()>;
```
  `main.rs` = desktop only: builds NativeOptions exactly as today and calls `easyvpn_gui::run_app(options, Box::new(platform::DesktopPlatform::default()))`.
- `platform.rs`:
```rust
#[derive(Clone, Debug, PartialEq)]
pub enum VpnStatus { Idle, Starting, Running, PermissionDenied, Failed(String) }
pub trait Platform: Send + Sync {
    fn is_mobile(&self) -> bool;
    fn clipboard_get(&self) -> Option<String>;
    fn clipboard_set(&self, text: &str);
    fn pick_import_file(&self) -> Option<std::path::PathBuf>;   // desktop: rfd; mobile: None (UI shows Import text instead)
    fn open_folder(&self, path: &std::path::Path);
    /// Mobile only: request VPN permission if needed and start the VpnService forwarding to 127.0.0.1:socks_port.
    /// allowed / disallowed = Android package names from Process rules (see below). Returns immediately.
    fn start_vpn(&self, socks_port: u16, allowed: &[String], disallowed: &[String]) -> anyhow::Result<()>;
    fn stop_vpn(&self);
    fn vpn_status(&self) -> VpnStatus;
    /// Logical points to keep clear at the top (status bar) and bottom (navigation bar).
    fn safe_area(&self) -> (f32, f32) { (0.0, 0.0) }
}
pub struct DesktopPlatform;  // arboard, rfd, explorer/open/xdg-open; start_vpn → Err (desktop uses its own modes)
```
  `rfd` and `arboard` become `[target.'cfg(not(target_os = "android"))'.dependencies]`, and every use goes through Platform.
- `App::new(cc, platform: Box<dyn Platform>)` stores it. When `platform.is_mobile()`:
  - no frameless window controls, no resize zones, no mini mode, no gui.json window state; honour `safe_area` padding;
  - layout = Full/Medium/Compact by available height as on desktop (phones are tall); touch targets ≥ 44 pt; scrolling by drag works (egui default);
  - Settings → CONNECTION MODE shows two options: "VPN (whole device)" (default, ProxyMode::Tun) and "Proxy only" (ProxyMode::Local) — System proxy hidden; Cores card shows bundled versions (no Install/Update buttons);
  - Rules page: kind "App" placeholder becomes "org.telegram.messenger" (Android package name) and the note says "App rules use Android package names";
  - Connect flow when mode == Tun on mobile: start the core (Local) → probe through the local proxy (proves the server) → `platform.start_vpn(mixed_port, allowed, disallowed)` → wait for `vpn_status() == Running` (poll each frame, 15 s timeout) → Connected. `PermissionDenied` / `Failed` → stop core, Failed state + toast. Disconnect → `stop_vpn()` then stop the core. Health probes go through the local proxy on mobile (our own app is excluded from the VPN).
  - Per-app split tunnel on Android: Process rules with action Direct → `disallowed`; if default_route == Direct, Process rules with action Proxy → `allowed` (then only those apps use the VPN). Block process rules are ignored on Android.
  - "Import file…" menu item hidden on mobile; "Open folder" buttons hidden.
- Desktop behaviour and look must stay exactly the same; all existing GUI tests keep passing.

## C. Android crate `crates/easyvpn-android` (package easyvpn-android, `[lib] name = "easyvpn"`, `crate-type = ["cdylib"]`)
- All code `#![cfg(target_os = "android")]` and all deps under `[target.'cfg(target_os = "android")'.dependencies]`, so `cargo build --workspace` on Windows still succeeds (the crate compiles to nothing there).
- Deps: easyvpn-gui (path), easyvpn-core (workspace), eframe 0.29 with features ["android-native-activity"] (same version as the GUI crate so features unify), jni (use the same major version tun2proxy 0.8.7 uses — it uses the new `jni` API with `Env`/`EnvUnowned`; check `cargo tree`), tun2proxy 0.8.7 with default-features = false, features = ["udpgw"], tokio (rt-multi-thread, macros), android_logger, log, anyhow, once_cell or std OnceLock.
- `#[no_mangle] fn android_main(app: winit::platform::android::activity::AndroidApp)` (re-exported via `eframe::winit`): init android_logger (tag "EasyVpn"); via JNI on the activity: set env `EASYVPN_HOME` = `getFilesDir()`, `EASYVPN_CORE_DIR` = `getApplicationInfo().nativeLibraryDir`, `EASYVPN_ASSET_DIR` = `<filesDir>/assets` (MainActivity copies geoip.dat/geosite.dat there on create); then `easyvpn_gui::run_app(NativeOptions { android_app: Some(app), ..Default::default() }, Box::new(AndroidPlatform::new(vm, activity_global_ref)))`.
- `AndroidPlatform` (implements Platform): clipboard through `ClipboardManager` (getSystemService("clipboard"), getPrimaryClip / setPrimaryClip(ClipData.newPlainText)); `start_vpn` → static Java `com.easyvpn.app.MainActivity.startVpn(int, String allowedCsv, String disallowedCsv)`; `stop_vpn` → `MainActivity.stopVpn()`; `vpn_status` reads a global set by `Native.onVpnState`; `safe_area` from resources `status_bar_height` / `navigation_bar_height` (px ÷ density). JNI calls attach the current thread (`vm.attach_current_thread`).
- JNI exports for class `com.easyvpn.app.Native`:
  - `static native int startTun(int fd, int socksPort, int mtu)`: build `tun2proxy::Args` (proxy = `ProxyParameters::try_from("socks5://127.0.0.1:<port>")`, `tun_fd(Some(fd))`, `close_fd_on_drop(false)`, `dns(ArgDns::Virtual)`, `dns_addr(1.1.1.1)`, `ipv6_enabled(false)`, `setup(false)`), spawn a thread with a tokio runtime running `tun2proxy::general_run_async(args, mtu as u16, false, token)`; keep the CancellationToken in a global; return 0 or a negative error.
  - `static native void stopTun()`: cancel the token, join/forget the thread.
  - `static native void onVpnState(int state, String message)`: 0 Idle, 1 Starting, 2 Running, 3 PermissionDenied, 4 Failed → global VpnStatus.
- Java (android/app/src/main/java/com/easyvpn/app/):
  - `Native.java`: `static { System.loadLibrary("easyvpn"); }` + the three natives.
  - `MainActivity extends android.app.NativeActivity`: keeps a static instance; `onCreate` copies assets geoip.dat/geosite.dat to filesDir/assets (if missing or size differs) BEFORE `super.onCreate`; asks POST_NOTIFICATIONS on API 33+; `public static void startVpn(int port, String allowed, String disallowed)` runs on the UI thread: `VpnService.prepare(this)` → if an Intent is returned, `startActivityForResult(intent, 1)` (remember params) else start the service; `onActivityResult` → RESULT_OK starts the service, else `Native.onVpnState(3, "permission denied")`; `public static void stopVpn()` sends ACTION_STOP to the service.
  - `EasyVpnService extends VpnService`: ACTION_START/ACTION_STOP; notification channel "vpn" + `startForeground(1, notification)` (API 34+: `ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE`); Builder: session "EasyVpn", mtu 1500, `addAddress("172.19.0.1", 30)`, `addRoute("0.0.0.0", 0)`, `addDnsServer("1.1.1.1")`, then app filters: if allowed non-empty → `addAllowedApplication` for each (skip invalid packages), else `addDisallowedApplication(getPackageName())` + each disallowed; `establish()` → keep the ParcelFileDescriptor; `Native.startTun(pfd.getFd(), port, 1500)`; report `onVpnState(2|4, msg)`; on stop/onRevoke/onDestroy: `Native.stopTun()`, close pfd, `stopForeground`, `onVpnState(0, "")`.
- `android/app/src/main/AndroidManifest.xml`: package `com.easyvpn.app`, versionCode 1, versionName 0.1.0; uses-sdk min 26 target 35; permissions INTERNET, ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, POST_NOTIFICATIONS; `<application android:label="EasyVpn" android:icon="@mipmap/ic_launcher" android:roundIcon="@mipmap/ic_launcher" android:extractNativeLibs="true" android:hasCode="true" android:theme="@android:style/Theme.Black.NoTitleBar">`; activity MainActivity (exported, launcher, `android:configChanges="orientation|screenSize|screenLayout|keyboardHidden|keyboard|density|uiMode"`, `android:windowSoftInputMode="adjustResize"`, meta-data `android.app.lib_name` = `easyvpn`); service EasyVpnService (exported false, permission BIND_VPN_SERVICE, foregroundServiceType specialUse, intent-filter `android.net.VpnService`, `<property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE" android:value="vpn"/>`).
- Resources: adaptive launcher icon in `res/mipmap-anydpi-v26/ic_launcher.xml` with `res/drawable/ic_launcher_background.xml` (blue #2563EB → #1D4ED8 vector) and `res/drawable/ic_launcher_foreground.xml` (white power symbol vector, inside the 66dp safe zone); notification icon `res/drawable/ic_stat_vpn.xml` (white shield/power vector).
- `tools/build_apk.py` (Python 3, stdlib only, no Gradle): `python tools/build_apk.py [--abi arm64-v8a|x86_64|all] [--install] [--release-name dist/EasyVpn.apk]`
  1. Locate SDK (`ANDROID_HOME` or default `E:\2-Sources\AndroidSdk`), newest build-tools, platform android-35 (fallback newest), NDK 28.x (`ANDROID_NDK_HOME`), JDK (`JAVA_HOME` or default path above).
  2. `cargo ndk -t <abi>... -P 26 -o android/build/jniLibs build --release -p easyvpn-android` (Windows-safe subprocess, PATH includes ~/.cargo/bin).
  3. Copy `android/cores/<abi>/*.so` into `android/build/jniLibs/<abi>/`.
  4. `javac --release 8 -classpath android.jar -d build/classes` (warnings about --release 8 are fine) → `d8 --release --lib android.jar --min-api 26 --output build/dex <classes>`.
  5. `aapt2 compile --dir res -o build/res.zip`; `aapt2 link -I android.jar --manifest AndroidManifest.xml -A android/cores/assets --min-sdk-version 26 --target-sdk-version 35 -o build/base.apk build/res.zip`.
  6. Add `classes.dex` and `lib/<abi>/*.so` to the APK with zipfile (keep compression for .so since extractNativeLibs=true).
  7. `zipalign -P 16 -f 4` → `apksigner sign` with `~/.android/debug.keystore` (create with keytool if missing: alias androiddebugkey, pass android, CN=Android Debug).
  8. Write the final APK (default `dist/EasyVpn.apk`); `--install` → `adb install -r`.
  On any failed step print the command and its output and exit 1.


---

# v10 — copy/paste in fields, QR camera scan, smart import

Found on the Android emulator (all verified):
- egui text fields cannot copy or paste on Android: egui's `PlatformOutput.copied_text` is never sent to the Android clipboard and nothing feeds `egui::Event::Paste` from it. (Platform::clipboard_get/set themselves work — "Copy link" and "Paste from clipboard" succeed.)
- Dropdown menus ("+", "≡", server row "⋯") stay open after an item is tapped on Android.
- `link::to_link` percent-encodes '-' in the VLESS/VMess/TUIC uuid (`vless://<uuid>%2D…%2D…`), which other apps may not accept.
- Pasting a subscription URL is not recognised as a subscription.

## A. Core: smart import (import.rs) + link encoding fix (link.rs)
```rust
pub enum Classified { Subscription(String /*url*/), Configs(Vec<Profile>), Nothing }
/// Decide what a pasted / scanned / imported text is.
pub fn classify(text: &str) -> Classified;
```
Rules: trim; a single line that is an http(s) URL with a non-empty path ("/x…") or a query, and no userinfo → Subscription (http(s) proxy links look like `http://user:pass@host:port` with no path → configs). Also accept `sub://<base64 url>` and `clash://install-config?url=<encoded>` / `sing-box://import-remote-profile?url=<encoded>#name` deep links → Subscription(decoded url). Several lines: if every non-empty line is a subscription URL → only the first is returned as Subscription is NOT enough: return Configs for share links and ignore URLs? Simpler and required: if ANY line is a share link (vmess:// vless:// trojan:// ss:// socks:// hy2:// hysteria2:// hysteria:// tuic:// wireguard:// wg:// ssh:// anytls://) → Configs(import_text(text)); else if the first non-empty line is a subscription URL → Subscription; else Configs(import_text(text)) or Nothing if empty.
Unit tests: the real subscription URL `https://panel.example.com/sub/abc123…` → Subscription; `http://u:p@1.2.3.4:8080` → Configs(http proxy); vless link → Configs; `sub://aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWI=` → Subscription("https://example.com/sub"); empty → Nothing; text with two vmess links → Configs(2).
link.rs: when serializing userinfo/query values only percent-encode characters outside RFC 3986 unreserved (`A-Z a-z 0-9 - . _ ~`) plus what the scheme needs; uuids must stay readable. Round-trip tests asserting `to_link` of a vless profile contains the literal uuid with dashes.

## B. GUI (easyvpn-gui)
1. Clipboard for text fields on mobile (desktop already works through winit/arboard — keep it):
   - Every frame, if `ctx.output(|o| o.copied_text)` is non-empty and `platform.is_mobile()`, call `platform.clipboard_set(text)` (read it outside any ctx closure).
   - Implement `eframe::App::raw_input_hook(&mut self, ctx, raw_input)`: push queued synthetic events (`egui::Event::Paste(text)`, `Event::Copy`, `Event::Cut`) prepared by the UI.
   - Long-press (≥ 450 ms, or a double tap) on any focused-capable text field opens a small floating menu (same dropdown style) with **Paste**, **Copy**, **Cut**, **Select all**: Paste → focus the field and queue `Event::Paste(platform.clipboard_get())`; Copy/Cut → queue `Event::Copy`/`Event::Cut` (egui then fills copied_text, forwarded as above); Select all → set the TextEdit's CCursorRange to the full text via `egui::TextEdit::load_state/store`. Put this in a shared theme helper used by every text input (`theme::text_input` etc.).
   - Additionally, on mobile, fields meant for links (subscription URL, import text, editor's address/uuid/password/key, rules value, source URL) show a small round "paste" icon button at the right edge inside the field that replaces/inserts the clipboard text.
2. Dropdown menus close after any item is clicked (mobile and desktop) — the close must also happen when the item's action changes the page.
3. Smart import everywhere: "Paste from clipboard", "Import text…" and QR results go through `easyvpn_core::import::classify`:
   - Subscription(url) → add subscription named after the URL host (if the same URL already exists just update it), update it on a background thread, toast "Subscription added · N servers" (or the error).
   - Configs(list) → add profiles, toast "N configs imported".
   - Nothing → toast "Clipboard doesn't contain a config or subscription link".
4. QR scanning:
   - Platform trait gains (default implementations keep desktop compiling):
```rust
fn can_scan_qr(&self) -> bool { false }
/// Mobile: opens the camera scanner; the result arrives later via take_qr_result.
fn start_qr_scan(&self) -> anyhow::Result<()> { anyhow::bail!("QR scanning is not supported on this platform") }
/// Some(Ok(text)) when a code was scanned, Some(Err(msg)) on cancel/permission denial, None while pending.
fn take_qr_result(&self) -> Option<Result<String, String>> { None }
```
   - "+" menu: item **Scan QR code** (camera icon drawn with the painter) shown when `can_scan_qr()`; the App polls `take_qr_result()` each frame while a scan is pending and sends Ok(text) through smart import; Err(msg) → toast (no toast for a plain cancel "cancelled").
   - Desktop: no change (no camera item).

## C. Android
1. Rust (crates/easyvpn-android): dependency `rqrr = "0.7"` (android target).
   - JNI `static native String decodeQr(byte[] luma, int width, int height, int rowStride)` on `com.easyvpn.app.Native`: build `rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luma[y * rowStride + x])`, detect grids, decode, return the first successful content, or null. Must never panic across JNI (catch_unwind); ignore frames with wrong sizes.
   - JNI `static native void onQrResult(int status, String text)` (status 0 = ok, 1 = cancelled, 2 = error/permission denied) stores the result in a global `Mutex<Option<Result<String,String>>>`.
   - AndroidPlatform: `can_scan_qr` → true; `start_qr_scan` → static Java `MainActivity.startScanner()`; `take_qr_result` → take from the global.
   - A pure helper `decode_qr_luma(luma: &[u8], width, height, row_stride) -> Option<String>` with a unit test (runs on the desktop host too, so keep it outside the android cfg in a small module compiled for all targets, e.g. `src/qr.rs` with `#[cfg(test)]` generating a QR via dev-dependency `qrcode = "0.14"` rendered to luma).
2. Java:
   - `ScannerActivity extends Activity` (new file): full-screen dark UI built in code (no XML layouts): a `TextureView` camera preview filling the screen, a rounded square viewfinder overlay with a subtle blue (#3B82F6) border, hint text "Point the camera at a QR code", and a "Cancel" button at the bottom. Requests `CAMERA` permission at runtime; denial → `Native.onQrResult(2, "camera permission denied")` + finish. Uses Camera2 with the back camera, preview to the TextureView and an `ImageReader` (YUV_420_888, ~1280×720 or the closest supported size) on a background HandlerThread; at most one decode in flight, throttled to every ~250 ms; passes the Y plane (with its rowStride) to `Native.decodeQr`; on a result: vibrate briefly (if VIBRATE permission present, else skip), `Native.onQrResult(0, text)`, finish. Back/Cancel → `onQrResult(1, "cancelled")`. Release the camera in onPause/onDestroy.
   - `MainActivity.startScanner()`: static, starts ScannerActivity on the UI thread.
   - Manifest: `<uses-permission android:name="android.permission.CAMERA"/>`, `<uses-feature android:name="android.hardware.camera.any" android:required="false"/>`, activity `.ScannerActivity` (exported false, `android:screenOrientation="portrait"`, theme `@android:style/Theme.Black.NoTitleBar.Fullscreen`).
