use crate::profile::{CoreKind, Profile, Protocol, ProxyMode, Settings};
use anyhow::{bail, Context, Result};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const LOG_CAPACITY: usize = 1000;
type LogBuffer = Arc<Mutex<VecDeque<String>>>;

pub fn cores_dir() -> PathBuf {
    crate::store::data_dir().join("cores")
}

pub(crate) fn executable_name(kind: CoreKind) -> String {
    format!("{}{}", kind.name(), std::env::consts::EXE_SUFFIX)
}

pub fn binary_path(kind: CoreKind) -> PathBuf {
    #[cfg(target_os = "android")]
    {
        let bundled_name = match kind {
            CoreKind::Xray => "libxray.so",
            CoreKind::SingBox => "libsingbox.so",
            CoreKind::Mihomo => "libmihomo.so",
            CoreKind::OpenVpn => {
                return cores_dir().join("openvpn-unsupported").join("openvpn");
            }
        };
        if let Some(directory) = std::env::var_os("EASYVPN_CORE_DIR") {
            return PathBuf::from(directory).join(bundled_name);
        }
        cores_dir().join(kind.name()).join(executable_name(kind))
    }

    #[cfg(not(target_os = "android"))]
    {
        let managed = cores_dir().join(kind.name()).join(executable_name(kind));
        if kind != CoreKind::OpenVpn || managed.is_file() {
            return managed;
        }
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                let candidate = directory.join(executable_name(kind));
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
        for path in [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            "/usr/sbin/openvpn",
            "/usr/local/sbin/openvpn",
            "/opt/homebrew/sbin/openvpn",
            "/opt/homebrew/bin/openvpn",
            "/usr/local/bin/openvpn",
        ] {
            let candidate = PathBuf::from(path);
            if candidate.is_file() {
                return candidate;
            }
        }
        managed
    }
}

pub fn is_installed(kind: CoreKind) -> bool {
    #[cfg(target_os = "android")]
    if kind == CoreKind::OpenVpn {
        return false;
    }
    binary_path(kind).is_file()
}

/// Whether the current application has administrator/root privileges.
/// Android VPN permission is handled by the platform's VpnService, not root.
pub fn is_elevated() -> bool {
    #[cfg(target_os = "android")]
    {
        true
    }
    #[cfg(windows)]
    {
        #[link(name = "shell32")]
        extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        // No pointers or ownership are involved in this shell32 query.
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        Command::new("id")
            .arg("-u")
            .output()
            .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "0")
            .unwrap_or(false)
    }
}

fn check_elevation(s: &Settings) -> Result<()> {
    if s.mode == ProxyMode::Tun && !is_elevated() {
        bail!("TUN mode needs Administrator/root");
    }
    Ok(())
}

fn run_directory(name: &str) -> PathBuf {
    crate::store::data_dir().join("run").join(name)
}

/// Probe the actual bind address; stats must always remain loopback-only.
/// These are preflight checks, not reservations: the core binds after spawn.
fn check_port(host: &str, port: u16) -> Result<()> {
    if port == 0 {
        bail!("Local port must be nonzero");
    }
    match TcpListener::bind((host.trim_matches(['[', ']']), port)) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
            bail!(
                "Port {port} is in use by another program — change Local port in Settings"
            )
        }
        Err(error) => Err(error).with_context(|| format!("checking local port {host}:{port}")),
    }
}

fn check_ports(kind: CoreKind, p: &Profile, s: &Settings) -> Result<()> {
    // Raw configs own their ports. OpenVPN has no mixed/stats listener.
    if kind.is_tunnel() || p.protocol == Some(Protocol::Custom) {
        return Ok(());
    }
    let stats = s.mixed_port.checked_add(2).context("stats port overflows u16")?;
    let listen = if s.allow_lan { "0.0.0.0" } else { &s.listen };
    check_port(listen, s.mixed_port)?;
    if kind == CoreKind::Xray {
        let http = s.mixed_port.checked_add(1).context("HTTP port overflows u16")?;
        check_port(listen, http)?;
    }
    check_port("127.0.0.1", stats)
}

fn push_log(logs: &LogBuffer, line: String) {
    let mut buffer = logs.lock().unwrap_or_else(|e| e.into_inner());
    if buffer.len() == LOG_CAPACITY {
        buffer.pop_front();
    }
    buffer.push_back(line);
}

fn read_logs(reader: impl Read + Send + 'static, logs: LogBuffer) {
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut bytes = Vec::new();
        loop {
            bytes.clear();
            match reader.read_until(b'\n', &mut bytes) {
                Ok(0) => break,
                Ok(_) => {
                    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
                        bytes.pop();
                    }
                    push_log(&logs, String::from_utf8_lossy(&bytes).into_owned());
                }
                Err(error) => {
                    push_log(&logs, format!("Failed to read core log: {error}"));
                    break;
                }
            }
        }
    });
}

struct AuthFile(PathBuf);

impl Drop for AuthFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn write_auth_file(path: PathBuf, p: &Profile) -> Result<AuthFile> {
    if p.username.contains(['\r', '\n']) || p.password.contains(['\r', '\n']) {
        bail!("OpenVPN username and password must not contain newlines");
    }
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("removing stale OpenVPN auth file"),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).context("creating OpenVPN auth file")?;
    let auth = AuthFile(path);
    writeln!(file, "{}", p.username).context("writing OpenVPN username")?;
    writeln!(file, "{}", p.password).context("writing OpenVPN password")?;
    file.sync_all().context("syncing OpenVPN auth file")?;
    Ok(auth)
}

fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_exe(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn process_exe(pid: u32) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    #[link(name = "proc")]
    extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, size: u32) -> i32;
    }
    let pid = i32::try_from(pid).ok()?;
    let mut buffer = vec![0u8; 4096];
    let size = unsafe { proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if size <= 0 {
        return None;
    }
    let end = buffer.iter().position(|&b| b == 0)?;
    buffer.truncate(end);
    Some(PathBuf::from(std::ffi::OsString::from_vec(buffer)))
}

#[cfg(windows)]
fn process_exe(pid: u32) -> Option<PathBuf> {
    windows::process_exe(pid)
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
fn process_exe(_pid: u32) -> Option<PathBuf> {
    // Fail closed on platforms without a reliable executable-path query.
    None
}

/// Only executables under an application-owned core directory may be killed.
fn is_managed_executable(exe: &Path) -> bool {
    let Ok(exe) = exe.canonicalize() else {
        return false;
    };
    if let Ok(root) = cores_dir().canonicalize() {
        if exe.starts_with(root) {
            return true;
        }
    }
    #[cfg(target_os = "android")]
    if let Some(directory) = std::env::var_os("EASYVPN_CORE_DIR") {
        if let Ok(root) = PathBuf::from(directory).canonicalize() {
            if exe.starts_with(root) {
                return true;
            }
        }
    }
    false
}

/// Never trust a stale PID alone: it could now refer to an unrelated program.
fn cleanup_orphan(pid_file: &Path) -> Result<()> {
    if let Some(pid) = read_pid(pid_file).filter(|pid| *pid != 0 && *pid != std::process::id()) {
        if let Some(exe) = process_exe(pid) {
            if is_managed_executable(&exe) {
                #[cfg(windows)]
                let mut command = {
                    use std::os::windows::process::CommandExt;
                    let mut command = Command::new("taskkill");
                    command.args(["/F", "/PID", &pid.to_string()]);
                    command.creation_flags(0x08000000);
                    command
                };
                #[cfg(not(windows))]
                let mut command = {
                    let mut command = Command::new("kill");
                    command.args(["-9", &pid.to_string()]);
                    command
                };
                let status = command
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .context("terminating orphaned core")?;
                if !status.success() && process_exe(pid).is_some() {
                    bail!("Could not stop orphaned core process {pid}");
                }
                // Killing is asynchronous. Wait briefly for listening sockets
                // to disappear before performing the port preflight.
                for _ in 0..40 {
                    if process_exe(pid).is_none() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }
    match std::fs::remove_file(pid_file) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("removing stale core pid file"),
    }
}

/// Resolve before installing TUN routes, while the OS resolver can still reach
/// its upstream without depending on Xray. Keep every distinct address so both
/// IPv4 and IPv6 server connections can bypass the helper.
fn resolve_tun_server(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if host.is_empty() {
        bail!("Cannot resolve Xray server before starting TUN: server hostname is empty");
    }
    let addresses = (host, port).to_socket_addrs().with_context(|| {
        format!(
            "Cannot resolve Xray server '{host}' before starting TUN — check the server hostname and your DNS connection"
        )
    })?;
    let mut ips = Vec::new();
    for address in addresses {
        let ip = address.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    if ips.is_empty() {
        bail!(
            "Cannot resolve Xray server '{host}' before starting TUN: DNS returned no IP addresses"
        );
    }
    Ok(ips)
}

/// Android owns the TUN device through VpnService. Generated core configs must
/// expose only their local proxy, even if the requested connection mode is TUN.
#[cfg(target_os = "android")]
fn android_core_settings(s: &Settings) -> Settings {
    let mut settings = s.clone();
    if settings.mode == ProxyMode::Tun {
        settings.mode = ProxyMode::Local;
    }
    settings.tun = false;
    settings
}

pub struct CoreProcess {
    child: Child,
    kind: CoreKind,
    logs: LogBuffer,
    auth_file: Option<AuthFile>,
    pid_file: PathBuf,
    #[cfg(windows)]
    job: Option<windows::Job>,
}

impl CoreProcess {
    pub fn start(kind: CoreKind, p: &Profile, s: &Settings) -> Result<CoreProcess> {
        #[cfg(target_os = "android")]
        let local_settings = android_core_settings(s);
        #[cfg(target_os = "android")]
        let s = &local_settings;

        check_elevation(s)?;
        if !is_installed(kind) {
            bail!(
                "core {} not installed, run `easyvpn core install {}`",
                kind.name(),
                kind.name()
            );
        }
        let text = crate::config::build(kind, p, s)?;
        let run_dir = run_directory(kind.name());
        cleanup_orphan(&run_dir.join("pid"))?;
        check_ports(kind, p, s)?;
        Self::spawn_config(kind, p, &text, &run_dir)
    }

    /// Shared spawn path for normal cores and the isolated TUN helper.
    /// Caller performs mode, orphan and port checks before writing any files.
    fn spawn_config(kind: CoreKind, p: &Profile, text: &str, run_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(run_dir).context("creating core run directory")?;
        let run_dir = std::path::absolute(run_dir).context("resolving run directory")?;
        let config_path = run_dir.join(crate::config::file_name(kind));
        std::fs::write(&config_path, text).context("writing core configuration")?;
        let binary = std::path::absolute(binary_path(kind)).context("resolving core binary")?;
        let core_dir = binary.parent().context("core binary has no parent directory")?;
        let mut command = Command::new(&binary);
        command
            .current_dir(core_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut auth_file = None;
        match kind {
            CoreKind::Xray => {
                let asset_dir = std::env::var_os("EASYVPN_ASSET_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| core_dir.to_path_buf());
                command
                    .arg("run")
                    .arg("-c")
                    .arg(&config_path)
                    .env("XRAY_LOCATION_ASSET", asset_dir);
            }
            CoreKind::SingBox => {
                command.arg("run").arg("-c").arg(&config_path).arg("-D").arg(&run_dir);
            }
            CoreKind::Mihomo => {
                command.arg("-d").arg(&run_dir).arg("-f").arg(&config_path);
            }
            CoreKind::OpenVpn => {
                command
                    .current_dir(&run_dir)
                    .arg("--config")
                    .arg(&config_path)
                    .arg("--auth-nocache")
                    .arg("--verb")
                    .arg("3");
                if !p.username.is_empty() {
                    let auth = write_auth_file(run_dir.join("auth.txt"), p)?;
                    command.arg("--auth-user-pass").arg(&auth.0);
                    auth_file = Some(auth);
                }
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }

        // Construct the owner immediately: every subsequent error kills/waits
        // the child and removes credentials via Drop.
        let child = command.spawn().with_context(|| format!("starting {}", kind.name()))?;
        let mut process = Self {
            child,
            kind,
            logs: Arc::new(Mutex::new(VecDeque::with_capacity(LOG_CAPACITY))),
            auth_file,
            pid_file: run_dir.join("pid"),
            #[cfg(windows)]
            job: None,
        };
        #[cfg(windows)]
        {
            process.job = Some(windows::Job::assign(&process.child)?);
        }
        std::fs::write(&process.pid_file, format!("{}\n", process.child.id()))
            .context("writing core pid file")?;

        if let Some(stdout) = process.child.stdout.take() {
            read_logs(stdout, Arc::clone(&process.logs));
        }
        if let Some(stderr) = process.child.stderr.take() {
            read_logs(stderr, Arc::clone(&process.logs));
        }

        thread::sleep(Duration::from_millis(800));
        if let Some(status) = process.child.try_wait().context("checking core startup")? {
            thread::sleep(Duration::from_millis(50));
            bail!(
                "{} exited during startup ({status}):\n{}",
                kind.name(),
                process.logs().join("\n")
            );
        }
        Ok(process)
    }

    pub fn kind(&self) -> CoreKind {
        self.kind
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn stop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        #[cfg(windows)]
        {
            self.job.take();
        }
        self.auth_file.take();
        // Do not erase a newer instance's PID if this instance was replaced.
        if read_pid(&self.pid_file) == Some(self.child.id()) {
            let _ = std::fs::remove_file(&self.pid_file);
        }
    }

    pub fn logs(&self) -> Vec<String> {
        self.logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Owns the main core and, for desktop Xray TUN mode, a sing-box TUN bridge.
/// System proxy configuration remains the responsibility of the caller.
pub struct Connection {
    main: CoreProcess,
    helper: Option<CoreProcess>,
}

impl Connection {
    pub fn start(kind: CoreKind, p: &Profile, s: &Settings) -> Result<Self> {
        #[cfg(target_os = "android")]
        let local_settings = android_core_settings(s);
        #[cfg(target_os = "android")]
        let s = &local_settings;

        check_elevation(s)?;
        // Custom configs are always used as-is, with no assumed SOCKS port.
        // Android's VpnService supplies the tunnel; never start a TUN helper.
        let needs_helper = !cfg!(target_os = "android")
            && s.mode == ProxyMode::Tun
            && kind == CoreKind::Xray
            && p.protocol != Some(Protocol::Custom);
        if needs_helper && !is_installed(CoreKind::SingBox) {
            bail!("TUN mode needs the sing-box core — install it in Settings");
        }

        let helper_dir = run_directory("sing-box-tun");
        // Remove a previous helper before resolving the server or starting the
        // main core: stale TUN routes could otherwise trap bootstrap DNS too.
        let server_ips = if needs_helper {
            cleanup_orphan(&helper_dir.join("pid"))?;
            resolve_tun_server(&p.address, p.port)?
        } else {
            Vec::new()
        };

        // Leave Xray's generated config unchanged, including its server name.
        // The helper handles subsequent OS DNS queries for that name directly.
        let main = CoreProcess::start(kind, p, s)?;
        let mut connection = Self { main, helper: None };
        if needs_helper {
            let config = serde_json::to_string_pretty(
                &crate::config::singbox::tun_helper(s, s.mixed_port, &p.address, &server_ips),
            )?;
            connection.helper = Some(
                CoreProcess::spawn_config(CoreKind::SingBox, p, &config, &helper_dir)
                    .context("starting sing-box TUN helper")?,
            );
        }
        // The main core could have exited while the helper was starting.
        if !connection.is_running() {
            bail!("connection exited during startup:\n{}", connection.logs().join("\n"));
        }
        Ok(connection)
    }

    pub fn kind(&self) -> CoreKind {
        self.main.kind()
    }

    pub fn is_running(&mut self) -> bool {
        let main = self.main.is_running();
        let helper = self.helper.as_mut().map(CoreProcess::is_running).unwrap_or(true);
        main && helper
    }

    pub fn stop(&mut self) {
        // Restore TUN routes before taking away its SOCKS destination.
        if let Some(helper) = &mut self.helper {
            helper.stop();
        }
        self.main.stop();
    }

    pub fn logs(&self) -> Vec<String> {
        let mut logs = self.main.logs();
        if let Some(helper) = &self.helper {
            logs.extend(helper.logs().into_iter().map(|line| format!("[tun] {line}")));
        }
        logs
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(windows)]
mod windows {
    use anyhow::{Context, Result};
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::PathBuf;
    use std::process::Child;

    type Handle = *mut c_void;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimitInformation {
        basic_limit_information: BasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            class: i32,
            information: *const c_void,
            length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn QueryFullProcessImageNameW(
            process: Handle,
            flags: u32,
            name: *mut u16,
            size: *mut u32,
        ) -> i32;
    }

    /// OwnedHandle closes the job on every exit path, including startup errors.
    /// The job is unnamed and non-inheritable so only this app owns its lifetime.
    pub(super) struct Job(OwnedHandle);

    impl Job {
        pub(super) fn assign(child: &Child) -> Result<Self> {
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(std::io::Error::last_os_error()).context("creating core Job Object");
            }
            let job = Self(unsafe { OwnedHandle::from_raw_handle(handle) });
            let mut limits = ExtendedLimitInformation::default();
            limits.basic_limit_information.limit_flags = 0x00002000;
            let success = unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    9,
                    (&limits as *const ExtendedLimitInformation).cast(),
                    std::mem::size_of::<ExtendedLimitInformation>() as u32,
                )
            };
            if success == 0 {
                return Err(std::io::Error::last_os_error()).context("configuring core Job Object");
            }
            if unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), child.as_raw_handle()) } == 0 {
                return Err(std::io::Error::last_os_error()).context("assigning core to Job Object");
            }
            Ok(job)
        }
    }

    pub(super) fn process_exe(pid: u32) -> Option<PathBuf> {
        let raw = unsafe { OpenProcess(0x1000, 0, pid) };
        if raw.is_null() {
            return None;
        }
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut buffer = vec![0u16; 32768];
        let mut length = buffer.len() as u32;
        let success = unsafe {
            QueryFullProcessImageNameW(
                process.as_raw_handle(),
                0,
                buffer.as_mut_ptr(),
                &mut length,
            )
        };
        if success == 0 {
            return None;
        }
        buffer.truncate(length as usize);
        Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static PORT_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "android")]
    #[test]
    fn android_tun_uses_local_core_settings() {
        let original = Settings {
            mode: ProxyMode::Tun,
            tun: true,
            mixed_port: 12345,
            ..Settings::default()
        };
        let local = android_core_settings(&original);
        assert_eq!(local.mode, ProxyMode::Local);
        assert!(!local.tun);
        assert_eq!(local.mixed_port, original.mixed_port);
        assert_eq!(original.mode, ProxyMode::Tun);
        assert!(original.tun);
        assert!(is_elevated());
        assert!(!is_installed(CoreKind::OpenVpn));
    }

    #[test]
    fn tun_server_literals_do_not_need_dns() -> Result<()> {
        for host in ["203.0.113.10", "2001:db8::10", "[2001:db8::10]"] {
            let expected: IpAddr = host.trim_matches(['[', ']']).parse()?;
            assert_eq!(resolve_tun_server(host, 443)?, vec![expected]);
        }
        Ok(())
    }

    #[test]
    fn tun_server_resolution_errors_are_actionable() {
        for host in ["", "invalid host name"] {
            let error = resolve_tun_server(host, 443).expect_err("invalid hostname");
            assert!(error.to_string().contains("Cannot resolve Xray server"));
            assert!(error.to_string().contains("before starting TUN"));
        }
    }

    #[test]
    fn occupied_port_has_actionable_error() -> Result<()> {
        let _guard = PORT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let error = check_port("127.0.0.1", port).expect_err("port is occupied");
        assert_eq!(
            error.to_string(),
            format!("Port {port} is in use by another program — change Local port in Settings")
        );
        Ok(())
    }

    #[test]
    fn free_port_passes_preflight() -> Result<()> {
        let _guard = PORT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        assert!(check_port("127.0.0.1", 0).is_err());

        // Other processes can still claim the port after the listener is dropped.
        // Retry only that race; unrelated preflight errors must fail immediately.
        for attempt in 0..10 {
            let listener = TcpListener::bind(("127.0.0.1", 0))?;
            let port = listener.local_addr()?.port();
            drop(listener);
            match check_port("127.0.0.1", port) {
                Ok(()) => return Ok(()),
                Err(error)
                    if attempt < 9
                        && error.to_string()
                            == format!(
                                "Port {port} is in use by another program — change Local port in Settings"
                            ) => {}
                Err(error) => return Err(error),
            }
        }
        bail!("Free-port preflight did not succeed after 10 attempts")
    }

    #[test]
    fn stats_port_is_checked_and_raw_configs_are_exempt() -> Result<()> {
        let _guard = PORT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        // Reserve a stats endpoint and find a free corresponding mixed port.
        let (stats_listener, mixed_listener, mixed_port) = loop {
            let stats = TcpListener::bind(("127.0.0.1", 0))?;
            let port = stats.local_addr()?.port();
            if port <= 2 {
                continue;
            }
            if let Ok(mixed) = TcpListener::bind(("127.0.0.1", port - 2)) {
                break (stats, mixed, port - 2);
            }
        };
        let stats_port = stats_listener.local_addr()?.port();
        drop(mixed_listener);
        let s = Settings { mixed_port, ..Settings::default() };
        let p = Profile { protocol: Some(Protocol::Socks), ..Profile::default() };
        let error = check_ports(CoreKind::SingBox, &p, &s).expect_err("stats occupied");
        assert!(error.to_string().contains(&format!("Port {stats_port} is in use")));
        let custom = Profile { protocol: Some(Protocol::Custom), ..Profile::default() };
        check_ports(CoreKind::Xray, &custom, &s)?;
        check_ports(CoreKind::OpenVpn, &p, &s)?;
        Ok(())
    }

    #[test]
    fn port_overflow_is_an_error() {
        let _guard = PORT_TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let p = Profile { protocol: Some(Protocol::Socks), ..Profile::default() };
        for mixed_port in [u16::MAX - 1, u16::MAX] {
            let s = Settings { mixed_port, ..Settings::default() };
            assert!(check_ports(CoreKind::Xray, &p, &s).is_err());
        }
    }

    #[test]
    fn auth_file_is_private_and_removed_on_drop() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "easyvpn-auth-test-{:016x}.txt", rand::random::<u64>()
        ));
        let profile = Profile {
            username: "user".into(), password: "password".into(), ..Profile::default()
        };
        let auth = write_auth_file(path.clone(), &profile)?;
        assert_eq!(std::fs::read_to_string(&path)?, "user\npassword\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        drop(auth);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn auth_file_replaces_stale_credentials() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "easyvpn-auth-test-{:016x}.txt", rand::random::<u64>()
        ));
        std::fs::write(&path, "old-user\nold-password-with-extra-data\n")?;
        let profile = Profile {
            username: "user".into(), password: "password".into(), ..Profile::default()
        };
        let auth = write_auth_file(path.clone(), &profile)?;
        assert_eq!(std::fs::read_to_string(&path)?, "user\npassword\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        drop(auth);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn auth_file_rejects_multiline_credentials() {
        let path = std::env::temp_dir().join(format!(
            "easyvpn-auth-test-{:016x}.txt", rand::random::<u64>()
        ));
        let profile = Profile { username: "user\ninjected".into(), ..Profile::default() };
        assert!(write_auth_file(path.clone(), &profile).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn malformed_pid_is_removed_without_killing() -> Result<()> {
        let path = std::env::temp_dir().join(format!(
            "easyvpn-pid-test-{:016x}", rand::random::<u64>()
        ));
        std::fs::write(&path, "invalid pid")?;
        cleanup_orphan(&path)?;
        assert!(!path.exists());
        std::fs::write(&path, std::process::id().to_string())?;
        cleanup_orphan(&path)?;
        assert!(!path.exists());
        Ok(())
    }
}
