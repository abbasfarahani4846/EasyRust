use anyhow::Result;

pub fn enable(host: &str, port: u16) -> Result<()> {
    #[cfg(not(target_os = "android"))]
    {
        anyhow::ensure!(!host.is_empty(), "proxy host must not be empty");
        anyhow::ensure!(port != 0, "proxy port must not be zero");
    }
    platform::enable(host, port)
}

pub fn disable() -> Result<()> {
    platform::disable()
}

#[cfg(target_os = "android")]
mod platform {
    use anyhow::{bail, Result};

    pub fn enable(_host: &str, _port: u16) -> Result<()> {
        bail!("not supported on Android")
    }

    pub fn disable() -> Result<()> {
        bail!("not supported on Android")
    }
}

#[cfg(windows)]
mod platform {
    use anyhow::{Context, Result};
    use std::ffi::c_void;
    use winreg::{enums::KEY_SET_VALUE, enums::HKEY_CURRENT_USER, RegKey};

    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            internet: *mut c_void,
            option: u32,
            buffer: *mut c_void,
            buffer_length: u32,
        ) -> i32;
    }

    fn settings_key() -> Result<RegKey> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                KEY_SET_VALUE,
            )
            .context("opening Windows Internet Settings")
    }

    fn notify() -> Result<()> {
        // Both notifications must be attempted, even if the first one fails.
        let changed = unsafe {
            InternetSetOptionW(std::ptr::null_mut(), 39, std::ptr::null_mut(), 0)
        };
        let changed_error = (changed == 0).then(std::io::Error::last_os_error);
        let refreshed = unsafe {
            InternetSetOptionW(std::ptr::null_mut(), 37, std::ptr::null_mut(), 0)
        };
        if let Some(error) = changed_error {
            return Err(error).context("notifying Windows of proxy settings change");
        }
        if refreshed == 0 {
            return Err(std::io::Error::last_os_error()).context("refreshing Windows proxy settings");
        }
        Ok(())
    }

    pub fn enable(host: &str, port: u16) -> Result<()> {
        let key = settings_key()?;
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        key.set_value("ProxyServer", &format!("{host}:{port}"))?;
        key.set_value(
            "ProxyOverride",
            &"localhost;127.*;10.*;172.16.*;192.168.*;<local>",
        )?;
        key.set_value("ProxyEnable", &1u32)?;
        notify()
    }

    pub fn disable() -> Result<()> {
        settings_key()?.set_value("ProxyEnable", &0u32)?;
        notify()
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use anyhow::{bail, Context, Result};
    use std::process::Command;

    fn run(args: &[&str]) -> Result<String> {
        let output = Command::new("networksetup")
            .args(args)
            .output()
            .context("running networksetup")?;
        if !output.status.success() {
            bail!(
                "networksetup failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn services() -> Result<Vec<String>> {
        Ok(run(&["-listallnetworkservices"])?
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.is_empty()
                    && !line.starts_with('*')
                    && !line.starts_with("An asterisk")
            })
            .map(str::to_owned)
            .collect())
    }

    fn apply(host_port: Option<(&str, u16)>) -> Result<()> {
        let services = services()?;
        anyhow::ensure!(!services.is_empty(), "no enabled network services found");
        let mut errors = Vec::new();
        for service in services {
            for (set, state) in [
                ("-setwebproxy", "-setwebproxystate"),
                ("-setsecurewebproxy", "-setsecurewebproxystate"),
                ("-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
            ] {
                if let Some((host, port)) = host_port {
                    let port = port.to_string();
                    if let Err(error) = run(&[set, &service, host, &port]) {
                        errors.push(error.to_string());
                        continue;
                    }
                }
                let state_value = if host_port.is_some() { "on" } else { "off" };
                if let Err(error) = run(&[state, &service, state_value]) {
                    errors.push(error.to_string());
                }
            }
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("; "));
        }
        Ok(())
    }

    pub fn enable(host: &str, port: u16) -> Result<()> {
        apply(Some((host, port)))
    }

    pub fn disable() -> Result<()> {
        apply(None)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use anyhow::{bail, Result};
    use std::process::{Command, Stdio};

    fn run(tool: &str, args: &[&str]) -> bool {
        Command::new(tool)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn gsettings(schema: &str, key: &str, value: &str) -> bool {
        run("gsettings", &["set", schema, key, value])
    }

    fn quoted(value: &str) -> String {
        format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
    }

    fn gnome(host_port: Option<(&str, u16)>) -> bool {
        let mut success = true;
        if let Some((host, port)) = host_port {
            let host = quoted(host);
            let port = port.to_string();
            for schema in [
                "org.gnome.system.proxy.http",
                "org.gnome.system.proxy.https",
                "org.gnome.system.proxy.socks",
            ] {
                success &= gsettings(schema, "host", &host);
                success &= gsettings(schema, "port", &port);
            }
            // Do not activate partially written settings.
            if success {
                success &= gsettings("org.gnome.system.proxy", "mode", "'manual'");
            }
        } else {
            success = gsettings("org.gnome.system.proxy", "mode", "'none'");
        }
        success
    }

    fn kde(tool: &str, host_port: Option<(&str, u16)>) -> bool {
        let write = |key: &str, value: &str| {
            run(
                tool,
                &[
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    key,
                    value,
                ],
            )
        };
        let mut success = true;
        if let Some((host, port)) = host_port {
            let host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            let http = format!("http://{host}:{port}");
            let socks = format!("socks://{host}:{port}");
            success &= write("httpProxy", &http);
            success &= write("httpsProxy", &http);
            success &= write("socksProxy", &socks);
            success &= write("NoProxyFor", "localhost,127.0.0.1,::1");
            if success {
                success &= write("ProxyType", "1");
            }
        } else {
            success = write("ProxyType", "0");
        }
        success
    }

    fn apply(host_port: Option<(&str, u16)>) -> Result<()> {
        // Attempt every desktop backend; a missing tool is not fatal.
        let mut success = gnome(host_port);
        success |= kde("kwriteconfig5", host_port);
        success |= kde("kwriteconfig6", host_port);
        if !success {
            bail!("could not update system proxy using gsettings or kwriteconfig5/6");
        }
        Ok(())
    }

    pub fn enable(host: &str, port: u16) -> Result<()> {
        apply(Some((host, port)))
    }

    pub fn disable() -> Result<()> {
        apply(None)
    }
}

#[cfg(not(any(
    windows,
    target_os = "macos",
    target_os = "linux",
    target_os = "android"
)))]
mod platform {
    use anyhow::{bail, Result};

    pub fn enable(_host: &str, _port: u16) -> Result<()> {
        bail!("system proxy is not supported on this platform")
    }

    pub fn disable() -> Result<()> {
        bail!("system proxy is not supported on this platform")
    }
}

#[cfg(all(test, target_os = "android"))]
mod tests {
    #[test]
    fn system_proxy_is_unsupported() {
        for (host, port) in [("127.0.0.1", 10808), ("", 0)] {
            let error = super::enable(host, port).expect_err("unsupported");
            assert_eq!(error.to_string(), "not supported on Android");
        }
        let error = super::disable().expect_err("unsupported");
        assert_eq!(error.to_string(), "not supported on Android");
    }
}
