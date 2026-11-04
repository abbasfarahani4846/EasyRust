use easyvpn_core::{core, CoreKind, DefaultRoute, Profile, Protocol, ProxyMode, RoutingMode};
use eframe::egui::*;

use crate::{
    app::{mode_name, openvpn_install_hint, routing_name, App, Page},
    theme,
};

pub fn show(app: &mut App, ui: &mut Ui, ctx: &Context) {
    let previous = app.store.settings.clone();
    let mobile = app.platform.is_mobile();
    let supported = app.store.selected_profile().map(Profile::supported_cores)
        .unwrap_or_else(|| CoreKind::ALL.to_vec());
    let custom = app.store.selected_profile().and_then(|p| p.protocol) == Some(Protocol::Custom);
    let mut install = None;
    ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        let tunnel = app.store.settings.core.is_tunnel();
        theme::section(ui, "CONNECTION MODE");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            if mobile {
                ui.horizontal_wrapped(|ui| {
                    for (mode, label) in [
                        (ProxyMode::Tun, "VPN (whole device)"),
                        (ProxyMode::Local, "Proxy only"),
                    ] {
                        if theme::chip(ui, label, app.store.settings.mode == mode).clicked() {
                            app.store.settings.mode = mode;
                            app.store.settings.system_proxy = false;
                            app.store.settings.tun = false;
                        }
                    }
                });
                let explanation = if app.store.settings.mode == ProxyMode::Tun {
                    "Android VPN forwards selected apps through the local proxy. VPN permission is required."
                } else {
                    "Apps opt in using the local proxy port."
                };
                ui.label(RichText::new(explanation).size(11.0_f32).color(theme::MUTED));
                if custom {
                    ui.label(RichText::new(
                        "Raw config is used as-is. For VPN mode, provide a SOCKS inbound on the configured local port."
                    ).size(11.0_f32).color(theme::BLUE));
                }
            } else if tunnel {
                ui.label(RichText::new("Full-device tunnel").font(theme::semibold_font(14.0_f32)).color(theme::BLUE));
                ui.label(RichText::new("OpenVPN controls device routing. Run as Administrator/root.").size(12.0_f32).color(theme::MUTED));
            } else if custom {
                ui.label(RichText::new("Raw configuration is used as-is").color(theme::BLUE).size(13.0_f32));
                ui.label(RichText::new("Ports, routing, DNS and TUN are controlled by your configuration. Automatic system proxy and traffic statistics are disabled.").size(12.0_f32).color(theme::MUTED));
            } else {
                ui.horizontal_wrapped(|ui| {
                    for mode in [ProxyMode::Local, ProxyMode::System, ProxyMode::Tun] {
                        if theme::chip(ui, mode_name(mode), app.store.settings.mode == mode).clicked() {
                            app.store.settings.mode = mode;
                            app.store.settings.system_proxy = false;
                            app.store.settings.tun = false;
                        }
                    }
                });
                let explanation = match app.store.settings.mode {
                    ProxyMode::Local => "Apps opt in using the local proxy port.",
                    ProxyMode::System => "Local proxy plus your operating system's proxy settings.",
                    ProxyMode::Tun => "Route the whole device through TUN. Requires Administrator/root.",
                };
                ui.label(RichText::new(explanation).size(11.0_f32).color(theme::MUTED));
                if app.store.settings.mode == ProxyMode::Tun && app.store.settings.core == CoreKind::Xray {
                    ui.label(RichText::new("Xray uses a sing-box TUN helper. Both cores must be installed.")
                        .size(11.0_f32).color(theme::BLUE));
                }
            }
        });

        theme::section(ui, "CONNECTION");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            ui.label(RichText::new("Core").size(12.0_f32).color(theme::MUTED));
            ui.horizontal_wrapped(|ui| {
                for &kind in &supported {
                    if mobile && kind.is_tunnel() { continue; }
                    if theme::chip(ui, kind.name(), app.store.settings.core == kind).clicked() {
                        app.store.settings.core = kind;
                    }
                }
            });
            let kind = app.store.settings.core;
            if mobile && kind.is_tunnel() {
                ui.label(RichText::new("OpenVPN is not supported on Android.")
                    .size(11.0_f32).color(theme::MUTED));
            } else if !core::is_installed(kind) {
                if mobile {
                    ui.label(RichText::new("Bundled core is missing — reinstall the app.")
                        .size(11.0_f32).color(theme::RED));
                } else if kind.is_tunnel() {
                    ui.label(RichText::new(openvpn_install_hint()).size(11.0_f32).color(theme::MUTED));
                } else {
                    ui.add_enabled_ui(!app.installing && !app.connecting && app.process.is_none(), |ui| {
                        if theme::secondary(ui, &format!("Install {}", kind.name()), false).clicked() { install = Some(kind); }
                    });
                }
            }
            if !kind.is_tunnel() && !custom {
                theme::divider(ui);
                ui.label(RichText::new("Routing").size(12.0_f32).color(theme::MUTED));
                ui.horizontal_wrapped(|ui| {
                    for mode in [RoutingMode::Global, RoutingMode::BypassLan, RoutingMode::BypassIran] {
                        if theme::chip(ui, routing_name(mode), app.store.settings.routing == mode).clicked() {
                            app.store.settings.routing = mode;
                        }
                    }
                });
                theme::divider(ui);
                theme::settings_row(ui, "Local port", None, |ui| {
                    ui.scope(|ui| {
                        ui.visuals_mut().extreme_bg_color = theme::INPUT;
                        if mobile {
                            ui.spacing_mut().interact_size.y = 44.0_f32;
                        }
                        ui.add(DragValue::new(&mut app.store.settings.mixed_port).range(1..=65533).speed(1.0_f32));
                    });
                });
                if kind == CoreKind::Xray {
                    ui.label(RichText::new("SOCKS on this port · HTTP on port + 1").size(10.0_f32).color(theme::MUTED));
                }
            }
        });
        ui.label(RichText::new("Applies on next connect").size(11.0_f32).color(theme::MUTED));

        theme::section(ui, "ROUTING");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            let editable = !custom && !app.store.settings.core.is_tunnel();
            ui.add_enabled_ui(editable, |ui| {
                ui.label(RichText::new("Default route").size(12.0_f32).color(theme::MUTED));
                ui.horizontal_wrapped(|ui| {
                    for (route, label) in [
                        (DefaultRoute::Proxy, "Everything via VPN"),
                        (DefaultRoute::Direct, "Only selected via VPN"),
                    ] {
                        if theme::chip(ui, label, app.store.settings.default_route == route).clicked() {
                            app.store.settings.default_route = route;
                        }
                    }
                });
                theme::divider(ui);
                let label = format!("Rules ({})", app.store.settings.rules.len());
                if theme::secondary(ui, &label, false).clicked() {
                    app.page = Page::Rules;
                }
                theme::divider(ui);
                if theme::secondary(ui, "Bypass sources", false).clicked() {
                    app.page = Page::Sources;
                }
                ui.label(RichText::new(if mobile {
                    "App rules use Android package names. Block app rules are ignored."
                } else {
                    "App rules work in TUN mode"
                }).size(11.0_f32).color(theme::MUTED));
            });
            if !editable {
                ui.label(RichText::new("Routing is managed by your configuration.")
                    .size(11.0_f32).color(theme::MUTED));
            }
        });

        theme::section(ui, "CORES");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            for (index, kind) in CoreKind::ALL.into_iter()
                .filter(|kind| !mobile || !kind.is_tunnel()).enumerate()
            {
                ui.push_id(kind.name(), |ui| {
                    if index > 0 { theme::divider(ui); }
                    let installed = core::is_installed(kind);
                    let version = bundled_or_installed_version(kind, mobile);
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(vec2(8.0_f32, 8.0_f32), Sense::hover());
                        ui.painter().circle_filled(dot.center(), 4.0_f32, if installed { theme::GREEN } else { theme::MUTED });
                        ui.vertical(|ui| {
                            ui.label(RichText::new(kind.name()).font(theme::semibold_font(13.0_f32)));
                            ui.label(RichText::new(if installed {
                                version.as_deref().unwrap_or(if mobile { "Bundled" } else { "Installed" })
                            } else { "Not installed" }).size(10.0_f32).color(theme::MUTED));
                        });
                        if !mobile && !kind.is_tunnel() {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.add_enabled_ui(!app.installing && !app.connecting && app.process.is_none(), |ui| {
                                    if theme::secondary(ui, if installed { "Update" } else { "Install" }, false).clicked() {
                                        install = Some(kind);
                                    }
                                });
                            });
                        }
                    });
                    if !mobile && kind.is_tunnel() {
                        if installed {
                            ui.add(Label::new(RichText::new(core::binary_path(kind).display().to_string()).monospace().size(10.0_f32).color(theme::MUTED)).wrap());
                        } else {
                            ui.label(RichText::new(openvpn_install_hint()).size(11.0_f32).color(theme::MUTED));
                        }
                    }
                    if !mobile && app.installing_core == Some(kind) {
                        ui.add(Label::new(RichText::new(&app.install_progress).size(11.0_f32).color(theme::BLUE)).wrap());
                    }
                });
            }
            if mobile {
                ui.label(RichText::new("Cores are bundled with the app. Update the app to update cores.")
                    .size(11.0_f32).color(theme::MUTED));
            }
        });

        let editable = !custom && !app.store.settings.core.is_tunnel();
        theme::section(ui, "DNS");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            ui.add_enabled_ui(editable, |ui| {
                ui.label(RichText::new("Remote DNS").size(12.0_f32).color(theme::MUTED));
                theme::input(ui, &mut app.store.settings.remote_dns, "https://1.1.1.1/dns-query");
                ui.label(RichText::new("Direct DNS").size(12.0_f32).color(theme::MUTED));
                theme::input(ui, &mut app.store.settings.direct_dns, "8.8.8.8");
            });
            if !editable {
                ui.label(RichText::new("Managed by your configuration").size(11.0_f32).color(theme::MUTED));
            }
        });

        theme::section(ui, "ADVANCED");
        theme::card_frame().show(ui, |ui| {
            ui.set_min_width((ui.available_width() - 1.0_f32).max(0.0_f32));
            ui.add_enabled_ui(editable, |ui| {
                theme::settings_row(ui, "Allow LAN", Some("Expose the local proxy to your network"), |ui| {
                    theme::toggle(ui, &mut app.store.settings.allow_lan);
                });
                theme::divider(ui);
                ui.label(RichText::new("Listen address").size(12.0_f32).color(theme::MUTED));
                theme::input(ui, &mut app.store.settings.listen, "127.0.0.1");
                theme::divider(ui);
                ui.label(RichText::new("Log level").size(12.0_f32).color(theme::MUTED));
                ui.horizontal_wrapped(|ui| {
                    for level in ["debug", "info", "warning", "error", "none"] {
                        if theme::chip(ui, level, app.store.settings.log_level == level).clicked() {
                            app.store.settings.log_level = level.into();
                        }
                    }
                });
            });
        });
        ui.add_space(8.0_f32);
        let label = if mobile { "Disconnect" } else { "Disconnect & disable system proxy" };
        if theme::secondary(ui, label, true).clicked() { app.disconnect(); }
    });
    if previous != app.store.settings { app.save(); }
    if let Some(kind) = install { app.install_core(kind, ctx); }
    app.ensure_bypass_country(ctx);
}

fn bundled_or_installed_version(kind: CoreKind, mobile: bool) -> Option<String> {
    let mut paths = Vec::new();
    if mobile {
        if let Some(directory) = core::binary_path(kind).parent() {
            paths.push(directory.join(format!("{}.version.txt", kind.name())));
            paths.push(directory.join(kind.name()).join("version.txt"));
        }
        if let Some(directory) = std::env::var_os("EASYVPN_ASSET_DIR") {
            paths.push(std::path::PathBuf::from(directory)
                .join(kind.name()).join("version.txt"));
        }
    }
    paths.push(core::cores_dir().join(kind.name()).join("version.txt"));
    paths.into_iter().find_map(|path| {
        std::fs::read_to_string(path).ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}
