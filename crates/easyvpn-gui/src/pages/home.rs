use std::{f32::consts::TAU, time::{Duration, Instant}};

use easyvpn_core::{Protocol, ProxyMode};
use eframe::egui::{self, *};

use crate::{
    app::{address, mode_name, protocol_name, App, ConnState, Page},
    text::display_name,
    theme::{self, Icon},
    window::WindowState,
};

const LOST: Color32 = Color32::from_rgb(239, 68, 68);
const COMPACT_INFO_HEIGHT: f32 = 24.0_f32;
const FOOTER_HEIGHT: f32 = 36.0_f32;
const FOOTER_BOTTOM_PADDING: f32 = 10.0_f32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakpoint {
    Full,
    Medium,
    Compact,
    Mini,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Layout {
    pub breakpoint: Breakpoint,
    pub padding: f32,
    pub column_width: f32,
    pub power_diameter: f32,
    pub power_height: f32,
    pub status_height: f32,
    pub config_height: f32,
    pub stats_height: f32,
    pub gap: f32,
}

impl Layout {
    #[cfg(test)]
    pub fn total_height(self) -> f32 {
        self.status_height + self.power_height + self.config_height
            + self.stats_height + self.gap * 3.0_f32
    }
}

/// Height is the available body height after window controls and navigation.
pub fn layout_for(size: Vec2) -> Layout {
    let w = if size.x.is_finite() { size.x.max(0.0_f32) } else { 420.0_f32 };
    let h = if size.y.is_finite() { size.y.max(0.0_f32) } else { 650.0_f32 };
    let breakpoint = if h < 238.0_f32 {
        Breakpoint::Mini
    } else if h < 390.0_f32 {
        Breakpoint::Compact
    } else if h < 540.0_f32 {
        Breakpoint::Medium
    } else {
        Breakpoint::Full
    };
    let padding = if w < 360.0_f32 { 16.0_f32 } else { 20.0_f32 };
    let (power_diameter, ring_space, status_height, config_height, stats_height, gap) =
        match breakpoint {
            Breakpoint::Full => (190.0_f32, 56.0_f32, 66.0_f32, 84.0_f32, 214.0_f32, 8.0_f32),
            Breakpoint::Medium => (168.0_f32, 32.0_f32, 58.0_f32, 80.0_f32, 132.0_f32, 6.0_f32),
            Breakpoint::Compact => (148.0_f32, 20.0_f32, 48.0_f32, 76.0_f32, COMPACT_INFO_HEIGHT, 4.0_f32),
            Breakpoint::Mini => (44.0_f32, 0.0_f32, 0.0_f32, 0.0_f32, 0.0_f32, 0.0_f32),
        };
    Layout {
        breakpoint,
        padding,
        column_width: (w - padding * 2.0_f32).clamp(0.0_f32, 460.0_f32),
        power_diameter,
        power_height: if breakpoint == Breakpoint::Mini { 0.0_f32 } else { power_diameter + ring_space },
        status_height,
        config_height,
        stats_height,
        gap,
    }
}

pub fn speed(bytes: f64) -> String {
    if bytes >= 1024.0_f64 * 1024.0_f64 {
        format!("{:.1} MB/s", bytes / (1024.0_f64 * 1024.0_f64))
    } else {
        format!("{:.0} KB/s", bytes.max(0.0_f64) / 1024.0_f64)
    }
}

pub fn session(seconds: u64) -> String {
    format!("{:02}:{:02}:{:02}", seconds / 3600, seconds / 60 % 60, seconds % 60)
}

fn bytes(value: f64) -> String {
    if value >= 1024.0_f64.powi(3) {
        format!("{:.1} GB", value / 1024.0_f64.powi(3))
    } else if value >= 1024.0_f64.powi(2) {
        format!("{:.1} MB", value / 1024.0_f64.powi(2))
    } else {
        format!("{:.0} KB", value.max(0.0_f64) / 1024.0_f64)
    }
}

fn elapsed(app: &App) -> u64 {
    app.session_start.map(|t| t.elapsed().as_secs()).unwrap_or(0)
}

#[derive(Clone)]
struct SessionTraffic {
    session: Option<Instant>,
    sampled_at: Instant,
    upload: f64,
    download: f64,
}

/// UI estimates only; the core counters remain authoritative.
fn sample_session(app: &App, ctx: &Context) {
    let now = Instant::now();
    let id = Id::new("home-session-traffic");
    ctx.data_mut(|data| {
        let mut totals = data.get_temp::<SessionTraffic>(id).unwrap_or(SessionTraffic {
            session: app.session_start,
            sampled_at: now,
            upload: 0.0_f64,
            download: 0.0_f64,
        });
        if totals.session != app.session_start {
            totals = SessionTraffic {
                session: app.session_start,
                sampled_at: now,
                upload: 0.0_f64,
                download: 0.0_f64,
            };
        }
        let seconds = now.duration_since(totals.sampled_at).as_secs_f64().min(2.0_f64);
        if totals.session.is_some() {
            totals.upload += app.upload_speed.max(0.0_f64) * seconds;
            totals.download += app.download_speed.max(0.0_f64) * seconds;
        }
        totals.sampled_at = now;
        data.insert_temp(id, totals);
    });
}

fn home_mode_name(mobile: bool, mode: ProxyMode) -> &'static str {
    if mobile {
        match mode {
            ProxyMode::Tun | ProxyMode::System => "VPN",
            ProxyMode::Local => "Proxy only",
        }
    } else {
        mode_name(mode)
    }
}

fn state_text(app: &App) -> (&'static str, String) {
    match &app.conn_state {
        ConnState::Connecting { since } => (
            "CONNECTING…",
            if since.elapsed() >= Duration::from_secs(10) {
                "Starting core — please wait".into()
            } else {
                "Establishing secure tunnel".into()
            },
        ),
        ConnState::Verifying { attempt } => (
            "TESTING CONNECTION…", format!("Checking traffic · attempt {attempt} of 4"),
        ),
        ConnState::Connected { rtt_ms } => ("CONNECTED", format!("Verified · {rtt_ms} ms")),
        ConnState::Lost { .. } => ("CONNECTION LOST", "No traffic — retrying automatically".into()),
        ConnState::Failed => ("Connection failed", "Check your server or see Logs".into()),
        ConnState::Disconnected => {
            let suffix = if app.platform.is_mobile() {
                home_mode_name(true, app.store.settings.mode)
            } else if app.store.settings.core.is_tunnel() {
                "Full-device tunnel"
            } else if app.store.selected_profile().and_then(|p| p.protocol) == Some(Protocol::Custom) {
                "Custom config"
            } else {
                home_mode_name(false, app.store.settings.mode)
            };
            ("DISCONNECTED", format!("Tap to connect · {suffix}"))
        }
    }
}

fn accent(app: &App) -> Color32 {
    if matches!(app.conn_state, ConnState::Lost { .. })
        || app.failed_at.is_some_and(|time| time.elapsed() < Duration::from_secs(1))
    {
        LOST
    } else if app.conn_state.verified() {
        Color32::from_rgb(34, 197, 94)
    } else {
        Color32::from_rgb(59, 130, 246)
    }
}

fn power(app: &mut App, ui: &mut Ui, ctx: &Context, area: Rect, radius: f32, small: bool) {
    let connected = app.conn_state.verified();
    let connecting = app.conn_state.busy();
    let lost = matches!(app.conn_state, ConnState::Lost { .. });
    let failed_flash = app.failed_at.is_some_and(|time| time.elapsed() < Duration::from_secs(1));
    let center = area.center();
    let response = ui.interact(
        Rect::from_center_size(center, Vec2::splat(radius * 2.0_f32)),
        ui.id().with(if small { "mini-power" } else { "power" }),
        Sense::click(),
    );
    let time = ctx.input(|i| i.time) as f32;
    let pulse = if connected || lost {
        (time * 1.7_f32).sin() * 0.5_f32 + 0.5_f32
    } else { 0.0_f32 };
    let color = accent(app);
    let p = ui.painter();
    let room = (area.height().min(area.width()) / 2.0_f32 - radius - 2.0_f32).max(0.0_f32);
    let outer = room.min(28.0_f32);
    let inner = outer / 2.0_f32;
    if !small {
        let glow = p.with_clip_rect(area.intersect(p.clip_rect()));
        theme::halo(&glow, center, radius, color, if connected || lost { 23 } else { 16 });
        for (offset, alpha) in [(inner, 23.0_f32), (outer, 15.0_f32)] {
            p.circle_stroke(center, radius + offset, Stroke::new(
                if lost { 2.0_f32 } else { 1.0_f32 },
                Color32::from_rgba_unmultiplied(
                    color.r(), color.g(), color.b(), (alpha + pulse * 8.0_f32) as u8,
                ),
            ));
        }
    }
    if connecting {
        theme::arc(
            p, center, radius + if small { 3.0_f32 } else { inner },
            time * 3.0_f32, time * 3.0_f32 + TAU * 0.23_f32,
            Stroke::new(2.0_f32, theme::BLUE),
        );
    }
    if lost || failed_flash {
        p.circle_stroke(center, radius + if small { 3.0_f32 } else { inner },
            Stroke::new(2.0_f32, LOST));
    }
    let (top, bottom) = if lost {
        (LOST, Color32::from_rgb(185, 28, 28))
    } else if connected {
        (
            if response.hovered() { Color32::from_rgb(47, 211, 108) }
            else { Color32::from_rgb(34, 197, 94) },
            Color32::from_rgb(22, 163, 74),
        )
    } else {
        (
            if response.hovered() { Color32::from_rgb(72, 141, 250) }
            else { Color32::from_rgb(59, 130, 246) },
            Color32::from_rgb(29, 78, 216),
        )
    };
    theme::disc(p, center, radius, top, bottom);
    p.circle_stroke(center, radius, Stroke::new(
        1.0_f32, Color32::from_rgba_unmultiplied(220, 240, 255, 48),
    ));
    if small {
        theme::arc(
            p, center, 8.0_f32, -std::f32::consts::FRAC_PI_2 + 0.55_f32,
            std::f32::consts::PI * 1.5_f32 - 0.55_f32,
            Stroke::new(2.5_f32, Color32::WHITE),
        );
        p.line_segment(
            [center - vec2(0.0_f32, 12.0_f32), center - vec2(0.0_f32, 2.0_f32)],
            Stroke::new(2.5_f32, Color32::WHITE),
        );
    } else {
        theme::power_icon(p, center - vec2(0.0_f32, 10.0_f32));
        theme::bold_text(
            p, center + vec2(0.0_f32, 31.0_f32), Align2::CENTER_CENTER,
            if connecting { "CANCEL" } else if connected || lost { "STOP" } else { "START" },
            15.0_f32, Color32::WHITE,
        );
    }
    if response.clicked()
        && response.interact_pointer_pos().is_some_and(|pos| pos.distance(center) <= radius)
    {
        app.toggle_connection(ctx);
    }
    if connected || connecting || lost || failed_flash {
        ctx.request_repaint_after(Duration::from_millis(16));
    }
}

pub fn show(app: &mut App, ui: &mut Ui, ctx: &Context) {
    sample_session(app, ctx);
    let mut layout = layout_for(vec2(ctx.screen_rect().width(), ui.available_height()));
    if layout.breakpoint == Breakpoint::Mini {
        layout = layout_for(vec2(ctx.screen_rect().width(), 238.0_f32));
    }
    let full = layout.breakpoint == Breakpoint::Full;
    ScrollArea::vertical().id_salt("home-body").auto_shrink([false, false]).show(ui, |ui| {
        ui.spacing_mut().item_spacing.y = 0.0_f32;
        let (heading, subtitle) = state_text(app);
        let (status, response) = ui.allocate_exact_size(
            vec2(ui.available_width(), layout.status_height), Sense::hover(),
        );
        centered_elided(
            ui.painter(),
            Rect::from_min_max(
                status.min + vec2(0.0_f32, 2.0_f32),
                pos2(status.right(), status.top() + 29.0_f32),
            ),
            heading, theme::bold_font(if full { 23.0_f32 } else { 22.0_f32 }),
            if matches!(app.conn_state, ConnState::Lost { .. }) { LOST } else { theme::TEXT },
        );
        centered_elided(
            ui.painter(),
            Rect::from_min_max(
                pos2(status.left(), status.top() + if full { 38.0_f32 } else { 29.0_f32 }),
                status.max,
            ),
            &subtitle, FontId::proportional(if full { 14.0_f32 } else { 12.0_f32 }),
            theme::MUTED,
        );
        response.on_hover_text(format!("{heading}\n{subtitle}"));
        ui.add_space(layout.gap);
        let (area, _) = ui.allocate_exact_size(
            vec2(ui.available_width(), layout.power_height), Sense::hover(),
        );
        power(app, ui, ctx, area, layout.power_diameter / 2.0_f32, false);
        ui.add_space(layout.gap);
        config(app, ui, layout.config_height);
        ui.add_space(layout.gap);
        stats(app, ui, layout);
    });
}

fn centered_elided(p: &Painter, rect: Rect, text: &str, font: FontId, color: Color32) {
    let mut job = egui::text::LayoutJob::simple(text.to_owned(), font, color, rect.width().max(1.0_f32));
    job.wrap.max_rows = 1;
    job.wrap.overflow_character = Some('…');
    let galley = p.layout_job(job);
    p.galley(pos2(rect.center().x - galley.size().x / 2.0_f32, rect.top()), galley, color);
}

fn config(app: &mut App, ui: &mut Ui, height: f32) {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), height), Sense::click());
    let p = ui.painter();
    theme::card(p, rect);
    let tile = Rect::from_center_size(
        pos2(rect.left() + 38.0_f32, rect.center().y), vec2(44.0_f32, 44.0_f32),
    );
    p.rect_filled(tile, 12.0_f32, Color32::from_rgb(24, 40, 69));
    let profile = app.store.selected_profile();
    let name = display_name(profile.map(|p| {
        if p.name.is_empty() { "(unnamed)" } else { &p.name }
    }).unwrap_or("No config — tap + to add"));
    let drawn = name.country().is_some_and(|code| app.flags.draw(
        ui, Rect::from_center_size(tile.center(), vec2(28.0_f32, 20.0_f32)), code,
    ));
    if !drawn { theme::icon(p, tile.center(), Icon::Server, 25.0_f32, theme::BLUE); }
    let left = tile.right() + 12.0_f32;
    let right = rect.right() - 35.0_f32;
    theme::text(p, pos2(left, rect.top() + 9.0_f32), Align2::LEFT_TOP,
        "Current config", 11.0_f32, theme::MUTED);
    theme::elided_with_font(
        p, Rect::from_min_max(
            pos2(left, rect.top() + 24.0_f32), pos2(right, rect.top() + 48.0_f32),
        ),
        &name.text, theme::bold_font(16.0_f32), theme::TEXT,
    );
    let description = profile.map(|p| format!("{} · {}", protocol_name(p.protocol), address(p)))
        .unwrap_or_default();
    theme::elided(
        p, Rect::from_min_max(
            pos2(left, rect.top() + 49.0_f32), pos2(right, rect.bottom() - 5.0_f32),
        ), &description, 11.0_f32, theme::MUTED,
    );
    theme::icon(p, pos2(rect.right() - 20.0_f32, rect.center().y),
        Icon::Chevron, 24.0_f32, theme::BLUE);
    if response.on_hover_text(format!("{}\n{description}", name.text)).clicked() {
        app.page = Page::Servers;
    }
}

fn location_line(app: &mut App, ui: &Ui, rect: Rect, font_size: f32) {
    let mut left = rect.left();
    if !app.location_country_code.is_empty() {
        app.flags.draw(
            ui, Rect::from_center_size(
                pos2(left + 11.0_f32, rect.center().y), vec2(22.0_f32, 16.0_f32),
            ), &app.location_country_code,
        );
        left += 28.0_f32;
    }
    theme::elided(ui.painter(), Rect::from_min_max(pos2(left, rect.top()), rect.max),
        &app.location, font_size, theme::MUTED);
}

/// One layout job owns the entire line so its ellipsis accounts for both the
/// prefix and the IP. A fixed-width blank section reserves the inline flag.
fn compact_info(app: &mut App, ui: &mut Ui, height: f32) {
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.available_width(), height), Sense::hover(),
    );
    let prefix = format!("{} · ↓ {} ↑ {} · ",
        session(elapsed(app)), speed(app.download_speed), speed(app.upload_speed));
    let location = if app.location_country_code.is_empty() {
        app.location.as_str()
    } else {
        app.location.rsplit_once(" · ").map(|(_, ip)| ip).unwrap_or(&app.location)
    };
    let font = FontId::proportional(10.0_f32);
    let format = egui::text::TextFormat::simple(font.clone(), theme::MUTED);
    let mut job = egui::text::LayoutJob::default();
    job.append(&prefix, 0.0_f32, format.clone());
    let flag_width = if app.location_country_code.is_empty() { 0.0_f32 } else { 26.0_f32 };
    job.append(location, flag_width, format);
    job.wrap.max_width = rect.width().max(1.0_f32);
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job.wrap.overflow_character = Some('…');
    let galley = ui.painter().layout_job(job);
    let origin = rect.left_center() - vec2(0.0_f32, galley.size().y / 2.0_f32);
    let prefix_width = ui.painter().layout_no_wrap(prefix.clone(), font, theme::MUTED).size().x;
    ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()))
        .galley(origin, galley, theme::MUTED);
    // Do not paint a flag on top of the overflow character if the prefix alone
    // has consumed the line.
    if flag_width > 0.0_f32 && prefix_width + flag_width + 12.0_f32 < rect.width() {
        app.flags.draw(ui, Rect::from_center_size(
            pos2(rect.left() + prefix_width + 11.0_f32, rect.center().y),
            vec2(22.0_f32, 16.0_f32),
        ), &app.location_country_code);
    }
    response.on_hover_text(format!("{prefix}{}\n{}", app.location, app.location_detail));
}

fn footer_rect(rect: Rect) -> Rect {
    Rect::from_min_max(
        pos2(rect.left() + 12.0_f32, rect.bottom() - FOOTER_HEIGHT + 4.0_f32),
        pos2(rect.right() - 12.0_f32, rect.bottom() - FOOTER_BOTTOM_PADDING),
    )
}

fn stats(app: &mut App, ui: &mut Ui, layout: Layout) {
    if layout.breakpoint == Breakpoint::Compact {
        compact_info(app, ui, layout.stats_height);
        return;
    }
    let full = layout.breakpoint == Breakpoint::Full;
    let (rect, response) = ui.allocate_exact_size(
        vec2(ui.available_width(), layout.stats_height), Sense::hover(),
    );
    let p = ui.painter();
    theme::card(p, rect);
    let values = if full {
        vec![
            (Icon::Clock, "Session Time", session(elapsed(app)), theme::MUTED),
            (Icon::Down, "Download", speed(app.download_speed), theme::GREEN),
            (Icon::Up, "Upload", speed(app.upload_speed), theme::BLUE),
            (Icon::Pin, "Location", app.location.clone(), theme::MUTED),
        ]
    } else {
        vec![
            (Icon::Clock, "Session Time", session(elapsed(app)), theme::MUTED),
            (Icon::Down, "Traffic", format!("↓ {} ↑ {}",
                speed(app.download_speed), speed(app.upload_speed)), theme::GREEN),
            (Icon::Pin, "Location", app.location.clone(), theme::MUTED),
        ]
    };
    let footer = if full { FOOTER_HEIGHT } else { 0.0_f32 };
    let row_height = (rect.height() - 16.0_f32 - footer) / values.len() as f32;
    for (index, (icon, label, value, color)) in values.iter().enumerate() {
        let y = rect.top() + 8.0_f32 + row_height * (index as f32 + 0.5_f32);
        theme::icon(p, pos2(rect.left() + 24.0_f32, y), *icon, 19.0_f32, *color);
        theme::text(p, pos2(rect.left() + 44.0_f32, y), Align2::LEFT_CENTER,
            label, if !full && index == 1 { 11.0_f32 } else { 12.0_f32 }, theme::MUTED);
        let right = rect.right() - 16.0_f32;
        let location = index == values.len() - 1;
        let flag_space = if location && !app.location_country_code.is_empty() { 28.0_f32 } else { 0.0_f32 };
        let label_width = if !full && index == 1 { 89.0_f32 } else { 120.0_f32 };
        let width = (rect.width() - label_width - 16.0_f32 - flag_space).max(20.0_f32);
        let mut job = egui::text::LayoutJob::simple(
            value.clone(), theme::bold_font(if !full && index == 1 { 10.0_f32 } else { 12.0_f32 }),
            theme::TEXT, width,
        );
        job.wrap.max_rows = 1;
        job.wrap.overflow_character = Some('…');
        let galley = p.layout_job(job);
        let left = right - galley.size().x;
        if flag_space > 0.0_f32 {
            app.flags.draw(ui, Rect::from_center_size(
                pos2(left - 17.0_f32, y), vec2(22.0_f32, 16.0_f32),
            ), &app.location_country_code);
        }
        p.galley(pos2(left, y - galley.size().y / 2.0_f32), galley, theme::TEXT);
        if index < values.len() - 1 {
            let divider = y + row_height / 2.0_f32;
            p.line_segment(
                [pos2(rect.left() + 18.0_f32, divider), pos2(right, divider)],
                Stroke::new(1.0_f32, theme::BORDER),
            );
        }
    }
    if full {
        let totals = ui.ctx().data(|data| data.get_temp::<SessionTraffic>(Id::new("home-session-traffic")));
        let line = totals.map(|t| format!("Session ≈ ↓ {} ↑ {}", bytes(t.download), bytes(t.upload)))
            .unwrap_or_else(|| "Session ↓ 0 KB ↑ 0 KB".into());
        centered_elided(p, footer_rect(rect), &line, FontId::proportional(10.0_f32), theme::MUTED);
    }
    response.on_hover_text(format!("{}\n{}\nSession totals are estimated from speed samples",
        app.location, app.location_detail));
}

pub fn mini(app: &mut App, ui: &mut Ui, ctx: &Context) {
    sample_session(app, ctx);
    let viewport = ui.max_rect();
    let bar = if app.window.mini { viewport } else {
        Rect::from_center_size(viewport.center(), vec2(
            (viewport.width() - 24.0_f32).clamp(0.0_f32, 460.0_f32),
            96.0_f32.min(viewport.height()),
        ))
    };
    theme::card(ui.painter(), bar);
    let drag = ui.interact(bar, ui.id().with("mini-drag"), Sense::click_and_drag());
    if drag.double_clicked() {
        app.window.restore(ctx);
    } else if drag.drag_started_by(PointerButton::Primary) && WindowState::can_drag(ctx) {
        ctx.send_viewport_cmd(ViewportCommand::StartDrag);
    }
    let name = display_name(app.store.selected_profile().map(|p| p.name.as_str())
        .unwrap_or("No configuration"));
    let flag = Rect::from_center_size(
        pos2(bar.left() + 23.0_f32, bar.center().y), vec2(22.0_f32, 16.0_f32),
    );
    if !name.country().is_some_and(|code| app.flags.draw(ui, flag, code)) {
        theme::icon(ui.painter(), flag.center(), Icon::Server, 22.0_f32, theme::BLUE);
    }
    let expand = Rect::from_center_size(
        pos2(bar.right() - 22.0_f32, bar.center().y), Vec2::splat(30.0_f32),
    );
    let button = Rect::from_center_size(
        pos2(expand.left() - 28.0_f32, bar.center().y), Vec2::splat(44.0_f32),
    );
    let left = bar.left() + 42.0_f32;
    let right = button.left() - 8.0_f32;
    let top = bar.center().y - 34.0_f32;
    let row = |index: f32| Rect::from_min_max(
        pos2(left, top + index * 17.0_f32), pos2(right, top + (index + 1.0_f32) * 17.0_f32),
    );
    theme::elided_with_font(ui.painter(), row(0.0_f32), &name.text,
        theme::bold_font(13.0_f32), theme::TEXT);
    let (status, color) = match &app.conn_state {
        ConnState::Connected { rtt_ms } => (format!("Connected · {rtt_ms} ms"), theme::GREEN),
        ConnState::Lost { .. } => ("CONNECTION LOST".into(), LOST),
        ConnState::Connecting { .. } | ConnState::Verifying { .. } => ("Connecting…".into(), theme::BLUE),
        ConnState::Failed => ("Connection failed".into(), theme::RED),
        ConnState::Disconnected => ("Not connected".into(), theme::MUTED),
    };
    let state_row = row(1.0_f32);
    ui.painter().circle_filled(pos2(left + 3.0_f32, state_row.center().y), 3.0_f32, color);
    theme::elided(ui.painter(), Rect::from_min_max(
        state_row.min + vec2(12.0_f32, 0.0_f32), state_row.max,
    ), &status, 11.0_f32, color);
    let rates = format!("↓ {} ↑ {}", speed(app.download_speed), speed(app.upload_speed));
    theme::elided(ui.painter(), row(2.0_f32), &rates, 10.0_f32, theme::MUTED);
    location_line(app, ui, row(3.0_f32), 10.0_f32);
    ui.interact(Rect::from_min_max(row(0.0_f32).min, row(3.0_f32).max),
        ui.id().with("mini-details"), Sense::hover())
        .on_hover_text(format!("{}\n{status}\n{rates}\n{}\n{}",
            name.text, app.location, app.location_detail));
    power(app, ui, ctx, button, 22.0_f32, true);
    ui.allocate_new_ui(UiBuilder::new().max_rect(expand), |ui| {
        if theme::expand_control(ui).on_hover_text("Restore full window · Escape").clicked() {
            app.window.restore(ctx);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_mode_names_follow_platform() {
        assert_eq!(home_mode_name(true, ProxyMode::Tun), "VPN");
        assert_eq!(home_mode_name(true, ProxyMode::Local), "Proxy only");
        assert_eq!(home_mode_name(false, ProxyMode::Local), "Local proxy");
        assert_eq!(home_mode_name(false, ProxyMode::System), "System proxy");
        assert_eq!(home_mode_name(false, ProxyMode::Tun), "TUN");
    }

    #[test]
    fn formats_speed_session_and_totals() {
        assert_eq!(speed(0.0_f64), "0 KB/s");
        assert_eq!(speed(320.0_f64 * 1024.0_f64), "320 KB/s");
        assert_eq!(speed(2.4_f64 * 1024.0_f64 * 1024.0_f64), "2.4 MB/s");
        assert_eq!(session(3661), "01:01:01");
        assert_eq!(bytes(1024.0_f64.powi(3)), "1.0 GB");
    }

    #[test]
    fn breakpoint_boundaries_use_body_height() {
        for (height, expected, diameter) in [
            (237.0_f32, Breakpoint::Mini, 44.0_f32),
            (238.0_f32, Breakpoint::Compact, 148.0_f32),
            (389.0_f32, Breakpoint::Compact, 148.0_f32),
            (390.0_f32, Breakpoint::Medium, 168.0_f32),
            (539.0_f32, Breakpoint::Medium, 168.0_f32),
            (540.0_f32, Breakpoint::Full, 190.0_f32),
        ] {
            let layout = layout_for(vec2(420.0_f32, height));
            assert_eq!(layout.breakpoint, expected);
            assert_eq!(layout.power_diameter, diameter);
        }
    }

    #[test]
    fn compact_counts_one_complete_info_line() {
        let layout = layout_for(vec2(400.0_f32, 348.0_f32));
        assert_eq!(layout.breakpoint, Breakpoint::Compact);
        assert_eq!(layout.stats_height, COMPACT_INFO_HEIGHT);
        assert_eq!(layout.total_height(), 328.0_f32);
        assert!(layout.total_height() <= 348.0_f32);
        assert_eq!(
            layout.total_height(),
            layout.status_height + layout.power_height + layout.config_height
                + COMPACT_INFO_HEIGHT + 3.0_f32 * layout.gap,
        );
    }

    #[test]
    fn full_footer_has_ten_pixels_of_bottom_padding() {
        let card = Rect::from_min_size(pos2(20.0_f32, 500.0_f32), vec2(380.0_f32, 214.0_f32));
        let footer = footer_rect(card);
        assert_eq!(card.bottom() - footer.bottom(), 10.0_f32);
        assert!(footer.height() >= 16.0_f32);
        assert!(card.contains_rect(footer));
        let last_row_bottom = card.bottom() - 8.0_f32 - FOOTER_HEIGHT;
        assert!(footer.top() > last_row_bottom);
    }

    #[test]
    fn short_bodies_scroll_instead_of_shrinking_or_hiding_information() {
        for height in 238..2000 {
            let layout = layout_for(vec2(300.0_f32, height as f32));
            assert!(layout.power_diameter >= 140.0_f32);
            assert!(layout.power_height >= layout.power_diameter);
            assert!(layout.status_height >= 48.0_f32);
            assert!(layout.config_height >= 76.0_f32);
            assert!(layout.stats_height >= COMPACT_INFO_HEIGHT);
            assert!(layout.total_height().is_finite());
        }
        assert!(layout_for(vec2(300.0_f32, 238.0_f32)).total_height() > 238.0_f32);
        assert!(layout_for(vec2(420.0_f32, 650.0_f32)).total_height() <= 650.0_f32);
    }

    #[test]
    fn geometry_remains_finite_and_bounded() {
        for size in [
            Vec2::ZERO, vec2(340.0_f32, 96.0_f32), vec2(300.0_f32, 244.0_f32),
            vec2(2000.0_f32, 2000.0_f32), vec2(f32::NAN, f32::INFINITY),
            vec2(-20.0_f32, -10.0_f32),
        ] {
            let layout = layout_for(size);
            assert!(layout.total_height().is_finite());
            assert!((0.0_f32..=460.0_f32).contains(&layout.column_width));
            assert!((44.0_f32..=190.0_f32).contains(&layout.power_diameter));
        }
    }

    #[test]
    fn columns_stay_bounded_and_padding_adapts() {
        assert_eq!(layout_for(vec2(420.0_f32, 650.0_f32)).column_width, 380.0_f32);
        assert_eq!(layout_for(vec2(1200.0_f32, 900.0_f32)).column_width, 460.0_f32);
        let small = layout_for(vec2(300.0_f32, 300.0_f32));
        assert_eq!(small.padding, 16.0_f32);
        assert_eq!(small.column_width, 268.0_f32);
    }
}
