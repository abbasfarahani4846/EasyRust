use eframe::egui::{self, epaint::Vertex, *};
use std::f32::consts::{PI, TAU};

pub const BG: Color32 = Color32::from_rgb(10, 15, 28);
pub const CARD: Color32 = Color32::from_rgba_premultiplied(14, 20, 33, 217);
pub const BORDER: Color32 = Color32::from_rgb(31, 42, 64);
pub const TEXT: Color32 = Color32::from_rgb(243, 246, 252);
pub const MUTED: Color32 = Color32::from_rgb(138, 148, 168);
pub const BLUE: Color32 = Color32::from_rgb(96, 165, 250);
pub const CYAN: Color32 = Color32::from_rgb(34, 211, 238);
pub const GREEN: Color32 = Color32::from_rgb(52, 211, 153);
pub const RED: Color32 = Color32::from_rgb(248, 113, 113);
pub const AMBER: Color32 = Color32::from_rgb(251, 191, 36);
pub const GLASS: Color32 = Color32::from_rgb(26, 34, 54);
pub const INPUT: Color32 = Color32::from_rgb(13, 20, 36);
pub const MENU_WIDTH: f32 = 226.0_f32;

include!(concat!(env!("OUT_DIR"), "/fonts.rs"));
const EMOJI_FONT: &str = "easyvpn-noto-emoji";
const EMOJI_FONT_BYTES: &[u8] = include_bytes!("../assets/fonts/NotoEmoji-Regular.ttf");

pub fn set_mobile(ctx: &Context, mobile: bool, top: f32, bottom: f32) {
    ctx.data_mut(|data| data.insert_temp(Id::new("platform-mobile-metrics"), (mobile, top, bottom)));
}

fn mobile_metrics(ctx: &Context) -> (bool, f32, f32) {
    ctx.data(|data| data.get_temp::<(bool, f32, f32)>(Id::new("platform-mobile-metrics"))
        .unwrap_or((false, 0.0_f32, 0.0_f32)))
}

fn touch_height(ui: &Ui, desktop: f32) -> f32 {
    if mobile_metrics(ui.ctx()).0 { desktop.max(44.0_f32) } else { desktop }
}

#[derive(Clone, Copy)]
pub enum Icon {
    Plus, Menu, Back, Server, Clock, Down, Up, Pin, Chevron, Clipboard,
    File, Text, Link, Gear, Terminal, Info, Refresh, Trash, Copy, Lightning,
    More, Check, Camera,
}

pub fn bold_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("bold".into()))
}

pub fn semibold_font(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semibold".into()))
}

fn configured_fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    for (name, bytes) in [
        ("inter-regular", include_bytes!("../assets/fonts/Inter-400.ttf").as_slice()),
        ("inter-semibold", include_bytes!("../assets/fonts/Inter-600.ttf").as_slice()),
        ("inter-bold", include_bytes!("../assets/fonts/Inter-700.ttf").as_slice()),
    ] {
        fonts.font_data.insert(name.into(), FontData::from_static(bytes).into());
    }
    fonts.font_data.insert(EMOJI_FONT.into(), FontData::from_static(EMOJI_FONT_BYTES).into());
    for name in ["Vazirmatn-400", "Vazirmatn-700"] {
        if let Some(bytes) = font_bytes(name) {
            fonts.font_data.insert(name.into(), FontData::from_static(bytes).into());
        }
    }
    let mut arabic_fallback = None;
    if !fonts.font_data.contains_key("Vazirmatn-400") || !fonts.font_data.contains_key("Vazirmatn-700") {
        for path in [
            r"C:\Windows\Fonts\tahoma.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        ] {
            if let Ok(bytes) = std::fs::read(path) {
                fonts.font_data.insert("arabic-system-fallback".into(), FontData::from_owned(bytes).into());
                arabic_fallback = Some("arabic-system-fallback".to_owned());
                break;
            }
        }
    }
    let original = fonts.families.clone();
    let proportional = original.get(&FontFamily::Proportional).cloned().unwrap_or_default();
    for (family, latin, arabic, defaults) in [
        (FontFamily::Proportional, "inter-regular", "Vazirmatn-400", proportional.clone()),
        (FontFamily::Name("semibold".into()), "inter-semibold", "Vazirmatn-700", proportional.clone()),
        (FontFamily::Name("bold".into()), "inter-bold", "Vazirmatn-700", proportional),
    ] {
        let mut chain = vec![latin.to_owned()];
        if fonts.font_data.contains_key(arabic) { chain.push(arabic.to_owned()); }
        else if let Some(name) = &arabic_fallback { chain.push(name.clone()); }
        chain.push(EMOJI_FONT.to_owned());
        chain.extend(defaults);
        fonts.families.insert(family, chain);
    }
    if let Some(defaults) = original.get(&FontFamily::Monospace) {
        let mut chain = Vec::new();
        if let Some(first) = defaults.first() { chain.push(first.clone()); }
        if fonts.font_data.contains_key("Vazirmatn-400") { chain.push("Vazirmatn-400".into()); }
        else if let Some(name) = arabic_fallback { chain.push(name); }
        chain.push(EMOJI_FONT.to_owned());
        chain.extend(defaults.iter().skip(1).cloned());
        fonts.families.insert(FontFamily::Monospace, chain);
    }
    fonts
}

pub fn setup(ctx: &Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = Visuals::dark();
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = Color32::from_rgb(17, 24, 39);
    style.visuals.window_stroke = Stroke::new(1.0_f32, BORDER);
    style.visuals.window_rounding = Rounding::same(18.0_f32);
    for widget in [&mut style.visuals.widgets.inactive, &mut style.visuals.widgets.noninteractive] {
        widget.bg_fill = GLASS;
        widget.weak_bg_fill = GLASS;
        widget.bg_stroke = Stroke::new(1.0_f32, BORDER);
        widget.rounding = Rounding::same(14.0_f32);
    }
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(35, 51, 79);
    style.visuals.widgets.hovered.rounding = Rounding::same(14.0_f32);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(29, 78, 216);
    style.visuals.selection.bg_fill = Color32::from_rgb(29, 64, 117);
    style.spacing.item_spacing = vec2(8.0_f32, 10.0_f32);
    style.spacing.button_padding = vec2(12.0_f32, 8.0_f32);
    ctx.set_style(style);
    ctx.set_fonts(configured_fonts());
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let channel = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgba_unmultiplied(channel(a.r(), b.r()), channel(a.g(), b.g()), channel(a.b(), b.b()), channel(a.a(), b.a()))
}

fn finite_position(pos: Pos2) -> bool { pos.x.is_finite() && pos.y.is_finite() }
fn usable_rect(rect: Rect) -> bool {
    finite_position(rect.min) && finite_position(rect.max)
        && rect.width().is_finite() && rect.height().is_finite()
        && rect.width() > 0.0_f32 && rect.height() > 0.0_f32
}
fn usable_mesh(mesh: &Mesh) -> bool {
    mesh.is_valid() && !mesh.indices.is_empty()
        && mesh.vertices.iter().all(|v| finite_position(v.pos) && finite_position(v.uv))
}
fn submit_mesh(p: &Painter, mesh: Mesh) {
    if usable_mesh(&mesh) { p.add(Shape::mesh(mesh)); }
}

fn gradient_mesh(rect: Rect, radius: f32, top: Color32, bottom: Color32) -> Option<Mesh> {
    if !usable_rect(rect) || !radius.is_finite() || radius < 0.0_f32 { return None; }
    let radius = radius.min(rect.width() / 2.0_f32).min(rect.height() / 2.0_f32);
    let color_at = |y: f32| blend(top, bottom, ((y - rect.top()) / rect.height()).clamp(0.0_f32, 1.0_f32));
    let mut mesh = Mesh::default();
    mesh.vertices.push(Vertex { pos: rect.center(), uv: egui::epaint::WHITE_UV, color: color_at(rect.center().y) });
    for (center, start) in [
        (pos2(rect.right() - radius, rect.top() + radius), -PI / 2.0_f32),
        (pos2(rect.right() - radius, rect.bottom() - radius), 0.0_f32),
        (pos2(rect.left() + radius, rect.bottom() - radius), PI / 2.0_f32),
        (pos2(rect.left() + radius, rect.top() + radius), PI),
    ] {
        for i in 0..=12 {
            let angle = start + i as f32 / 12.0_f32 * PI / 2.0_f32;
            let pos = center + vec2(angle.cos(), angle.sin()) * radius;
            mesh.vertices.push(Vertex { pos, uv: egui::epaint::WHITE_UV, color: color_at(pos.y) });
        }
    }
    let count = mesh.vertices.len() as u32 - 1;
    for i in 1..=count { mesh.indices.extend([0, i, if i == count { 1 } else { i + 1 }]); }
    Some(mesh)
}

pub fn gradient(p: &Painter, rect: Rect, radius: f32, top: Color32, bottom: Color32) {
    if let Some(mesh) = gradient_mesh(rect, radius, top, bottom) { submit_mesh(p, mesh); }
}
pub fn background(p: &Painter, rect: Rect) {
    if !usable_rect(rect) { return; }
    let rect = rect.shrink(0.5_f32);
    if !usable_rect(rect) { return; }
    gradient(p, rect, 18.0_f32, BG, Color32::from_rgb(7, 11, 20));
    p.rect_stroke(rect, 18.0_f32, Stroke::new(1.0_f32, BORDER));
}
pub fn card(p: &Painter, rect: Rect) {
    if usable_rect(rect) { p.rect(rect, 18.0_f32, CARD, Stroke::new(1.0_f32, BORDER)); }
}
pub fn card_frame() -> Frame {
    Frame::none().fill(CARD).stroke(Stroke::new(1.0_f32, BORDER)).rounding(18.0_f32).inner_margin(16.0_f32)
}
fn disc_mesh(center: Pos2, radius: f32, top: Color32, bottom: Color32) -> Option<Mesh> {
    if !finite_position(center) || !radius.is_finite() || radius <= 0.0_f32 { return None; }
    let mut mesh = Mesh::default();
    mesh.vertices.push(Vertex { pos: center, uv: egui::epaint::WHITE_UV, color: blend(top, bottom, 0.5_f32) });
    for i in 0..=96_u32 {
        let angle = TAU * i as f32 / 96.0_f32;
        let offset = vec2(angle.cos(), angle.sin()) * radius;
        mesh.vertices.push(Vertex { pos: center + offset, uv: egui::epaint::WHITE_UV,
            color: blend(top, bottom, (offset.y / radius + 1.0_f32) * 0.5_f32) });
        if i > 0 { mesh.indices.extend([0, i, i + 1]); }
    }
    Some(mesh)
}
pub fn disc(p: &Painter, center: Pos2, radius: f32, top: Color32, bottom: Color32) {
    if let Some(mesh) = disc_mesh(center, radius, top, bottom) { submit_mesh(p, mesh); }
}
fn halo_mesh(center: Pos2, radius: f32, color: Color32, alpha: u8) -> Option<Mesh> {
    if !finite_position(center) || !radius.is_finite() || radius <= 0.0_f32 { return None; }
    const SEGMENTS: u32 = 96;
    const STRIDE: u32 = SEGMENTS + 1;
    let mut mesh = Mesh::default();
    for ring in 0..=12_u32 {
        let t = ring as f32 / 12.0_f32;
        let r = radius + t * 30.0_f32;
        let a = (f32::from(alpha.min(25)) * (1.0_f32 - t).powi(2)) as u8;
        for i in 0..=SEGMENTS {
            let angle = TAU * i as f32 / SEGMENTS as f32;
            mesh.vertices.push(Vertex { pos: center + vec2(angle.cos(), angle.sin()) * r,
                uv: egui::epaint::WHITE_UV, color: Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), a) });
            if ring > 0 && i > 0 {
                let current = ring * STRIDE + i;
                let previous = current - STRIDE;
                mesh.indices.extend([previous - 1, previous, current, previous - 1, current, current - 1]);
            }
        }
    }
    Some(mesh)
}
pub fn halo(p: &Painter, center: Pos2, radius: f32, color: Color32, alpha: u8) {
    if let Some(mesh) = halo_mesh(center, radius, color, alpha) { submit_mesh(p, mesh); }
}
pub fn arc(p: &Painter, center: Pos2, radius: f32, start: f32, end: f32, stroke: Stroke) {
    if !finite_position(center) || !radius.is_finite() || radius <= 0.0_f32
        || !start.is_finite() || !end.is_finite() || !(end - start).is_finite()
        || !stroke.width.is_finite() || stroke.width <= 0.0_f32 { return; }
    let points: Vec<_> = (0..=64).map(|i| {
        let angle = start + (end - start) * i as f32 / 64.0_f32;
        center + vec2(angle.cos(), angle.sin()) * radius
    }).collect();
    if points.iter().copied().all(finite_position) { p.add(Shape::line(points, stroke)); }
}

pub fn icon(p: &Painter, center: Pos2, kind: Icon, size: f32, color: Color32) {
    if !finite_position(center) || !size.is_finite() || size <= 0.0_f32 { return; }
    let s = size / 2.0_f32;
    let stroke = Stroke::new(1.7_f32, color);
    let line = |a: Vec2, b: Vec2| { p.line_segment([center + a * s, center + b * s], stroke); };
    match kind {
        Icon::Plus => {
            line(vec2(-0.6_f32, 0.0_f32), vec2(0.6_f32, 0.0_f32));
            line(vec2(0.0_f32, -0.6_f32), vec2(0.0_f32, 0.6_f32));
        }
        Icon::Menu | Icon::Text => {
            for y in [-0.4_f32, 0.0_f32, 0.4_f32] { line(vec2(-0.6_f32, y), vec2(0.6_f32, y)); }
        }
        Icon::Back | Icon::Chevron => {
            let dir = if matches!(kind, Icon::Back) { -1.0_f32 } else { 1.0_f32 };
            line(vec2(-dir * 0.25_f32, -0.55_f32), vec2(dir * 0.3_f32, 0.0_f32));
            line(vec2(dir * 0.3_f32, 0.0_f32), vec2(-dir * 0.25_f32, 0.55_f32));
        }
        Icon::Server => {
            for y in [-0.65_f32, 0.0_f32, 0.65_f32] {
                let r = Rect::from_center_size(center + vec2(0.0_f32, y * s), vec2(size * 0.76_f32, size * 0.24_f32));
                p.rect_filled(r, 2.0_f32, color);
                p.circle_filled(pos2(r.left() + 4.0_f32, r.center().y), 1.2_f32, BG);
                p.line_segment([pos2(r.left() + 8.0_f32, r.center().y), pos2(r.right() - 3.0_f32, r.center().y)], Stroke::new(1.0_f32, BG));
            }
        }
        Icon::Clock => {
            p.circle_stroke(center, s * 0.7_f32, stroke);
            line(vec2(0.0_f32, -0.45_f32), Vec2::ZERO);
            line(Vec2::ZERO, vec2(0.35_f32, 0.22_f32));
        }
        Icon::Down | Icon::Up => {
            let dir = if matches!(kind, Icon::Down) { 1.0_f32 } else { -1.0_f32 };
            line(vec2(0.0_f32, -0.65_f32 * dir), vec2(0.0_f32, 0.35_f32 * dir));
            p.add(Shape::convex_polygon(vec![
                center + vec2(-0.55_f32, -0.05_f32 * dir) * s,
                center + vec2(0.55_f32, -0.05_f32 * dir) * s,
                center + vec2(0.0_f32, 0.6_f32 * dir) * s,
            ], color, Stroke::NONE));
            line(vec2(-0.65_f32, 0.85_f32), vec2(0.65_f32, 0.85_f32));
        }
        Icon::Pin => {
            p.circle_filled(center - vec2(0.0_f32, s * 0.25_f32), s * 0.55_f32, color);
            p.add(Shape::convex_polygon(vec![
                center + vec2(-s * 0.48_f32, 0.0_f32),
                center + vec2(s * 0.48_f32, 0.0_f32),
                center + vec2(0.0_f32, s * 0.9_f32),
            ], color, Stroke::NONE));
            p.circle_filled(center - vec2(0.0_f32, s * 0.25_f32), s * 0.2_f32, BG);
        }
        Icon::Clipboard | Icon::File | Icon::Copy => {
            let r = Rect::from_center_size(center, vec2(size * 0.65_f32, size * 0.8_f32));
            if matches!(kind, Icon::Copy) { p.rect_stroke(r.translate(vec2(-3.0_f32, -3.0_f32)), 3.0_f32, stroke); }
            p.rect(r, 3.0_f32, GLASS, stroke);
            if matches!(kind, Icon::Clipboard) {
                p.rect_filled(Rect::from_center_size(center - vec2(0.0_f32, s * 0.75_f32), vec2(s * 0.7_f32, s * 0.3_f32)), 2.0_f32, color);
            } else {
                line(vec2(-0.35_f32, -0.2_f32), vec2(0.35_f32, -0.2_f32));
                line(vec2(-0.35_f32, 0.2_f32), vec2(0.25_f32, 0.2_f32));
            }
        }
        Icon::Camera => {
            p.rect_stroke(Rect::from_center_size(center + vec2(0.0_f32, s * 0.1_f32), vec2(s * 1.7_f32, s * 1.2_f32)), 3.0_f32, stroke);
            p.circle_stroke(center + vec2(0.0_f32, s * 0.1_f32), s * 0.38_f32, stroke);
            line(vec2(-0.4_f32, -0.5_f32), vec2(-0.25_f32, -0.8_f32));
            line(vec2(-0.25_f32, -0.8_f32), vec2(0.25_f32, -0.8_f32));
            line(vec2(0.25_f32, -0.8_f32), vec2(0.4_f32, -0.5_f32));
        }
        Icon::Link => {
            for offset in [-0.3_f32, 0.3_f32] {
                p.rect_stroke(Rect::from_center_size(center + vec2(offset * s, -offset * s), vec2(s, s * 0.65_f32)), s * 0.3_f32, stroke);
            }
            line(vec2(-0.25_f32, 0.25_f32), vec2(0.25_f32, -0.25_f32));
        }
        Icon::Gear => {
            p.circle_stroke(center, s * 0.55_f32, stroke);
            p.circle_stroke(center, s * 0.2_f32, stroke);
            for i in 0..8 {
                let a = i as f32 * TAU / 8.0_f32;
                let d = vec2(a.cos(), a.sin());
                line(d * 0.55_f32, d * 0.85_f32);
            }
        }
        Icon::Terminal => {
            p.rect_stroke(Rect::from_center_size(center, vec2(size * 0.9_f32, size * 0.7_f32)), 3.0_f32, stroke);
            line(vec2(-0.5_f32, -0.25_f32), vec2(-0.2_f32, 0.0_f32));
            line(vec2(-0.2_f32, 0.0_f32), vec2(-0.5_f32, 0.25_f32));
            line(vec2(0.0_f32, 0.25_f32), vec2(0.5_f32, 0.25_f32));
        }
        Icon::Info => {
            p.circle_stroke(center, s * 0.8_f32, stroke);
            p.circle_filled(center - vec2(0.0_f32, s * 0.35_f32), 1.2_f32, color);
            line(vec2(0.0_f32, -0.05_f32), vec2(0.0_f32, 0.45_f32));
        }
        Icon::Refresh => {
            arc(p, center, s * 0.65_f32, 0.2_f32, TAU - 0.55_f32, stroke);
            line(vec2(0.55_f32, -0.65_f32), vec2(0.55_f32, -0.1_f32));
            line(vec2(0.55_f32, -0.1_f32), vec2(0.0_f32, -0.2_f32));
        }
        Icon::Trash => {
            p.rect_stroke(Rect::from_center_size(center + vec2(0.0_f32, s * 0.2_f32), vec2(s, s * 1.1_f32)), 2.0_f32, stroke);
            line(vec2(-0.7_f32, -0.5_f32), vec2(0.7_f32, -0.5_f32));
            line(vec2(-0.2_f32, -0.75_f32), vec2(0.2_f32, -0.75_f32));
        }
        Icon::Lightning => {
            p.add(Shape::line(vec![
                center + vec2(0.2_f32, -0.85_f32) * s,
                center + vec2(-0.55_f32, 0.1_f32) * s,
                center + vec2(0.25_f32, 0.1_f32) * s,
                center + vec2(-0.2_f32, 0.85_f32) * s,
            ], Stroke::new(2.2_f32, color)));
        }
        Icon::More => {
            for x in [-0.5_f32, 0.0_f32, 0.5_f32] { p.circle_filled(center + vec2(x * s, 0.0_f32), 1.6_f32, color); }
        }
        Icon::Check => {
            line(vec2(-0.6_f32, 0.0_f32), vec2(-0.15_f32, 0.45_f32));
            line(vec2(-0.15_f32, 0.45_f32), vec2(0.65_f32, -0.45_f32));
        }
    }
}

pub fn round_button(ui: &mut Ui, kind: Icon) -> Response { round_button_tinted(ui, kind, TEXT) }
pub fn round_button_tinted(ui: &mut Ui, kind: Icon, color: Color32) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(44.0_f32, 44.0_f32), Sense::click());
    ui.painter().circle(rect.center(), 21.5_f32,
        if response.hovered() { Color32::from_rgb(36, 48, 73) } else { GLASS },
        Stroke::new(1.0_f32, Color32::from_rgb(42, 53, 80)));
    icon(ui.painter(), rect.center(), kind, 24.0_f32, color.gamma_multiply(if ui.is_enabled() { 1.0_f32 } else { 0.4_f32 }));
    response
}
pub fn busy_button(ui: &mut Ui, kind: Icon, busy: bool) -> Response {
    let response = ui.add_enabled_ui(!busy, |ui| round_button(ui, kind)).inner;
    if busy {
        ui.painter().circle_filled(response.rect.center(), 14.0_f32, GLASS);
        let angle = ui.input(|i| i.time) as f32 * 4.0_f32;
        arc(ui.painter(), response.rect.center(), 9.0_f32, angle, angle + 4.5_f32, Stroke::new(2.0_f32, BLUE));
        ui.ctx().request_repaint();
    }
    response
}
pub fn top_bar(ui: &mut Ui, title: &str, right: Option<Icon>) -> (Response, Option<Response>) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 44.0_f32), Sense::hover());
    let left = ui.allocate_new_ui(UiBuilder::new().max_rect(Rect::from_min_size(rect.min, vec2(44.0_f32, 44.0_f32))),
        |ui| round_button(ui, Icon::Back)).inner;
    let title_rect = Rect::from_min_max(rect.min + vec2(52.0_f32, 0.0_f32), rect.max - vec2(52.0_f32, 0.0_f32));
    let mut job = egui::text::LayoutJob::simple(title.to_owned(), bold_font(20.0_f32), TEXT, title_rect.width().max(1.0_f32));
    job.wrap.max_rows = 1;
    job.wrap.overflow_character = Some('…');
    let galley = ui.painter().layout_job(job);
    ui.painter().galley(title_rect.center() - galley.size() / 2.0_f32, galley, TEXT);
    let right = right.map(|kind| ui.allocate_new_ui(UiBuilder::new().max_rect(Rect::from_min_size(
        pos2(rect.right() - 44.0_f32, rect.top()), vec2(44.0_f32, 44.0_f32))), |ui| round_button(ui, kind)).inner);
    (left, right)
}
pub fn window_control(ui: &mut Ui, close: bool) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(30.0_f32, 30.0_f32), Sense::click());
    ui.painter().circle_filled(rect.center(), 15.0_f32, if response.hovered() {
        if close { Color32::from_rgb(239, 68, 68) } else { GLASS }
    } else { Color32::TRANSPARENT });
    let c = rect.center();
    let stroke = Stroke::new(1.6_f32, if response.hovered() { TEXT } else { MUTED });
    if close {
        ui.painter().line_segment([c - vec2(4.0_f32, 4.0_f32), c + vec2(4.0_f32, 4.0_f32)], stroke);
        ui.painter().line_segment([c + vec2(-4.0_f32, 4.0_f32), c + vec2(4.0_f32, -4.0_f32)], stroke);
    } else { ui.painter().line_segment([c - vec2(5.0_f32, 0.0_f32), c + vec2(5.0_f32, 0.0_f32)], stroke); }
    response
}
pub fn expand_control(ui: &mut Ui) -> Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::splat(30.0_f32), Sense::click());
    if response.hovered() { ui.painter().circle_filled(rect.center(), 15.0_f32, GLASS); }
    let c = rect.center();
    let stroke = Stroke::new(1.4_f32, if response.hovered() { TEXT } else { MUTED });
    for direction in [-1.0_f32, 1.0_f32] {
        let tip = c + Vec2::splat(5.0_f32 * direction);
        ui.painter().line_segment([c, tip], stroke);
        ui.painter().line_segment([tip, tip - vec2(4.0_f32 * direction, 0.0_f32)], stroke);
        ui.painter().line_segment([tip, tip - vec2(0.0_f32, 4.0_f32 * direction)], stroke);
    }
    response
}
pub fn primary(ui: &mut Ui, label: &str) -> Response {
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 48.0_f32), Sense::click());
    gradient(ui.painter(), rect, 24.0_f32,
        if response.hovered() { Color32::from_rgb(79, 149, 255) } else { Color32::from_rgb(59, 130, 246) },
        Color32::from_rgb(29, 78, 216));
    if !ui.is_enabled() { ui.painter().rect_filled(rect, 24.0_f32, Color32::from_black_alpha(100)); }
    ui.painter().text(rect.center(), Align2::CENTER_CENTER, label, semibold_font(14.0_f32), TEXT);
    response
}
pub fn secondary(ui: &mut Ui, label: &str, danger: bool) -> Response {
    let font = semibold_font(12.0_f32);
    let width = (ui.painter().layout_no_wrap(label.to_owned(), font.clone(), TEXT).size().x + 28.0_f32)
        .min(ui.available_width().max(1.0_f32));
    let height = touch_height(ui, 34.0_f32);
    let (rect, response) = ui.allocate_exact_size(vec2(width, height), Sense::click());
    ui.painter().rect(rect, height / 2.0_f32,
        if response.hovered() { Color32::from_rgb(35, 51, 79) } else { GLASS }, Stroke::new(1.0_f32, BORDER));
    elided_with_font(ui.painter(), rect.shrink2(vec2(12.0_f32, 0.0_f32)), label, font, if danger { RED } else { TEXT });
    response.on_hover_text(label)
}
pub fn toggle(ui: &mut Ui, value: &mut bool) -> Response {
    let height = touch_height(ui, 24.0_f32);
    let (hit, mut response) = ui.allocate_exact_size(vec2(44.0_f32, height), Sense::click());
    let rect = Rect::from_center_size(hit.center(), vec2(44.0_f32, 24.0_f32));
    if response.clicked() { *value = !*value; response.mark_changed(); }
    let t = ui.ctx().animate_bool(response.id, *value);
    ui.painter().rect_filled(rect, 12.0_f32, Color32::from_rgb(42, 53, 80));
    if t > 0.0_f32 {
        gradient(ui.painter(), rect, 12.0_f32,
            Color32::from_rgba_unmultiplied(59, 130, 246, (255.0_f32 * t) as u8),
            Color32::from_rgba_unmultiplied(29, 78, 216, (255.0_f32 * t) as u8));
    }
    ui.painter().circle_filled(pos2(rect.left() + 12.0_f32 + t * 20.0_f32, rect.center().y), 9.0_f32,
        if ui.is_enabled() { Color32::WHITE } else { MUTED });
    response
}
pub fn chip(ui: &mut Ui, label: &str, selected: bool) -> Response {
    let font = semibold_font(11.0_f32);
    let width = ui.painter().layout_no_wrap(label.to_owned(), font.clone(), TEXT).size().x + 22.0_f32;
    let height = touch_height(ui, 30.0_f32);
    let (rect, response) = ui.allocate_exact_size(vec2(width.min(ui.max_rect().width()), height), Sense::click());
    if selected {
        gradient(ui.painter(), rect, height / 2.0_f32, Color32::from_rgb(59, 130, 246), Color32::from_rgb(29, 78, 216));
    } else {
        ui.painter().rect(rect, height / 2.0_f32,
            if response.hovered() { Color32::from_rgb(35, 51, 79) } else { GLASS }, Stroke::new(1.0_f32, BORDER));
    }
    elided_with_font(ui.painter(), rect.shrink2(vec2(11.0_f32, 0.0_f32)), label, font, if selected { TEXT } else { MUTED });
    response.on_hover_text(label)
}
pub fn latency(p: &Painter, rect: Rect, value: Option<Option<u128>>) {
    let (label, color) = match value {
        None => ("—".to_owned(), MUTED),
        Some(None) => ("Timeout".to_owned(), RED),
        Some(Some(ms)) => (format!("{ms} ms"), if ms < 150 { GREEN } else if ms < 300 { AMBER } else { RED }),
    };
    p.rect_filled(rect, rect.height() / 2.0_f32, color.gamma_multiply(0.12_f32));
    text(p, rect.center(), Align2::CENTER_CENTER, &label, 11.0_f32, color);
}

fn style_text_edit(ui: &mut Ui) {
    let visuals = ui.visuals_mut();
    visuals.extreme_bg_color = INPUT;
    for widget in [&mut visuals.widgets.inactive, &mut visuals.widgets.hovered, &mut visuals.widgets.active] {
        widget.rounding = Rounding::same(14.0_f32);
        widget.bg_stroke = Stroke::new(1.0_f32, BORDER);
    }
    visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, BLUE);
}

fn single_input(ui: &mut Ui, value: &mut String, hint: &str, password: bool) -> Response {
    let mobile = mobile_metrics(ui.ctx()).0;
    let response = ui.scope(|ui| {
        style_text_edit(ui);
        let field = ui.next_auto_id();
        crate::platform::prepare_text_field(ui, field);
        let margin = if mobile { 14.0_f32 } else { 11.0_f32 };
        ui.add(TextEdit::singleline(value)
            .id(field)
            .password(password)
            .hint_text(RichText::new(hint).color(MUTED))
            .desired_width(f32::INFINITY)
            .margin(Margin {
                left: 12.0_f32, right: if mobile { 48.0_f32 } else { 12.0_f32 },
                top: margin, bottom: margin,
            }))
    }).inner;
    crate::platform::text_field(ui, response, value, true)
}

pub fn input(ui: &mut Ui, value: &mut String, hint: &str) -> Response {
    single_input(ui, value, hint, false)
}

pub fn password_input(ui: &mut Ui, value: &mut String) -> Response {
    single_input(ui, value, "", true)
}

pub fn text_area(ui: &mut Ui, value: &mut String, height: f32) -> Response {
    let mobile = mobile_metrics(ui.ctx()).0;
    let response = ui.scope(|ui| {
        style_text_edit(ui);
        let field = ui.next_auto_id();
        crate::platform::prepare_text_field(ui, field);
        // add_sized supplies a minimum width. Explicitly limit the galley
        // width as well, otherwise long lines can grow beneath the paste icon.
        let width = ui.available_width();
        let right = if mobile { 48.0_f32 } else { 14.0_f32 };
        let text_width = (width - 14.0_f32 - right).max(1.0_f32);
        ui.add_sized(vec2(width, height),
            TextEdit::multiline(value).id(field).font(TextStyle::Monospace)
                .hint_text(RichText::new("Paste links or configuration text…").color(MUTED))
                .desired_width(text_width)
                .margin(Margin {
                    left: 14.0_f32, right,
                    top: 14.0_f32, bottom: 14.0_f32,
                }))
    }).inner;
    crate::platform::text_field(ui, response, value, true)
}

pub fn section(ui: &mut Ui, label: &str) {
    ui.add_space(8.0_f32);
    let mut job = egui::text::LayoutJob::default();
    let mut format = egui::text::TextFormat::simple(semibold_font(10.0_f32), MUTED);
    format.extra_letter_spacing = 1.5_f32;
    job.append(label, 0.0_f32, format);
    ui.label(job);
}
pub fn divider(ui: &mut Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0_f32), Sense::hover());
    ui.painter().line_segment([rect.left_center(), rect.right_center()], Stroke::new(1.0_f32, BORDER));
}
pub fn settings_row<R>(ui: &mut Ui, label: &str, subtitle: Option<&str>, control: impl FnOnce(&mut Ui) -> R) -> R {
    let width = ui.available_width();
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(vec2((width - 72.0_f32).max(40.0_f32), 0.0_f32), Layout::top_down(Align::Min), |ui| {
            ui.label(RichText::new(label).size(13.0_f32));
            if let Some(subtitle) = subtitle {
                ui.add(Label::new(RichText::new(subtitle).size(10.0_f32).color(MUTED)).wrap());
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), control).inner
    }).inner
}

fn menu_activation(ctx: &Context) -> u64 {
    ctx.data(|data| data.get_temp::<u64>(Id::new("menu-activation")).unwrap_or_default())
}

pub fn menu_row(ui: &mut Ui, kind: Icon, label: &str, danger: bool) -> Response {
    let height = touch_height(ui, 42.0_f32);
    let (rect, response) = ui.allocate_exact_size(vec2(MENU_WIDTH - 16.0_f32, height), Sense::click());
    if response.hovered() { ui.painter().rect_filled(rect, 10.0_f32, GLASS); }
    icon(ui.painter(), pos2(rect.left() + 21.0_f32, rect.center().y), kind, 20.0_f32, if danger { RED } else { BLUE });
    text(ui.painter(), pos2(rect.left() + 44.0_f32, rect.center().y), Align2::LEFT_CENTER,
        label, 13.0_f32, if danger { RED } else { TEXT });
    if response.clicked() {
        let activation = menu_activation(ui.ctx()).wrapping_add(1);
        ui.ctx().data_mut(|data| data.insert_temp(Id::new("menu-activation"), activation));
        ui.memory_mut(|memory| memory.close_popup());
    }
    response
}
fn menu_position(screen: Rect, anchor: Rect) -> Pos2 {
    let right_side = anchor.center().x > screen.center().x;
    let x = if right_side { anchor.right() - MENU_WIDTH } else { anchor.left() };
    let minimum = screen.left() + 12.0_f32;
    let maximum = (screen.right() - 12.0_f32 - MENU_WIDTH).max(minimum);
    pos2(x.clamp(minimum, maximum),
        (anchor.bottom() + 6.0_f32).clamp(screen.top() + 12.0_f32, (screen.bottom() - 72.0_f32).max(screen.top() + 12.0_f32)))
}
pub fn dropdown<R>(ui: &mut Ui, id: Id, anchor: &Response, content: impl FnOnce(&mut Ui) -> R) {
    let anchor_clicked = anchor.clicked();
    if anchor_clicked { ui.memory_mut(|m| m.toggle_popup(id)); }
    if !ui.memory(|m| m.is_popup_open(id)) { return; }
    let mut screen = ui.ctx().screen_rect();
    let (mobile, top, bottom) = mobile_metrics(ui.ctx());
    if mobile {
        screen.min.y += top;
        screen.max.y = (screen.max.y - bottom).max(screen.min.y);
    }
    let position = menu_position(screen, anchor.rect);
    let height = (screen.bottom() - position.y - 24.0_f32).max(42.0_f32);
    let activation = menu_activation(ui.ctx());
    let shown = Area::new(id).order(Order::Foreground).movable(false).fixed_pos(position).show(ui.ctx(), |ui| {
        Frame::none().fill(Color32::from_rgb(17, 24, 39)).stroke(Stroke::new(1.0_f32, BORDER))
            .rounding(18.0_f32).inner_margin(8.0_f32).show(ui, |ui| {
                ui.set_width(MENU_WIDTH - 16.0_f32);
                ui.spacing_mut().item_spacing.y = 2.0_f32;
                ScrollArea::vertical().id_salt(id.with("scroll")).max_height(height)
                    .auto_shrink([false, true]).show(ui, content);
            });
    });
    let (escape, click, pointer) = ui.input(|i| (
        i.key_pressed(Key::Escape), i.pointer.any_click(), i.pointer.interact_pos(),
    ));
    let outside = pointer.is_some_and(|p| !shown.response.rect.contains(p));
    // Close after the entire action has run, including navigation or an
    // egui close_menu call. All three Area menus share this path.
    let activated = menu_activation(ui.ctx()) != activation;
    if activated || escape || (click && !anchor_clicked && outside) {
        ui.memory_mut(|m| m.close_popup());
        ui.ctx().request_repaint();
    }
}
pub fn toast(ctx: &Context, message: &str, color: Color32, action: Option<&str>) -> bool {
    let screen = ctx.screen_rect();
    let pad = if screen.width() < 360.0_f32 { 16.0_f32 } else { 20.0_f32 };
    let width = (screen.width() - pad * 2.0_f32).clamp(80.0_f32, 460.0_f32);
    let (_, _, safe_bottom) = mobile_metrics(ctx);
    let mut clicked = false;
    Area::new(Id::new("toast")).order(Order::Tooltip)
        .anchor(Align2::CENTER_BOTTOM, vec2(0.0_f32, -18.0_f32 - safe_bottom))
        .interactable(action.is_some()).show(ctx, |ui| {
            Frame::none().fill(GLASS).stroke(Stroke::new(1.0_f32, BORDER))
                .rounding(22.0_f32).inner_margin(vec2(16.0_f32, 12.0_f32)).show(ui, |ui| {
                    ui.set_width((width - 32.0_f32).max(1.0_f32));
                    ui.horizontal(|ui| {
                        let (dot, _) = ui.allocate_exact_size(vec2(8.0_f32, 8.0_f32), Sense::hover());
                        ui.painter().circle_filled(dot.center(), 4.0_f32, color);
                        ui.add(Label::new(RichText::new(message).size(12.0_f32)).wrap());
                    });
                    if let Some(label) = action { clicked = secondary(ui, label, false).clicked(); }
                });
        });
    clicked
}
pub fn empty(ui: &mut Ui, kind: Icon, label: &str) {
    ui.add_space(28.0_f32);
    ui.vertical_centered(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(72.0_f32, 72.0_f32), Sense::hover());
        ui.painter().circle_filled(rect.center(), 36.0_f32, GLASS);
        icon(ui.painter(), rect.center(), kind, 32.0_f32, BLUE);
        ui.add_space(8.0_f32);
        ui.label(RichText::new(label).font(semibold_font(16.0_f32)));
    });
    ui.add_space(20.0_f32);
}
pub fn text(p: &Painter, position: Pos2, align: Align2, value: &str, size: f32, color: Color32) {
    p.text(position, align, value, FontId::proportional(size), color);
}
pub fn bold_text(p: &Painter, position: Pos2, align: Align2, value: &str, size: f32, color: Color32) {
    p.text(position, align, value, bold_font(size), color);
}
pub fn elided_with_font(p: &Painter, rect: Rect, value: &str, font: FontId, color: Color32) {
    if !usable_rect(rect) { return; }
    let mut job = egui::text::LayoutJob::simple(value.to_owned(), font, color, rect.width());
    job.wrap.max_rows = 1;
    job.wrap.break_anywhere = true;
    job.wrap.overflow_character = Some('…');
    let galley = p.layout_job(job);
    p.galley(rect.left_center() - vec2(0.0_f32, galley.size().y / 2.0_f32), galley, color);
}
pub fn elided(p: &Painter, rect: Rect, value: &str, size: f32, color: Color32) {
    elided_with_font(p, rect, value, FontId::proportional(size), color);
}
pub fn power_icon(p: &Painter, center: Pos2) {
    if !finite_position(center) { return; }
    arc(p, center, 19.0_f32, -PI / 2.0_f32 + 0.55_f32, PI * 1.5_f32 - 0.55_f32, Stroke::new(5.0_f32, Color32::WHITE));
    p.line_segment([center - vec2(0.0_f32, 27.0_f32), center - vec2(0.0_f32, 3.0_f32)], Stroke::new(5.0_f32, Color32::WHITE));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_custom_meshes_are_valid_and_finite() {
        for size in [vec2(380.0_f32, 680.0_f32), vec2(420.0_f32, 760.0_f32)] {
            let mesh = gradient_mesh(Rect::from_min_size(Pos2::ZERO, size), 18.0_f32, BG, INPUT).expect("rectangle");
            assert!(usable_mesh(&mesh));
            assert_eq!(mesh.vertices.len(), 53);
            assert_eq!(mesh.indices.iter().copied().max(), Some(52));
        }
        for radius in [69.0_f32, 80.0_f32, 85.0_f32] {
            let center = pos2(210.0_f32, 300.0_f32);
            assert!(usable_mesh(&disc_mesh(center, radius, BLUE, CYAN).expect("disc")));
            assert!(usable_mesh(&halo_mesh(center, radius, BLUE, 23).expect("halo")));
        }
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        for rect in [
            Rect::from_min_size(Pos2::ZERO, vec2(0.0_f32, 760.0_f32)), Rect::NOTHING, Rect::EVERYTHING,
            Rect::from_min_max(pos2(f32::NAN, 0.0_f32), pos2(420.0_f32, 760.0_f32)),
        ] {
            assert!(gradient_mesh(rect, 18.0_f32, BG, INPUT).is_none());
        }
        for radius in [0.0_f32, -1.0_f32, f32::NAN, f32::INFINITY] {
            assert!(disc_mesh(Pos2::ZERO, radius, BLUE, CYAN).is_none());
            assert!(halo_mesh(Pos2::ZERO, radius, BLUE, 23).is_none());
        }
        let mut mesh = disc_mesh(Pos2::ZERO, 80.0_f32, BLUE, CYAN).expect("disc");
        mesh.vertices[0].uv.x = f32::NAN;
        assert!(!usable_mesh(&mesh));
    }

    #[test]
    fn dropdown_positions_are_fixed_and_inside_margins() {
        let screen = Rect::from_min_size(Pos2::ZERO, vec2(420.0_f32, 760.0_f32));
        let left = Rect::from_min_size(pos2(20.0_f32, 40.0_f32), vec2(44.0_f32, 44.0_f32));
        let right = Rect::from_min_size(pos2(356.0_f32, 40.0_f32), vec2(44.0_f32, 44.0_f32));
        assert_eq!(menu_position(screen, left), pos2(20.0_f32, 90.0_f32));
        assert_eq!(menu_position(screen, right), pos2(174.0_f32, 90.0_f32));
        let edge = right.translate(vec2(100.0_f32, 0.0_f32));
        assert_eq!(menu_position(screen, edge).x, 182.0_f32);
        let small = Rect::from_min_size(Pos2::ZERO, vec2(300.0_f32, 190.0_f32));
        let position = menu_position(small, edge);
        assert!(position.x + MENU_WIDTH <= small.right() - 12.0_f32);
        assert!(position.y <= small.bottom() - 72.0_f32);
    }

    #[test]
    fn embedded_emoji_precedes_default_fallbacks_in_every_family() {
        let defaults = FontDefinitions::default();
        let fonts = configured_fonts();
        assert!(fonts.font_data.contains_key(EMOJI_FONT));
        for (family, chain) in &fonts.families {
            let emoji = chain.iter().position(|name| name == EMOJI_FONT).expect("emoji font");
            if let Some(arabic) = chain.iter().position(|name| name.starts_with("Vazirmatn-") || name == "arabic-system-fallback") {
                assert_eq!(emoji, arabic + 1);
            }
            let original = defaults.families.get(family)
                .or_else(|| defaults.families.get(&FontFamily::Proportional)).expect("fallback");
            let tail = if *family == FontFamily::Monospace { &original[1..] } else { original.as_slice() };
            assert_eq!(&chain[emoji + 1..], tail);
        }
    }

    #[test]
    fn mobile_widgets_have_touch_targets_without_changing_desktop_metrics() {
        let ctx = Context::default();
        setup(&ctx);
        for mobile in [false, true] {
            set_mobile(&ctx, mobile, 24.0_f32, 20.0_f32);
            let _ = ctx.run(RawInput::default(), |ctx| {
                CentralPanel::default().show(ctx, |ui| {
                    let chip = chip(ui, "VPN", true);
                    let secondary = secondary(ui, "Update", false);
                    let toggle = toggle(ui, &mut false);
                    let row = menu_row(ui, Icon::Server, "Servers", false);
                    if mobile {
                        for response in [chip, secondary, toggle, row] { assert!(response.rect.height() >= 44.0_f32); }
                    } else {
                        assert_eq!(chip.rect.height(), 30.0_f32);
                        assert_eq!(secondary.rect.height(), 34.0_f32);
                        assert_eq!(toggle.rect.height(), 24.0_f32);
                        assert_eq!(row.rect.height(), 42.0_f32);
                    }
                });
            });
        }
    }

    #[test]
    fn open_dropdown_handles_pointer_click_without_nested_context_access() {
        let ctx = Context::default();
        let popup = Id::new("dropdown-lock-regression");
        let _ = ctx.run(RawInput::default(), |ctx| {
            CentralPanel::default().show(ctx, |ui| {
                let anchor = round_button(ui, Icon::Menu);
                ui.memory_mut(|m| m.open_popup(popup));
                dropdown(ui, popup, &anchor, |ui| { menu_row(ui, Icon::Server, "Servers", false); });
            });
        });
        let input = RawInput {
            events: vec![
                Event::PointerMoved(pos2(350.0_f32, 350.0_f32)),
                Event::PointerButton { pos: pos2(350.0_f32, 350.0_f32), button: PointerButton::Primary, pressed: true, modifiers: Modifiers::default() },
                Event::PointerButton { pos: pos2(350.0_f32, 350.0_f32), button: PointerButton::Primary, pressed: false, modifiers: Modifiers::default() },
            ], ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            CentralPanel::default().show(ctx, |ui| {
                let anchor = round_button(ui, Icon::Menu);
                dropdown(ui, popup, &anchor, |ui| { menu_row(ui, Icon::Server, "Servers", false); });
            });
        });
        assert!(!ctx.memory(|m| m.is_popup_open(popup)));
    }

    #[test]
    fn clicked_menu_row_closes_area_popup() {
        let ctx = Context::default();
        let popup = Id::new("clicked-menu");
        let mut rect = Rect::NOTHING;
        let _ = ctx.run(RawInput::default(), |ctx| {
            CentralPanel::default().show(ctx, |ui| {
                rect = menu_row(ui, Icon::Server, "Servers", false).rect;
            });
        });
        ctx.memory_mut(|memory| memory.open_popup(popup));
        let position = rect.center();
        let input = RawInput {
            events: vec![
                Event::PointerMoved(position),
                Event::PointerButton { pos: position, button: PointerButton::Primary, pressed: true, modifiers: Modifiers::default() },
                Event::PointerButton { pos: position, button: PointerButton::Primary, pressed: false, modifiers: Modifiers::default() },
            ], ..Default::default()
        };
        let _ = ctx.run(input, |ctx| {
            CentralPanel::default().show(ctx, |ui| {
                menu_row(ui, Icon::Server, "Servers", false);
            });
        });
        assert!(!ctx.memory(|memory| memory.is_popup_open(popup)));
    }
}
