use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use eframe::egui::{self, text::CCursor, text::CCursorRange, *};

#[derive(Clone, Debug, PartialEq)]
pub enum VpnStatus {
    Idle,
    Starting,
    Running,
    PermissionDenied,
    Failed(String),
}

pub trait Platform: Send + Sync {
    fn is_mobile(&self) -> bool;
    fn clipboard_get(&self) -> Option<String>;
    fn clipboard_set(&self, text: &str);
    fn pick_import_file(&self) -> Option<PathBuf>;
    fn open_folder(&self, path: &Path);
    fn start_vpn(
        &self,
        socks_port: u16,
        allowed: &[String],
        disallowed: &[String],
    ) -> anyhow::Result<()>;
    fn stop_vpn(&self);
    fn vpn_status(&self) -> VpnStatus;
    fn safe_area(&self) -> (f32, f32) {
        (0.0_f32, 0.0_f32)
    }
    fn can_scan_qr(&self) -> bool {
        false
    }
    fn start_qr_scan(&self) -> anyhow::Result<()> {
        anyhow::bail!("QR scanning is not supported on this platform")
    }
    fn take_qr_result(&self) -> Option<Result<String, String>> {
        None
    }
    /// Lets the platform wake the UI thread (e.g. `ctx.request_repaint()`) from its own callbacks.
    fn set_wake(&self, _wake: std::sync::Arc<dyn Fn() + Send + Sync>) {}
    /// True once per hardware Back press.
    fn take_back_press(&self) -> bool {
        false
    }
    /// Hide the app without stopping it (Back at the root screen).
    fn move_to_background(&self) {}
}

#[derive(Default)]
pub struct DesktopPlatform;

impl Platform for DesktopPlatform {
    fn is_mobile(&self) -> bool {
        false
    }

    fn clipboard_get(&self) -> Option<String> {
        #[cfg(not(target_os = "android"))]
        {
            arboard::Clipboard::new().ok()?.get_text().ok()
        }
        #[cfg(target_os = "android")]
        {
            None
        }
    }

    fn clipboard_set(&self, text: &str) {
        #[cfg(not(target_os = "android"))]
        if let Ok(mut clipboard) = arboard::Clipboard::new() {
            let _ = clipboard.set_text(text.to_owned());
        }
        #[cfg(target_os = "android")]
        let _ = text;
    }

    fn pick_import_file(&self) -> Option<PathBuf> {
        #[cfg(not(target_os = "android"))]
        {
            rfd::FileDialog::new()
                .add_filter("Supported configurations", &["ovpn", "conf", "json", "yaml", "yml", "txt"])
                .add_filter("All files", &["*"])
                .pick_file()
        }
        #[cfg(target_os = "android")]
        {
            None
        }
    }

    fn open_folder(&self, path: &Path) {
        #[cfg(not(target_os = "android"))]
        {
            let path = path.to_owned();
            std::thread::spawn(move || {
                let program = if cfg!(target_os = "windows") {
                    "explorer"
                } else if cfg!(target_os = "macos") {
                    "open"
                } else {
                    "xdg-open"
                };
                if let Ok(mut child) = std::process::Command::new(program).arg(path).spawn() {
                    let _ = child.wait();
                }
            });
        }
        #[cfg(target_os = "android")]
        let _ = path;
    }

    fn start_vpn(
        &self,
        _socks_port: u16,
        _allowed: &[String],
        _disallowed: &[String],
    ) -> anyhow::Result<()> {
        anyhow::bail!("Desktop uses its own connection modes")
    }

    fn stop_vpn(&self) {}

    fn vpn_status(&self) -> VpnStatus {
        VpnStatus::Idle
    }
}

#[derive(Clone)]
struct ClipboardBridge(Arc<dyn Platform>);

#[derive(Clone)]
struct PendingEdit {
    field: Id,
    selection: Option<CCursorRange>,
    event: egui::Event,
}

#[derive(Clone, Default)]
struct TouchEdit {
    pressed_at: Option<f64>,
    press_position: Option<Pos2>,
    selection_at_press: Option<CCursorRange>,
    last_selection: Option<CCursorRange>,
    menu_position: Option<Pos2>,
    triggered: bool,
    menu: bool,
}

pub(crate) fn install_clipboard(ctx: &Context, platform: Arc<dyn Platform>) {
    ctx.data_mut(|data| {
        data.insert_temp(Id::new("mobile-clipboard-platform"), ClipboardBridge(platform));
    });
}

fn selection(ctx: &Context, field: Id) -> Option<CCursorRange> {
    TextEdit::load_state(ctx, field).and_then(|state| state.cursor.char_range())
}

fn restore_selection(ctx: &Context, field: Id, range: Option<CCursorRange>) {
    if let Some(mut state) = TextEdit::load_state(ctx, field) {
        state.cursor.set_char_range(range);
        state.store(ctx, field);
    }
}

/// Called before TextEdit processes a pointer press, which would otherwise
/// replace the selection with the cursor under the finger.
pub(crate) fn prepare_text_field(ui: &Ui, field: Id) {
    let pressed = ui.input(|input| input.pointer.button_pressed(PointerButton::Primary));
    if !pressed {
        return;
    }
    let range = selection(ui.ctx(), field);
    ui.ctx().data_mut(|data| {
        let key = field.with("touch-edit");
        let mut touch = data.get_temp::<TouchEdit>(key).unwrap_or_default();
        touch.last_selection = range;
        data.insert_temp(key, touch);
    });
}

pub(crate) fn drain_edit_events(ctx: &Context, input: &mut RawInput) {
    let pending = ctx.data_mut(|data| {
        data.remove_temp::<Vec<PendingEdit>>(Id::new("mobile-edit-events"))
            .unwrap_or_default()
    });
    for edit in pending {
        ctx.memory_mut(|memory| memory.request_focus(edit.field));
        restore_selection(ctx, edit.field, edit.selection);
        input.events.push(edit.event);
    }
}

fn queue_edit(ctx: &Context, field: Id, range: Option<CCursorRange>, event: egui::Event) {
    ctx.data_mut(|data| {
        let key = Id::new("mobile-edit-events");
        let mut events = data.get_temp::<Vec<PendingEdit>>(key).unwrap_or_default();
        events.push(PendingEdit { field, selection: range, event });
        data.insert_temp(key, events);
    });
    ctx.request_repaint();
}

fn has_selection(range: Option<CCursorRange>) -> bool {
    range.is_some_and(|range| range.primary.index != range.secondary.index)
}

fn clipboard_menu_position(screen: Rect, touch: Pos2, size: Vec2) -> Pos2 {
    let minimum = screen.min + vec2(12.0_f32, 12.0_f32);
    let maximum = pos2(
        (screen.right() - size.x - 12.0_f32).max(minimum.x),
        (screen.bottom() - size.y - 12.0_f32).max(minimum.y),
    );
    let y = if touch.y < screen.center().y {
        touch.y + 10.0_f32
    } else {
        touch.y - size.y - 10.0_f32
    };
    pos2(touch.x.clamp(minimum.x, maximum.x), y.clamp(minimum.y, maximum.y))
}

/// Mobile clipboard affordances. The saved range is restored both when opening
/// the menu and when dispatching a deferred edit, since clicking a menu row can
/// temporarily take focus away from TextEdit.
pub(crate) fn text_field(
    ui: &mut Ui,
    mut response: Response,
    value: &mut String,
    paste_icon: bool,
) -> Response {
    let platform = ui.ctx().data(|data| {
        data.get_temp::<ClipboardBridge>(Id::new("mobile-clipboard-platform"))
    });
    let Some(ClipboardBridge(platform)) = platform else { return response; };
    if !platform.is_mobile() || !ui.is_enabled() {
        return response;
    }

    let key = response.id.with("touch-edit");
    let mut touch = ui.ctx().data(|data| data.get_temp::<TouchEdit>(key)).unwrap_or_default();
    let (now, down, pressed, released, position) = ui.input(|input| (
        input.time,
        input.pointer.primary_down(),
        input.pointer.button_pressed(PointerButton::Primary),
        input.pointer.button_released(PointerButton::Primary),
        input.pointer.interact_pos(),
    ));
    if pressed && !touch.menu {
        touch.pressed_at = position.filter(|p| response.rect.contains(*p)).map(|_| now);
        touch.press_position = position;
        touch.selection_at_press = touch.last_selection;
        touch.triggered = false;
    }
    let stationary = match (touch.press_position, position) {
        (Some(start), Some(current)) => start.distance(current) <= 10.0_f32,
        _ => false,
    };
    let long_press = down && stationary && !touch.triggered
        && touch.pressed_at.is_some_and(|since| now - since >= 0.45_f64);
    if !touch.menu && (long_press || response.double_clicked()) {
        touch.menu = true;
        touch.triggered = true;
        touch.menu_position = touch.press_position.or(position);
        restore_selection(ui.ctx(), response.id, touch.selection_at_press);
        response.request_focus();
    }
    if down && touch.pressed_at.is_some() && !touch.triggered {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(40));
    }
    if !down || !stationary {
        touch.pressed_at = None;
    }

    if paste_icon {
        let rect = Rect::from_min_size(
            pos2(response.rect.right() - 44.0_f32, response.rect.top()),
            vec2(44.0_f32, response.rect.height().min(44.0_f32)),
        );
        let paste = ui.interact(rect, response.id.with("inline-paste"), Sense::click());
        ui.painter().circle_filled(rect.center(), 15.0_f32, crate::theme::GLASS);
        crate::theme::icon(ui.painter(), rect.center(), crate::theme::Icon::Clipboard, 17.0_f32, crate::theme::BLUE);
        if paste.clicked() {
            if let Some(text) = platform.clipboard_get() {
                *value = text;
                response.mark_changed();
                response.request_focus();
                restore_selection(ui.ctx(), response.id, Some(CCursorRange::one(
                    CCursor::new(value.chars().count()),
                )));
            }
            touch.menu = false;
        }
        paste.on_hover_text("Paste");
    }

    if touch.menu {
        let screen = ui.ctx().screen_rect();
        let size = vec2(crate::theme::MENU_WIDTH, 198.0_f32);
        let point = touch.menu_position.unwrap_or(response.rect.center());
        let pos = clipboard_menu_position(screen, point, size);
        let range = touch.selection_at_press;
        // Preserve selection while the menu owns pointer interactions.
        restore_selection(ui.ctx(), response.id, range);
        let mut action = None;
        let shown = Area::new(response.id.with("clipboard-menu"))
            .order(Order::Tooltip)
            .fixed_pos(pos)
            .movable(false)
            .show(ui.ctx(), |ui| {
                Frame::none()
                    .fill(Color32::from_rgb(17, 24, 39))
                    .stroke(Stroke::new(1.0_f32, crate::theme::BORDER))
                    .rounding(18.0_f32)
                    .shadow(egui::epaint::Shadow {
                        offset: vec2(0.0_f32, 5.0_f32),
                        blur: 18.0_f32,
                        spread: 2.0_f32,
                        color: Color32::from_black_alpha(90),
                    })
                    .inner_margin(8.0_f32)
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0_f32;
                        for (index, label, icon) in [
                            (0, "Paste", crate::theme::Icon::Clipboard),
                            (1, "Copy", crate::theme::Icon::Copy),
                            (2, "Cut", crate::theme::Icon::Text),
                            (3, "Select all", crate::theme::Icon::Check),
                        ] {
                            if crate::theme::menu_row(ui, icon, label, false).clicked() {
                                action = Some(index);
                            }
                        }
                    });
            });
        if let Some(action) = action {
            response.request_focus();
            match action {
                0 => {
                    if let Some(text) = platform.clipboard_get() {
                        queue_edit(ui.ctx(), response.id, range, egui::Event::Paste(text));
                    }
                }
                1 | 2 if !has_selection(range) => {
                    platform.clipboard_set(value);
                    if action == 2 {
                        value.clear();
                        response.mark_changed();
                        restore_selection(ui.ctx(), response.id, Some(CCursorRange::one(CCursor::new(0))));
                    }
                }
                1 => queue_edit(ui.ctx(), response.id, range, egui::Event::Copy),
                2 => queue_edit(ui.ctx(), response.id, range, egui::Event::Cut),
                _ => {
                    let all = Some(CCursorRange::two(
                        CCursor::new(0), CCursor::new(value.chars().count()),
                    ));
                    touch.selection_at_press = all;
                    restore_selection(ui.ctx(), response.id, all);
                }
            }
            // Select all is a preparation for Copy/Cut, not a dismissal.
            touch.menu = action == 3;
        } else {
            let escape = ui.input(|input| input.key_pressed(Key::Escape));
            let outside = position.is_some_and(|p| !shown.response.rect.contains(p));
            if escape || (released && !touch.triggered && outside) {
                touch.menu = false;
            }
        }
        if released {
            touch.triggered = false;
        }
    }
    touch.last_selection = selection(ui.ctx(), response.id);
    ui.ctx().data_mut(|data| data.insert_temp(key, touch));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_selection_uses_whole_text() {
        assert!(!has_selection(None));
        assert!(!has_selection(Some(CCursorRange::one(CCursor::new(3)))));
        assert!(has_selection(Some(CCursorRange::two(CCursor::new(0), CCursor::new(3)))));
    }

    #[test]
    fn menu_follows_touch_instead_of_tall_field_bottom() {
        let screen = Rect::from_min_size(Pos2::ZERO, vec2(400.0_f32, 500.0_f32));
        let size = vec2(226.0_f32, 198.0_f32);
        let upper = clipboard_menu_position(screen, pos2(30.0_f32, 80.0_f32), size);
        assert_eq!(upper.y, 90.0_f32);
        let lower = clipboard_menu_position(screen, pos2(390.0_f32, 450.0_f32), size);
        assert_eq!(lower.y, 242.0_f32);
        for point in [upper, lower] {
            assert!(point.x >= 12.0_f32);
            assert!(point.x + size.x <= screen.right() - 12.0_f32);
            assert!(point.y >= 12.0_f32);
            assert!(point.y + size.y <= screen.bottom() - 12.0_f32);
        }
    }

    #[test]
    fn selection_survives_deferred_copy() {
        let ctx = Context::default();
        let field = Id::new("selection-test");
        let range = CCursorRange::two(CCursor::new(1), CCursor::new(5));
        let mut text = String::from("selection test");

        let _ = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                TextEdit::singleline(&mut text).id(field).show(ui);

                let mut state = egui::text_edit::TextEditState::default();
                state.cursor.set_char_range(Some(range));
                state.store(ctx, field);
                queue_edit(ctx, field, Some(range), Event::Copy);
                restore_selection(ctx, field, Some(CCursorRange::one(CCursor::new(2))));

                let mut raw = RawInput::default();
                drain_edit_events(ctx, &mut raw);

                let restored = selection(ctx, field).expect("restored range");
                assert_eq!(restored.primary.index, range.primary.index);
                assert_eq!(restored.secondary.index, range.secondary.index);
                assert!(matches!(raw.events.last(), Some(Event::Copy)));
            });
        });
    }
}
