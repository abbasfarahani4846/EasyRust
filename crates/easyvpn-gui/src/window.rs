use std::{
    fs,
    time::{Duration, Instant},
};

use easyvpn_core::store;
use eframe::egui::{
    self, viewport::ResizeDirection, Context, CursorIcon, Pos2, Rect, Vec2, ViewportCommand,
};
use serde_json::{json, Value};

const MIN_SIZE: Vec2 = egui::vec2(300.0_f32, 190.0_f32);
const MINI_MIN_SIZE: Vec2 = egui::vec2(300.0_f32, 80.0_f32);
const DEFAULT_SIZE: Vec2 = egui::vec2(420.0_f32, 760.0_f32);
const MINI_SIZE: Vec2 = egui::vec2(340.0_f32, 96.0_f32);
const MINI_EXIT_HEIGHT: f32 = 160.0_f32;

/// Geometry is kept separately from the connection/profile store.
pub struct WindowState {
    pub mini: bool,
    size: Vec2,
    position: Option<Pos2>,
    full_size: Vec2,
    dirty_since: Option<Instant>,
    checked_monitor: bool,
    resize_active: bool,
    mini_resize_pending: Option<Instant>,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            mini: false,
            size: DEFAULT_SIZE,
            position: None,
            full_size: DEFAULT_SIZE,
            dirty_since: None,
            checked_monitor: false,
            resize_active: false,
            mini_resize_pending: None,
        }
    }
}

fn pair(value: Option<&Value>) -> Option<[f32; 2]> {
    let values = value?.as_array()?;
    let x = values.first()?.as_f64()? as f32;
    let y = values.get(1)?.as_f64()? as f32;
    (x.is_finite() && y.is_finite()).then_some([x, y])
}

fn valid_size_for(size: Vec2, minimum: Vec2) -> bool {
    size.is_finite()
        && size.x >= minimum.x
        && size.y >= minimum.y
        && size.x <= 16384.0_f32
        && size.y <= 16384.0_f32
}

fn valid_size(size: Vec2) -> bool {
    valid_size_for(size, MIN_SIZE)
}

impl WindowState {
    fn from_json(value: &Value) -> Self {
        let mut state = Self {
            mini: value.get("mini").and_then(Value::as_bool).unwrap_or(false),
            ..Self::default()
        };
        if let Some([x, y]) = pair(value.get("full_size")) {
            let size = egui::vec2(x, y);
            if valid_size(size) {
                state.full_size = size;
            }
        }

        let saved_size = pair(value.get("size")).map(|[x, y]| egui::vec2(x, y));
        if let Some(size) = saved_size {
            let minimum = if state.mini { MINI_MIN_SIZE } else { MIN_SIZE };
            if valid_size_for(size, minimum) {
                state.size = size;
                if state.mini && size.y > MINI_EXIT_HEIGHT {
                    state.mini = false;
                    state.full_size = size;
                } else if !state.mini && size.y >= 360.0_f32 {
                    state.full_size = size;
                }
            }
        } else if state.mini {
            state.size = MINI_SIZE;
        }
        state.position = pair(value.get("position")).map(|[x, y]| egui::pos2(x, y));
        state
    }

    pub fn load() -> Self {
        fs::read(store::data_dir().join("gui.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .map(|value| Self::from_json(&value))
            .unwrap_or_default()
    }

    pub fn startup_size(&self) -> Vec2 {
        self.size
    }

    pub fn startup_position(&self) -> Option<Pos2> {
        self.position
    }

    pub fn is_mini(&self, size: Vec2) -> bool {
        self.mini || size.y < 360.0_f32
    }

    pub fn save(&mut self) {
        let path = store::data_dir().join("gui.json");
        let value = json!({
            "size": [self.size.x, self.size.y],
            "position": self.position.map(|p| [p.x, p.y]),
            "full_size": [self.full_size.x, self.full_size.y],
            "mini": self.mini,
        });
        if let Ok(bytes) = serde_json::to_vec_pretty(&value) {
            let temporary = path.with_extension("json.tmp");
            if fs::write(&temporary, bytes).is_ok()
                && fs::rename(&temporary, &path).is_err()
            {
                let _ = fs::remove_file(&path);
                let _ = fs::rename(&temporary, &path);
            }
        }
        self.dirty_since = None;
    }

    pub fn enter_mini(&mut self, ctx: &Context) {
        let size = ctx.input(|i| i.viewport().inner_rect.map(|r| r.size()));
        if !self.mini {
            if let Some(size) = size.filter(|s| valid_size(*s)) {
                self.full_size = size;
            }
        }
        self.mini = true;
        self.size = MINI_SIZE;
        // Viewport commands take effect asynchronously. Do not mistake the
        // previous full-sized frame for a user resize before acknowledging it.
        self.mini_resize_pending = Some(Instant::now());
        ctx.send_viewport_cmd(ViewportCommand::MinInnerSize(MINI_MIN_SIZE));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize(MINI_SIZE));
        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
            egui::viewport::WindowLevel::AlwaysOnTop,
        ));
        self.save();
    }

    pub fn restore(&mut self, ctx: &Context) {
        self.mini = false;
        self.mini_resize_pending = None;
        self.size = self.full_size;
        ctx.send_viewport_cmd(ViewportCommand::MinInnerSize(MIN_SIZE));
        ctx.send_viewport_cmd(ViewportCommand::InnerSize(self.full_size));
        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
            egui::viewport::WindowLevel::Normal,
        ));
        self.save();
    }

    fn leave_mini_at_current_size(&mut self, ctx: &Context, size: Vec2) {
        self.mini = false;
        self.mini_resize_pending = None;
        self.size = size;
        self.full_size = size;
        ctx.send_viewport_cmd(ViewportCommand::MinInnerSize(MIN_SIZE));
        ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
            egui::viewport::WindowLevel::Normal,
        ));
        self.save();
    }

    pub fn toggle(&mut self, ctx: &Context) {
        if self.is_mini(ctx.screen_rect().size()) {
            self.restore(ctx);
        } else {
            self.enter_mini(ctx);
        }
    }

    /// Called before any drag zones or page widgets are registered.
    pub fn begin_frame(&mut self, ctx: &Context) {
        let (inner, outer, monitor, pointer, pressed, down) = ctx.input(|i| {
            (
                i.viewport().inner_rect,
                i.viewport().outer_rect,
                i.viewport().monitor_size,
                i.pointer.hover_pos(),
                i.pointer.primary_pressed(),
                i.pointer.primary_down(),
            )
        });

        if !self.checked_monitor {
            self.checked_monitor = true;
            ctx.send_viewport_cmd(ViewportCommand::MinInnerSize(
                if self.mini { MINI_MIN_SIZE } else { MIN_SIZE },
            ));
            ctx.send_viewport_cmd(ViewportCommand::WindowLevel(
                if self.mini {
                    egui::viewport::WindowLevel::AlwaysOnTop
                } else {
                    egui::viewport::WindowLevel::Normal
                },
            ));
            if let (Some(rect), Some(monitor)) = (outer, monitor) {
                let screen = Rect::from_min_size(Pos2::ZERO, monitor);
                if !screen.intersects(rect) {
                    let minimum = if self.mini { MINI_MIN_SIZE } else { MIN_SIZE };
                    let size = self.startup_size().min(monitor).max(minimum);
                    ctx.send_viewport_cmd(ViewportCommand::InnerSize(size));
                    ctx.send_viewport_cmd(ViewportCommand::OuterPosition(egui::pos2(
                        ((monitor.x - size.x) / 2.0_f32).max(0.0_f32),
                        ((monitor.y - size.y) / 2.0_f32).max(0.0_f32),
                    )));
                }
            }
        }

        if let Some(rect) = inner {
            if self.mini {
                if rect.height() <= MINI_EXIT_HEIGHT {
                    self.mini_resize_pending = None;
                }
                let waiting = self.mini_resize_pending
                    .is_some_and(|time| time.elapsed() < Duration::from_secs(1));
                if rect.height() > MINI_EXIT_HEIGHT
                    && valid_size_for(rect.size(), MINI_MIN_SIZE)
                    && !waiting
                {
                    self.leave_mini_at_current_size(ctx, rect.size());
                }
                if waiting {
                    ctx.request_repaint_after(Duration::from_millis(50));
                }
            }
        }

        let old = (self.size, self.position);
        if self.mini_resize_pending.is_none() {
            if let Some(rect) = inner {
                let minimum = if self.mini { MINI_MIN_SIZE } else { MIN_SIZE };
                if valid_size_for(rect.size(), minimum) {
                    self.size = rect.size();
                    if !self.mini && self.size.y >= 360.0_f32 {
                        self.full_size = self.size;
                    }
                }
            }
        }
        if let Some(rect) = outer {
            if rect.min.is_finite() {
                self.position = Some(rect.min);
            }
        }
        if old != (self.size, self.position) {
            self.dirty_since = Some(Instant::now());
        }
        if self.dirty_since.is_some_and(|time| time.elapsed() >= Duration::from_millis(500)) {
            self.save();
        }
        if self.dirty_since.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }

        if !down {
            self.resize_active = false;
        }
        let hit = pointer.and_then(|p| resize_hit(ctx.screen_rect(), p));
        if let Some((direction, cursor)) = hit {
            ctx.set_cursor_icon(cursor);
            if pressed {
                self.resize_active = true;
                ctx.send_viewport_cmd(ViewportCommand::BeginResize(direction));
            }
        }
        ctx.data_mut(|data| {
            data.insert_temp(
                egui::Id::new("resize-zone"),
                hit.is_some() || self.resize_active,
            )
        });
    }

    pub fn can_drag(ctx: &Context) -> bool {
        !ctx.data(|data| {
            data.get_temp::<bool>(egui::Id::new("resize-zone")).unwrap_or(false)
        })
    }
}

pub fn resize_hit(rect: Rect, p: Pos2) -> Option<(ResizeDirection, CursorIcon)> {
    if !rect.contains(p) {
        return None;
    }
    let left = p.x - rect.left();
    let right = rect.right() - p.x;
    let top = p.y - rect.top();
    let bottom = rect.bottom() - p.y;
    if left <= 12.0_f32 && top <= 12.0_f32 {
        Some((ResizeDirection::NorthWest, CursorIcon::ResizeNwSe))
    } else if right <= 12.0_f32 && top <= 12.0_f32 {
        Some((ResizeDirection::NorthEast, CursorIcon::ResizeNeSw))
    } else if left <= 12.0_f32 && bottom <= 12.0_f32 {
        Some((ResizeDirection::SouthWest, CursorIcon::ResizeNeSw))
    } else if right <= 12.0_f32 && bottom <= 12.0_f32 {
        Some((ResizeDirection::SouthEast, CursorIcon::ResizeNwSe))
    } else if left <= 6.0_f32 {
        Some((ResizeDirection::West, CursorIcon::ResizeHorizontal))
    } else if right <= 6.0_f32 {
        Some((ResizeDirection::East, CursorIcon::ResizeHorizontal))
    } else if top <= 6.0_f32 {
        Some((ResizeDirection::North, CursorIcon::ResizeVertical))
    } else if bottom <= 6.0_f32 {
        Some((ResizeDirection::South, CursorIcon::ResizeVertical))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corners_take_priority_over_edges() {
        let rect = Rect::from_min_size(Pos2::ZERO, DEFAULT_SIZE);
        assert!(matches!(
            resize_hit(rect, egui::pos2(10.0_f32, 10.0_f32)),
            Some((ResizeDirection::NorthWest, _))
        ));
        assert!(matches!(
            resize_hit(rect, egui::pos2(419.0_f32, 400.0_f32)),
            Some((ResizeDirection::East, _))
        ));
        assert!(resize_hit(rect, rect.center()).is_none());
        assert!(resize_hit(rect, egui::pos2(-1.0_f32, 0.0_f32)).is_none());
    }

    #[test]
    fn invalid_geometry_is_rejected() {
        assert!(!valid_size(egui::vec2(f32::NAN, 760.0_f32)));
        assert!(!valid_size(egui::vec2(299.0_f32, 190.0_f32)));
        assert!(valid_size(MIN_SIZE));
        assert!(pair(Some(&json!([null, 2]))).is_none());
    }

    #[test]
    fn mini_has_its_own_minimum() {
        assert!(!valid_size(MINI_SIZE));
        assert!(valid_size_for(MINI_SIZE, MINI_MIN_SIZE));
        assert!(valid_size_for(egui::vec2(300.0_f32, 80.0_f32), MINI_MIN_SIZE));
        assert!(!valid_size_for(egui::vec2(300.0_f32, 79.0_f32), MINI_MIN_SIZE));
    }

    #[test]
    fn saved_large_mini_window_starts_full_at_saved_size() {
        let state = WindowState::from_json(&json!({
            "mini": true,
            "size": [600, 700],
            "full_size": [420, 760],
        }));
        assert!(!state.mini);
        assert_eq!(state.startup_size(), egui::vec2(600.0_f32, 700.0_f32));
        assert_eq!(state.full_size, state.startup_size());
    }

    #[test]
    fn saved_small_mini_preserves_full_size() {
        let state = WindowState::from_json(&json!({
            "mini": true,
            "size": [340, 96],
            "full_size": [420, 760],
        }));
        assert!(state.mini);
        assert_eq!(state.startup_size(), MINI_SIZE);
        assert_eq!(state.full_size, DEFAULT_SIZE);
    }

    #[test]
    fn mini_exit_threshold_is_strict() {
        let small = WindowState::from_json(&json!({"mini": true, "size": [340, 160]}));
        let large = WindowState::from_json(&json!({"mini": true, "size": [340, 161]}));
        assert!(small.mini);
        assert!(!large.mini);
        assert_eq!(large.full_size, egui::vec2(340.0_f32, 161.0_f32));
    }

    #[test]
    fn live_resize_leaves_mini_without_restoring_old_geometry() {
        let ctx = Context::default();
        let mut state = WindowState {
            mini: true,
            size: MINI_SIZE,
            ..Default::default()
        };
        let size = egui::vec2(500.0_f32, 600.0_f32);
        state.leave_mini_at_current_size(&ctx, size);
        assert!(!state.mini);
        assert_eq!(state.size, size);
        assert_eq!(state.full_size, size);
    }
}
