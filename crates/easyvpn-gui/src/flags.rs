use std::collections::{HashMap, HashSet};

use eframe::egui::{self, ColorImage, Rect, TextureHandle, TextureOptions, Ui};

include!(concat!(env!("OUT_DIR"), "/flags.rs"));

#[derive(Default)]
pub struct FlagCache {
    textures: HashMap<String, TextureHandle>,
    missing: HashSet<String>,
}

impl FlagCache {
    /// Returns false for missing or malformed assets, allowing an icon fallback.
    pub fn draw(&mut self, ui: &Ui, rect: Rect, code: &str) -> bool {
        let code = code.to_ascii_lowercase();
        if self.missing.contains(&code) {
            return false;
        }
        if !self.textures.contains_key(&code) {
            let decoded = flag_png(&code)
                .and_then(|bytes| image::load_from_memory_with_format(bytes, image::ImageFormat::Png).ok());
            let Some(image) = decoded else {
                self.missing.insert(code);
                return false;
            };
            let rgba = image.to_rgba8();
            let size = [rgba.width() as usize, rgba.height() as usize];
            let image = ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
            let texture = ui.ctx().load_texture(
                format!("country-flag-{code}"),
                image,
                TextureOptions::LINEAR,
            );
            self.textures.insert(code.clone(), texture);
        }
        if let Some(texture) = self.textures.get(&code) {
            egui::Image::new((texture.id(), rect.size()))
                .rounding(4.0_f32)
                .paint_at(ui, rect);
            true
        } else {
            false
        }
    }
}
