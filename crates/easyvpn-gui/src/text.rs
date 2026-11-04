use unicode_bidi::BidiInfo;
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayName {
    pub text: String,
    /// Lowercase ISO country codes, in their original order.
    pub flags: Vec<String>,
}

impl DisplayName {
    pub fn country(&self) -> Option<&str> {
        self.flags
            .iter()
            .find(|code| code.as_str() != "ir")
            .or_else(|| self.flags.first())
            .map(String::as_str)
    }
}

fn regional_indicator(c: char) -> Option<u8> {
    let value = u32::from(c);
    (0x1f1e6..=0x1f1ff)
        .contains(&value)
        .then(|| b'a' + (value - 0x1f1e6) as u8)
}

/// Prepare names for egui, which does not perform Arabic shaping or bidi layout.
/// This is display-only: never write the visual-order string back into the store.
pub fn display_name(raw: &str) -> DisplayName {
    let mut flags = Vec::new();
    let mut plain = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(first) = regional_indicator(c) {
            if let Some(second) = chars.peek().copied().and_then(regional_indicator) {
                chars.next();
                flags.push(String::from_iter([char::from(first), char::from(second)]));
                // Treat a removed flag as a separator rather than joining the
                // text on either side. Leading/trailing/repeated spaces are
                // collapsed below, after normalization and visual reordering.
                plain.push(' ');
                continue;
            }
        }
        plain.push(c);
    }

    let normalized: String = plain.nfkc().collect();
    let shaped = ar_reshaper::reshape_line(&normalized);
    let mut visual_lines = Vec::new();
    for line in shaped.lines() {
        let bidi = BidiInfo::new(line, None);
        let mut visual = String::new();
        for paragraph in &bidi.paragraphs {
            visual.push_str(&bidi.reorder_line(paragraph, paragraph.range.clone()));
        }
        visual_lines.push(visual);
    }
    let text = visual_lines
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    DisplayName { text, flags }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_and_compatibility_latin() {
        let name = display_name("🇺🇸𝗨𝗦𝗔🇮🇷AI🤖");
        assert_eq!(name.flags, ["us", "ir"]);
        assert_eq!(name.country(), Some("us"));
        assert_eq!(name.text, "USA AI🤖");
        assert_eq!(display_name("𝗚𝗲𝗿𝗺𝗮𝗻𝘆").text, "Germany");
    }

    #[test]
    fn removed_flags_separate_text_parts_with_one_space() {
        for raw in [
            "USA🇮🇷AI",
            "USA🇮🇷🇩🇪AI",
            "  🇺🇸USA 🇮🇷  AI🇩🇪  ",
            "USA\t🇮🇷\nAI",
        ] {
            assert_eq!(display_name(raw).text, "USA AI", "{raw}");
        }
        assert_eq!(display_name("🇺🇸USA🇮🇷").text, "USA");
        assert_eq!(display_name("🇺🇸🇮🇷").text, "");
    }

    #[test]
    fn persian_sample_is_shaped_and_reordered() {
        let name = display_name("🇩🇪🇮🇷هر موقع قطع شد‼بروزرسانی کن");
        assert_eq!(name.flags, ["de", "ir"]);
        assert_eq!(name.country(), Some("de"));
        assert!(!name.text.is_empty());
        assert!(name.text.contains("!!"));
        assert!(name
            .text
            .chars()
            .any(|c| { matches!(u32::from(c), 0xfb50..=0xfdff | 0xfe70..=0xfeff) }));
        assert!(!name.text.contains("بروزرسانی"));
    }

    #[test]
    fn monochrome_emoji_are_preserved() {
        let raw = "abbas4846👤(∞🔋)(∞📆)(✅)";
        let name = display_name(raw);
        assert_eq!(name.text, raw);
        assert!(name.flags.is_empty());
        assert_eq!(name.country(), None);
        assert_eq!(display_name("🤖 🎮 🚫").text, "🤖 🎮 🚫");
    }

    #[test]
    fn mixed_text_keeps_latin_runs_in_reading_order() {
        let name = display_name("Server 42 سلام VPN");
        assert!(name.text.contains("Server 42"));
        assert!(name.text.contains("VPN"));
        assert!(!name.text.contains("سلام"));
    }

    #[test]
    fn whitespace_and_country_preference() {
        assert_eq!(display_name("  a \n b\t c  ").text, "a b c");
        assert_eq!(display_name("🇮🇷🇮🇷").country(), Some("ir"));
        assert_eq!(display_name("🇮🇷🇫🇷🇩🇪").country(), Some("fr"));
        assert_eq!(display_name("🇩").text, "🇩");
        assert_eq!(display_name("").text, "");
    }
}
