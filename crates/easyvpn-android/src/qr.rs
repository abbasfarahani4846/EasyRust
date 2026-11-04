//! QR decoding independent of Android and JNI.

/// Decodes the first readable QR code in an eight-bit luminance plane.
///
/// Rows may contain padding. Invalid dimensions, truncated buffers and images
/// larger than 4096 pixels on either axis are rejected before accessing pixels.
pub fn decode_qr_luma(
    luma: &[u8],
    width: usize,
    height: usize,
    row_stride: usize,
) -> Option<String> {
    if width == 0 || height == 0 || width > 4096 || height > 4096 || row_stride < width {
        return None;
    }
    let required = (height - 1).checked_mul(row_stride)?.checked_add(width)?;
    if luma.len() < required {
        return None;
    }

    let mut image =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luma[y * row_stride + x]);
    image
        .detect_grids()
        .into_iter()
        .find_map(|grid| grid.decode().ok().map(|(_, content)| content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::{types::Color, QrCode};

    #[test]
    fn decodes_qr_with_padded_rows() {
        let content = "https://example.com/sub?token=easyvpn";
        let code = QrCode::new(content.as_bytes()).expect("valid QR content");
        let scale = 6;
        let quiet_zone = 4;
        let width = (code.width() + quiet_zone * 2) * scale;
        let height = width;
        let stride = width + 17;
        let mut luma = vec![255; stride * height];

        for y in 0..code.width() {
            for x in 0..code.width() {
                if code[(x, y)] == Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = (x + quiet_zone) * scale + dx;
                            let py = (y + quiet_zone) * scale + dy;
                            luma[py * stride + px] = 0;
                        }
                    }
                }
            }
        }

        assert_eq!(
            decode_qr_luma(&luma, width, height, stride).as_deref(),
            Some(content)
        );
        // The final row's padding is not required by Android's Y-plane contract.
        luma.truncate((height - 1) * stride + width);
        assert_eq!(
            decode_qr_luma(&luma, width, height, stride).as_deref(),
            Some(content)
        );
    }

    #[test]
    fn rejects_invalid_planes() {
        assert_eq!(decode_qr_luma(&[], 0, 0, 0), None);
        assert_eq!(decode_qr_luma(&[255; 16], 4, 4, 3), None);
        assert_eq!(decode_qr_luma(&[255; 15], 4, 4, 4), None);
        assert_eq!(decode_qr_luma(&[], usize::MAX, 2, usize::MAX), None);
        assert_eq!(decode_qr_luma(&[255; 64], 8, 8, 8), None);
    }
}
