/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::sniff::{SniffPrefix, Sniffed};
use mail_parser::MessagePart;
use sieve::{Context, runtime::Variable};

pub trait ImageMetadata {
    fn image_metadata(&self, property: &str) -> Option<Variable<'static>>;
}

pub fn fn_img_metadata<'x>(ctx: &Context<'x>, v: &[Variable<'x>]) -> Variable<'x> {
    let property = v[1].to_string();
    ctx.message()
        .part(ctx.part())
        .and_then(|part| part.image_metadata(&property))
        .unwrap_or_default()
}

impl ImageMetadata for MessagePart<'_> {
    fn image_metadata(&self, property: &str) -> Option<Variable<'static>> {
        match self.sniff() {
            Sniffed::Whole(bytes) => image_property(&bytes, property),
            Sniffed::Prefix(prefix) => image_property(&prefix, property)
                .or_else(|| image_property(&self.decoded(), property)),
        }
    }
}

fn image_property(bytes: &[u8], property: &str) -> Option<Variable<'static>> {
    match property {
        "type" => imagesize::image_type(bytes).ok().map(|t| {
            Variable::from(match t {
                imagesize::ImageType::Aseprite => "aseprite",
                imagesize::ImageType::Bmp => "bmp",
                imagesize::ImageType::Dds(_) => "dds",
                imagesize::ImageType::Exr => "exr",
                imagesize::ImageType::Farbfeld => "farbfeld",
                imagesize::ImageType::Gif => "gif",
                imagesize::ImageType::Hdr => "hdr",
                imagesize::ImageType::Heif(_) => "heif",
                imagesize::ImageType::Ico => "ico",
                imagesize::ImageType::Jpeg => "jpeg",
                imagesize::ImageType::Jxl => "jxl",
                imagesize::ImageType::Ktx2 => "ktx2",
                imagesize::ImageType::Png => "png",
                imagesize::ImageType::Pnm => "pnm",
                imagesize::ImageType::Psd => "psd",
                imagesize::ImageType::Qoi => "qoi",
                imagesize::ImageType::Tga => "tga",
                imagesize::ImageType::Tiff => "tiff",
                imagesize::ImageType::Vtf => "vtf",
                imagesize::ImageType::Webp => "webp",
                imagesize::ImageType::Ilbm => "ilbm",
                _ => "unknown",
            })
        }),
        "width" => imagesize::blob_size(bytes)
            .ok()
            .map(|s| Variable::Integer(s.width as i64)),
        "height" => imagesize::blob_size(bytes)
            .ok()
            .map(|s| Variable::Integer(s.height as i64)),
        "area" => imagesize::blob_size(bytes)
            .ok()
            .map(|s| Variable::Integer(s.width.saturating_mul(s.height) as i64)),
        "dimension" => imagesize::blob_size(bytes)
            .ok()
            .map(|s| Variable::Integer(s.width.saturating_add(s.height) as i64)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ImageMetadata, image_property};
    use crate::scripts::functions::sniff::{SNIFF_WINDOW, SniffPrefix, Sniffed};
    use mail_parser::MessageParser;

    #[test]
    fn prefix_metadata_matches_whole_body() {
        let mut png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x2c\x00\x00\x00\xc8\x08\x02\x00\x00\x00"
            .to_vec();
        png.resize(SNIFF_WINDOW * 3, 0x41);
        let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF];
        jpeg.resize(jpeg.len() + 65533, 0);
        jpeg.extend_from_slice(&[0xFF, 0xE2]);
        jpeg.extend_from_slice(&[0xFF, 0xFF]);
        jpeg.resize(jpeg.len() + 65533, 0);
        jpeg.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x40, 0x00, 0x80, 0x03]);
        jpeg.resize(jpeg.len() + SNIFF_WINDOW, 0);
        let small = png.get(..1024).expect("sample").to_vec();
        for body in [png, jpeg, small] {
            for encoding in ["base64", "quoted-printable", "binary"] {
                let encoded = match encoding {
                    "base64" => encodify::base64::MIME.encode(&body).into_bytes(),
                    "quoted-printable" => encodify::qp::BODY.encode(&body).into_bytes(),
                    _ => body.clone(),
                };
                let mut raw = format!(
                    "Content-Type: image/png\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n"
                )
                .into_bytes();
                raw.extend_from_slice(&encoded);
                let parsed = MessageParser::new().parse(&raw).expect("parses");
                let part = parsed.root_part();
                let decoded = part.decoded();
                assert_eq!(
                    matches!(part.sniff(), Sniffed::Whole(_)),
                    body.len() < SNIFF_WINDOW,
                    "{encoding}"
                );
                for property in ["type", "width", "height", "area", "dimension", "other"] {
                    let expected = image_property(&decoded, property);
                    assert_eq!(expected.is_some(), property != "other", "{property}");
                    assert_eq!(
                        part.image_metadata(property)
                            .map(|v| v.to_string().into_owned()),
                        expected.map(|v| v.to_string().into_owned()),
                        "{encoding} {property}"
                    );
                }
            }
        }
    }
}
