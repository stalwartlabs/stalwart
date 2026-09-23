/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use text_extract::Hints;
use types::media_type::media_type_essence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileContentKind {
    Document = 1,
    Html = 2,
    PlainText = 3,
}

impl FileContentKind {
    pub fn detect(file_name: &str, media_type: Option<&str>) -> Option<Self> {
        let essence = media_type.and_then(media_type_essence);
        let parts = essence
            .as_deref()
            .and_then(|essence| essence.split_once('/'));
        match parts {
            Some(("text", "html")) => return Some(FileContentKind::Html),
            Some(("text", "rtf")) => return Some(FileContentKind::Document),
            Some(("text", _)) => return Some(FileContentKind::PlainText),
            _ => {}
        }
        let mut hints = Hints::new().with_file_name(file_name);
        if let Some(media_type) = media_type {
            hints = hints.with_media_type(media_type);
        }
        if hints.format().is_some() {
            return Some(FileContentKind::Document);
        }
        match parts {
            Some(("application", "xhtml+xml")) => Some(FileContentKind::Html),
            None | Some(("application", "octet-stream")) => Self::from_extension(file_name),
            Some(("application", sub))
                if matches!(
                    sub,
                    "json" | "xml" | "javascript" | "x-sh" | "x-yaml" | "yaml" | "toml"
                ) || sub.ends_with("+json")
                    || sub.ends_with("+xml") =>
            {
                Some(FileContentKind::PlainText)
            }
            _ => None,
        }
    }

    fn from_extension(file_name: &str) -> Option<Self> {
        let (_, extension) = file_name.rsplit_once('.')?;
        hashify::map_ignore_case!(extension.as_bytes(), FileContentKind,
            b"html" => FileContentKind::Html,
            b"htm" => FileContentKind::Html,
            b"xhtml" => FileContentKind::Html,
            b"txt" => FileContentKind::PlainText,
            b"text" => FileContentKind::PlainText,
            b"md" => FileContentKind::PlainText,
            b"markdown" => FileContentKind::PlainText,
            b"rst" => FileContentKind::PlainText,
            b"csv" => FileContentKind::PlainText,
            b"tsv" => FileContentKind::PlainText,
            b"log" => FileContentKind::PlainText,
            b"json" => FileContentKind::PlainText,
            b"xml" => FileContentKind::PlainText,
            b"yaml" => FileContentKind::PlainText,
            b"yml" => FileContentKind::PlainText,
            b"toml" => FileContentKind::PlainText,
            b"ini" => FileContentKind::PlainText,
            b"conf" => FileContentKind::PlainText,
            b"cfg" => FileContentKind::PlainText,
            b"tex" => FileContentKind::PlainText,
            b"srt" => FileContentKind::PlainText,
            b"vtt" => FileContentKind::PlainText,
            b"sql" => FileContentKind::PlainText,
            b"sh" => FileContentKind::PlainText,
            b"py" => FileContentKind::PlainText,
            b"rs" => FileContentKind::PlainText,
            b"js" => FileContentKind::PlainText,
            b"ts" => FileContentKind::PlainText,
            b"css" => FileContentKind::PlainText,
            b"c" => FileContentKind::PlainText,
            b"h" => FileContentKind::PlainText,
            b"cpp" => FileContentKind::PlainText,
            b"java" => FileContentKind::PlainText,
            b"go" => FileContentKind::PlainText,
            b"rb" => FileContentKind::PlainText,
            b"php" => FileContentKind::PlainText,
        )
        .copied()
    }

    pub fn index_hash(kind: Option<Self>, blob_hash: &[u8]) -> u64 {
        blob_hash
            .first_chunk::<8>()
            .map_or(0, |bytes| u64::from_le_bytes(*bytes))
            ^ ((kind.map_or(0, |kind| kind as u64)) << 56)
    }
}

#[cfg(test)]
mod tests {
    use super::FileContentKind;

    #[test]
    fn content_kinds() {
        for (name, media_type, expected) in [
            ("a.docx", None, Some(FileContentKind::Document)),
            (
                "notes",
                Some("text/plain; charset=utf-8"),
                Some(FileContentKind::PlainText),
            ),
            ("page", Some("text/html"), Some(FileContentKind::Html)),
            (
                "data",
                Some("application/ld+json"),
                Some(FileContentKind::PlainText),
            ),
            ("photo.jpg", Some("image/jpeg"), None),
            ("notes.txt", None, Some(FileContentKind::PlainText)),
            (
                "notes.MD",
                Some("application/octet-stream"),
                Some(FileContentKind::PlainText),
            ),
            ("index.htm", None, Some(FileContentKind::Html)),
            ("archive.bin", None, None),
            ("noext", None, None),
            ("photo.txt", Some("image/png"), None),
            (
                "notes.rtf",
                Some("text/plain"),
                Some(FileContentKind::PlainText),
            ),
            (
                "notes.docx",
                Some("text/plain"),
                Some(FileContentKind::PlainText),
            ),
            ("notes", Some("text/rtf"), Some(FileContentKind::Document)),
            ("notes.rtf", None, Some(FileContentKind::Document)),
        ] {
            assert_eq!(
                FileContentKind::detect(name, media_type),
                expected,
                "{name} {media_type:?}"
            );
        }
        let hash = [7u8; 32];
        assert_ne!(
            FileContentKind::index_hash(None, &hash),
            FileContentKind::index_hash(Some(FileContentKind::PlainText), &hash)
        );
        assert_ne!(
            FileContentKind::index_hash(Some(FileContentKind::Html), &hash),
            FileContentKind::index_hash(Some(FileContentKind::PlainText), &hash)
        );
    }
}
