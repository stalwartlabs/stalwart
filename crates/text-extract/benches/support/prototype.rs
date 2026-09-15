/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use quick_xml::{Reader, events::Event};
use std::io::{BufReader, Cursor, Read};
use zip::CompressionMethod;

const MAX_PART_BYTES: u64 = 64 << 20;
const MAX_TEXT_BYTES: usize = 4 << 20;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Docx,
    Xlsx,
    Pptx,
    Odf,
    Epub,
}

pub fn extract(data: &[u8]) -> Option<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
    let names: Vec<String> = archive.file_names().map(str::to_owned).collect();
    let has = |name: &str| names.iter().any(|candidate| candidate == name);
    let kind = if has("word/document.xml") {
        Kind::Docx
    } else if has("xl/workbook.xml") {
        Kind::Xlsx
    } else if has("ppt/presentation.xml") {
        Kind::Pptx
    } else if has("content.xml") {
        Kind::Odf
    } else if has("META-INF/container.xml") {
        Kind::Epub
    } else {
        return None;
    };
    let mut parts: Vec<&String> = names
        .iter()
        .filter(|name| match kind {
            Kind::Docx => {
                name.starts_with("word/")
                    && name.ends_with(".xml")
                    && [
                        "document",
                        "header",
                        "footer",
                        "footnotes",
                        "endnotes",
                        "comments",
                    ]
                    .iter()
                    .any(|prefix| name[5..].starts_with(prefix))
            }
            Kind::Xlsx => {
                name.as_str() == "xl/sharedStrings.xml" || name.starts_with("xl/worksheets/sheet")
            }
            Kind::Pptx => {
                (name.starts_with("ppt/slides/slide")
                    || name.starts_with("ppt/notesSlides/notesSlide"))
                    && name.ends_with(".xml")
            }
            Kind::Odf => name.as_str() == "content.xml" || name.as_str() == "styles.xml",
            Kind::Epub => name.ends_with(".xhtml") || name.ends_with(".html"),
        })
        .collect();
    parts.sort_by_key(|name| {
        let digits: String = name.chars().filter(char::is_ascii_digit).collect();
        (digits.parse::<u64>().unwrap_or(0), (*name).clone())
    });
    let mut out = String::new();
    for name in parts {
        if out.len() >= MAX_TEXT_BYTES {
            break;
        }
        let file = archive.by_name(name).ok()?;
        if !matches!(
            file.compression(),
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return None;
        }
        xml_text(file.take(MAX_PART_BYTES), kind, &mut out);
        out.push('\n');
    }
    Some(out)
}

fn xml_text<R: Read>(source: R, kind: Kind, out: &mut String) {
    let mut reader = Reader::from_reader(BufReader::new(source));
    let config = reader.config_mut();
    config.check_end_names = false;
    config.expand_empty_elements = false;
    let mut buf = Vec::new();
    let mut in_text = 0u32;
    let mut skip = 0u32;
    let text_elements: &[&[u8]] = match kind {
        Kind::Docx | Kind::Pptx => &[b"t"],
        Kind::Xlsx => &[b"t", b"v"],
        Kind::Odf | Kind::Epub => &[],
    };
    let skip_elements: &[&[u8]] = match kind {
        Kind::Docx => &[b"delText", b"instrText"],
        Kind::Xlsx => &[b"rPh"],
        Kind::Epub => &[b"script", b"style", b"head"],
        _ => &[],
    };
    loop {
        if out.len() >= MAX_TEXT_BYTES {
            return;
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(element)) => {
                let local = element.local_name();
                if skip_elements.contains(&local.as_ref()) {
                    skip += 1;
                } else if text_elements.contains(&local.as_ref()) {
                    in_text += 1;
                }
            }
            Ok(Event::Empty(element)) => match element.local_name().as_ref() {
                b"tab" => out.push('\t'),
                b"br" | b"cr" | b"line-break" => out.push('\n'),
                b"s" if kind == Kind::Odf => out.push(' '),
                _ => {}
            },
            Ok(Event::End(element)) => {
                let local = element.local_name();
                if skip_elements.contains(&local.as_ref()) {
                    skip = skip.saturating_sub(1);
                } else if text_elements.contains(&local.as_ref()) {
                    in_text = in_text.saturating_sub(1);
                    out.push(' ');
                }
                if matches!(
                    local.as_ref(),
                    b"p" | b"h" | b"tr" | b"row" | b"div" | b"li" | b"si"
                ) {
                    out.push('\n');
                }
            }
            Ok(Event::Text(text)) => {
                let collect = skip == 0
                    && match kind {
                        Kind::Odf | Kind::Epub => true,
                        _ => in_text > 0,
                    };
                if collect && let Ok(decoded) = text.decode() {
                    out.push_str(&decoded);
                }
            }
            Ok(Event::GeneralRef(reference)) if skip == 0 => {
                if let Ok(Some(ch)) = reference.resolve_char_ref() {
                    out.push(ch);
                }
            }
            Ok(Event::Eof) | Err(_) => return,
            Ok(_) => {}
        }
        buf.clear();
    }
}

pub fn epub_html_to_text(data: &[u8]) -> Option<String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
    let names: Vec<String> = archive
        .file_names()
        .filter(|name| name.ends_with(".xhtml") || name.ends_with(".html"))
        .map(str::to_owned)
        .collect();
    let mut out = String::new();
    let mut chapter = String::new();
    for name in names {
        chapter.clear();
        archive
            .by_name(&name)
            .ok()?
            .take(MAX_PART_BYTES)
            .read_to_string(&mut chapter)
            .ok()?;
        out.push_str(&mail_parser::decoders::html::html_to_text(&chapter));
        out.push('\n');
    }
    Some(out)
}
