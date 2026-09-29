/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::resources_dir;
use email::message::metadata::{ExtraHeaders, MessageMetadata, MetadataRow};
use imap::op::fetch::{
    FetchNeeds,
    source::DecodedSources,
    structure::{Binary, ImapMetadata},
};
use imap_proto::{
    ResponseCode, StatusResponse,
    protocol::fetch::{Attribute, BodyContents, DataItem, Section},
};
use mail_parser::MessageParser;
use std::{borrow::Cow, fs};
use store::Deserialize;
use types::blob_hash::BlobHash;

pub fn test() {
    println!("Running BODYSTRUCTURE...");

    let mut failed = Vec::new();
    for file_name in fs::read_dir(resources_dir()).unwrap() {
        let mut file_name = file_name.as_ref().unwrap().path();
        if file_name.extension().is_none_or(|e| e != "txt") {
            continue;
        }

        let mut buf = Vec::new();
        let raw_message = fs::read(&file_name).unwrap();
        let message = MessageParser::new().parse(&raw_message).unwrap();
        let row = MessageMetadata::build(
            &message,
            &ExtraHeaders::default(),
            BlobHash::generate(&raw_message),
        )
        .encode()
        .unwrap();
        let row = MetadataRow::deserialize(&row).unwrap();
        let metadata = row.unarchive().unwrap();
        let headers = row.raw_headers().unwrap();
        let raw = metadata.raw_message(Some(&headers), &raw_message);
        let body_only = metadata.raw_message(None, &raw_message);
        let section_b_mismatch = |label: &str, sections: String| {
            format!(
                "{}: {label} {sections} differs when FetchNeeds skips section B",
                file_name.display()
            )
        };
        let unknown_cte = |sections: &[u32]| {
            StatusResponse::no(format!(
                "Failed to decode part {} of message {}.",
                sections
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join("."),
                0
            ))
            .with_code(ResponseCode::UnknownCte)
            .serialize(Vec::new())
        };

        // Serialize body and bodystructure
        for (is_extended, is_utf8) in [(false, false), (true, false), (true, true)] {
            let mut buf_ = Vec::new();
            metadata.write_structure(&mut buf_, is_extended, is_utf8);
            if !is_extended {
                buf.extend_from_slice(b"BODY ");
            } else if !is_utf8 {
                buf.extend_from_slice(b"BODYSTRUCTURE ");
            } else {
                buf.extend_from_slice(b"BODYSTRUCTURE UTF8=ACCEPT ");
            }

            // Poor man's indentation
            let mut indent_count = 0;
            let mut in_quote = false;
            for ch in buf_ {
                if ch == b'(' && !in_quote {
                    buf.extend_from_slice(b"(\n");
                    indent_count += 1;
                    for _ in 0..indent_count {
                        buf.extend_from_slice(b"   ");
                    }
                } else if ch == b')' && !in_quote {
                    buf.push(b'\n');
                    indent_count -= 1;
                    for _ in 0..indent_count {
                        buf.extend_from_slice(b"   ");
                    }
                    buf.push(b')');
                } else {
                    if ch == b'"' {
                        in_quote = !in_quote;
                    }
                    buf.push(ch);
                }
            }
            buf.extend_from_slice(b"\n\n");
        }

        // Serialize body parts
        let mut iter = 1..9;
        let mut stack = Vec::new();
        let mut sections = Vec::new();
        loop {
            'inner: while let Some(part_id) = iter.next() {
                if part_id == 1 {
                    for section in [
                        None,
                        Some(Section::Header),
                        Some(Section::Text),
                        Some(Section::Mime),
                    ] {
                        let mut body_sections = sections
                            .iter()
                            .map(|id| Section::Part { num: *id })
                            .collect::<Vec<_>>();
                        let is_first = if let Some(section) = section {
                            body_sections.push(section);
                            false
                        } else {
                            true
                        };

                        let needs = FetchNeeds::new(&[Attribute::BodySection {
                            peek: true,
                            sections: body_sections.clone(),
                            partial: None,
                        }]);
                        if !needs.headers
                            && metadata
                                .body_section(
                                    raw,
                                    &mut DecodedSources::default(),
                                    &body_sections,
                                    None,
                                    None,
                                )
                                .map(|contents| contents.as_chained().to_vec())
                                != metadata
                                    .body_section(
                                        body_only,
                                        &mut DecodedSources::default(),
                                        &body_sections,
                                        None,
                                        None,
                                    )
                                    .map(|contents| contents.as_chained().to_vec())
                        {
                            failed.push(section_b_mismatch("BODY", format!("{body_sections:?}")));
                        }
                        if let Some(contents) = metadata.body_section(
                            raw,
                            &mut DecodedSources::default(),
                            &body_sections,
                            None,
                            None,
                        ) {
                            DataItem::BodySection {
                                sections: body_sections.into(),
                                origin_octet: None,
                                contents,
                            }
                            .serialize(&mut buf);

                            if is_first {
                                let needs = FetchNeeds::new(&[Attribute::Binary {
                                    peek: true,
                                    sections: sections.clone(),
                                    partial: None,
                                }]);
                                if !needs.headers
                                    && metadata
                                        .binary(
                                            raw,
                                            &mut DecodedSources::default(),
                                            &sections,
                                            None,
                                        )
                                        .map(|contents| contents.as_chained().to_vec())
                                        != metadata
                                            .binary(
                                                body_only,
                                                &mut DecodedSources::default(),
                                                &sections,
                                                None,
                                            )
                                            .map(|contents| contents.as_chained().to_vec())
                                {
                                    failed.push(section_b_mismatch(
                                        "BINARY",
                                        format!("{sections:?}"),
                                    ));
                                }
                                match metadata.binary(
                                    raw,
                                    &mut DecodedSources::default(),
                                    &sections,
                                    None,
                                ) {
                                    Binary::Found(contents) => {
                                        buf.push(b'\n');
                                        DataItem::Binary {
                                            sections: Cow::Borrowed(&sections),
                                            offset: None,
                                            contents: match contents {
                                                BodyContents::Text(text) => {
                                                    BodyContents::Text(text)
                                                }
                                                bytes => BodyContents::Text(
                                                    std::str::from_utf8(
                                                        &bytes.as_chained().to_vec(),
                                                    )
                                                    .unwrap_or("[binary content]")
                                                    .to_string()
                                                    .into(),
                                                ),
                                            },
                                        }
                                        .serialize(&mut buf);
                                    }
                                    Binary::Missing => (),
                                    Binary::UnknownCte => {
                                        buf.push(b'\n');
                                        buf.extend_from_slice(&unknown_cte(&sections));
                                    }
                                }

                                match metadata.binary_size(&sections) {
                                    Binary::Found(size) => {
                                        buf.push(b'\n');
                                        DataItem::BinarySize {
                                            sections: Cow::Borrowed(&sections),
                                            size,
                                        }
                                        .serialize(&mut buf);
                                    }
                                    Binary::Missing => (),
                                    Binary::UnknownCte => {
                                        buf.push(b'\n');
                                        buf.extend_from_slice(&unknown_cte(&sections));
                                    }
                                }
                            }

                            buf.extend_from_slice(b"\n----------------------------------\n");
                        } else if is_first {
                            break 'inner;
                        }
                    }
                }
                sections.push(part_id);
                stack.push(iter);
                iter = 1..9;
            }
            if let Some(prev_iter) = stack.pop() {
                sections.pop();
                iter = prev_iter;
            } else {
                break;
            }
        }

        // Check header fields and partial sections
        for sections in [
            vec![Section::HeaderFields {
                not: false,
                fields: vec!["From".into(), "To".into()],
            }],
            vec![Section::HeaderFields {
                not: true,
                fields: vec!["Subject".into(), "Cc".into()],
            }],
        ] {
            DataItem::BodySection {
                contents: metadata
                    .body_section(raw, &mut DecodedSources::default(), &sections, None, None)
                    .unwrap(),
                sections: Cow::Borrowed(&sections),
                origin_octet: None,
            }
            .serialize(&mut buf);
            buf.extend_from_slice(b"\n----------------------------------\n");
            DataItem::BodySection {
                contents: metadata
                    .body_section(
                        raw,
                        &mut DecodedSources::default(),
                        &sections,
                        (10, 25).into(),
                        None,
                    )
                    .unwrap(),
                sections: sections.into(),
                origin_octet: 10.into(),
            }
            .serialize(&mut buf);
            buf.extend_from_slice(b"\n----------------------------------\n");
        }

        file_name.set_extension("imap");

        let expected_result = fs::read(&file_name).unwrap_or_default();

        if buf != expected_result {
            file_name.set_extension("imap_failed");
            fs::write(&file_name, buf).unwrap();
            failed.push(file_name.display().to_string());
        }
    }

    assert!(
        failed.is_empty(),
        "Failed test, written output to {}",
        failed.join(", ")
    );
}
