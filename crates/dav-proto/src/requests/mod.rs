/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{tokenizer::Tokenizer, DavParser, RawElement, Token},
    schema::Namespace,
};
use types::dead_property::{DeadElementTag, DeadProperty, DeadPropertyTag};

pub mod acl;
pub mod lockinfo;
pub mod mkcol;
pub mod propertyupdate;
pub mod propfind;
pub mod report;

impl DavParser for DeadProperty {
    fn parse(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Self> {
        let mut depth = 1;
        let mut items = DeadProperty::default();

        loop {
            match stream.token()? {
                Token::ElementStart { raw, .. } | Token::UnknownElement(raw) => {
                    items.0.push(DeadPropertyTag::ElementStart((&raw).into()));
                    depth += 1;
                }
                Token::ElementEnd => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                    items.0.push(DeadPropertyTag::ElementEnd);
                }
                Token::Text(text) => {
                    items.0.push(DeadPropertyTag::Text(text.into_owned()));
                }
                Token::Bytes(bytes) => {
                    items.0.push(DeadPropertyTag::Text(
                        String::from_utf8_lossy(&bytes).into_owned(),
                    ));
                }
                Token::Eof => {
                    break;
                }
            }
        }

        Ok(items)
    }
}

pub trait NsDeadProperty {
    fn single_with_ns(namespace: Namespace, name: &str) -> Self;
}

impl NsDeadProperty for DeadProperty {
    fn single_with_ns(namespace: Namespace, name: &str) -> Self {
        DeadProperty(vec![
            DeadPropertyTag::ElementStart(DeadElementTag {
                name: format!("{}:{name}", namespace.prefix()),
                attrs: None,
            }),
            DeadPropertyTag::ElementEnd,
        ])
    }
}

impl From<&RawElement<'_>> for DeadElementTag {
    fn from(raw: &RawElement<'_>) -> Self {
        let name = std::str::from_utf8(raw.element.local_name().as_ref())
            .unwrap_or("invalid-utf8")
            .trim_ascii()
            .to_string();
        let mut attrs = String::with_capacity(raw.element.attributes_raw().len());
        if let Some(namespace) = &raw.namespace {
            attrs.push_str("xmlns=\"");
            attrs.push_str(std::str::from_utf8(namespace).unwrap_or("invalid-utf8"));
            attrs.push('"');
        }

        for attr in raw.element.attributes().flatten() {
            if attr.key.as_ref() == b"xmlns" || attr.key.as_ref().starts_with(b"xmlns:") {
                // Skip namespace attributes
                continue;
            }
            if let (Ok(key), Ok(value)) = (
                std::str::from_utf8(attr.key.as_ref()),
                std::str::from_utf8(attr.value.as_ref()),
            ) {
                if !attrs.is_empty() {
                    attrs.push(' ');
                }
                attrs.push_str(key);
                attrs.push('=');
                attrs.push('"');
                attrs.push_str(value);
                attrs.push('"');
            }
        }

        DeadElementTag {
            name,
            attrs: (!attrs.is_empty()).then_some(attrs),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        parser::{tokenizer::Tokenizer, DavParser},
        schema::request::{Acl, LockInfo, MkCol, PropFind, PropertyUpdate, Report},
    };

    #[test]
    fn parse_requests() {
        for entry in std::fs::read_dir("resources/requests").unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();

            if path.extension().map(|ext| ext == "xml").unwrap_or(false) {
                println!("Parsing: {:?}", path);
                let filename = path.file_name().unwrap().to_str().unwrap();
                let xml = std::fs::read_to_string(&path).unwrap();
                let mut tokenizer = Tokenizer::new(xml.as_bytes());

                let json_path = path.with_extension("json");
                let json_output = match filename.split_once('-').unwrap().0 {
                    "propfind" => match PropFind::parse(&mut tokenizer) {
                        Ok(propfind) => serde_json::to_string_pretty(&propfind).unwrap(),
                        Err(_) => String::new(),
                    },
                    "propertyupdate" => serde_json::to_string_pretty(
                        &PropertyUpdate::parse(&mut tokenizer).unwrap(),
                    )
                    .unwrap(),
                    "mkcol" => serde_json::to_string_pretty(&MkCol::parse(&mut tokenizer).unwrap())
                        .unwrap(),
                    "lockinfo" => {
                        serde_json::to_string_pretty(&LockInfo::parse(&mut tokenizer).unwrap())
                            .unwrap()
                    }
                    "report" => {
                        serde_json::to_string_pretty(&Report::parse(&mut tokenizer).unwrap())
                            .unwrap()
                    }
                    "acl" => {
                        serde_json::to_string_pretty(&Acl::parse(&mut tokenizer).unwrap()).unwrap()
                    }
                    _ => {
                        panic!("Unknown method: {}", filename);
                    }
                };

                /*if json_path.exists() {
                    let expected = std::fs::read_to_string(json_path).unwrap();
                    assert_eq!(json_output, expected);
                } else {*/
                std::fs::write(json_path, json_output).unwrap();
                //}
            }
        }
    }
}
