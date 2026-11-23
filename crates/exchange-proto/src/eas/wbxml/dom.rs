/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    DecodeError, Decoder, Event, HEADER, OPAQUE, STR_I, SWITCH_PAGE, TAG_CONTENT, WbxmlLimits,
    encoder::write_mb_u_int32,
};
use crate::{
    common::{base64::base64_encode_into, xml::escape_text},
    eas::tokens::{Tag, ValueEncoding, page_name},
};
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    None,
    Text(Vec<u8>),
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub tag: Tag,
    pub value: Value,
    pub children: Vec<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Document {
    pub nodes: Vec<Node>,
}

impl Document {
    pub fn parse(body: &[u8], limits: &WbxmlLimits) -> Result<Self, DecodeError> {
        let mut decoder = Decoder::new(body, limits)?;
        let mut document = Document::default();
        let mut stack: Vec<usize> = Vec::new();
        loop {
            match decoder.next()? {
                Event::Start { tag, .. } => {
                    let index = document.nodes.len();
                    document.nodes.push(Node {
                        tag,
                        value: Value::None,
                        children: Vec::new(),
                    });
                    if let Some(parent) = stack.last().and_then(|&p| document.nodes.get_mut(p)) {
                        parent.children.push(index);
                    }
                    stack.push(index);
                }
                Event::Text(text) => document.append(stack.last().copied(), text, false),
                Event::Opaque(data) => document.append(stack.last().copied(), data, true),
                Event::End => {
                    stack.pop();
                }
                Event::Eof => return Ok(document),
            }
        }
    }

    fn append(&mut self, node: Option<usize>, data: &[u8], opaque: bool) {
        let Some(node) = node.and_then(|n| self.nodes.get_mut(n)) else {
            return;
        };
        match &mut node.value {
            Value::Text(existing) if opaque => {
                let mut merged = std::mem::take(existing);
                merged.extend_from_slice(data);
                node.value = Value::Opaque(merged);
            }
            Value::Text(existing) | Value::Opaque(existing) => existing.extend_from_slice(data),
            value @ Value::None => {
                *value = if opaque {
                    Value::Opaque(data.to_vec())
                } else {
                    Value::Text(data.to_vec())
                }
            }
        }
    }

    pub fn root(&self) -> Option<&Node> {
        self.nodes.first()
    }

    pub fn to_xml(&self) -> String {
        let mut out = String::new();
        let Some(root) = self.root() else {
            return out;
        };
        let mut pages: Vec<u8> = self.nodes.iter().map(|n| n.tag.page()).collect();
        pages.sort_unstable();
        pages.dedup();
        out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        let mut stack: Vec<(usize, usize, bool)> = vec![(0, 0, false)];
        while let Some((index, depth, closing)) = stack.pop() {
            let Some(node) = self.nodes.get(index) else {
                continue;
            };
            let indent = depth.saturating_mul(2);
            if closing {
                push_indent(&mut out, indent);
                out.push_str("</");
                push_name(&mut out, node.tag, root.tag.page());
                out.push_str(">\n");
                continue;
            }
            push_indent(&mut out, indent);
            out.push('<');
            push_name(&mut out, node.tag, root.tag.page());
            if index == 0 {
                for page in &pages {
                    let name = page_name(*page).unwrap_or("Unknown");
                    if *page == root.tag.page() {
                        let _ = write!(out, " xmlns=\"{name}\"");
                    } else {
                        let _ = write!(out, " xmlns:{}=\"{name}\"", name.to_ascii_lowercase());
                    }
                }
            }
            if matches!(node.value, Value::None) && node.children.is_empty() {
                out.push_str("/>\n");
                continue;
            }
            out.push('>');
            match &node.value {
                Value::Text(text) => {
                    let mut escaped = Vec::with_capacity(text.len());
                    escape_text(&String::from_utf8_lossy(text), &mut escaped);
                    out.push_str(&String::from_utf8_lossy(&escaped));
                }
                Value::Opaque(data) => {
                    let mut encoded = Vec::with_capacity(data.len().saturating_mul(2));
                    base64_encode_into(data, &mut encoded);
                    out.push_str(&String::from_utf8_lossy(&encoded));
                }
                Value::None => {}
            }
            if node.children.is_empty() {
                out.push_str("</");
                push_name(&mut out, node.tag, root.tag.page());
                out.push_str(">\n");
            } else {
                out.push('\n');
                stack.push((index, depth, true));
                let child_depth = depth.saturating_add(1);
                stack.extend(node.children.iter().rev().map(|&c| (c, child_depth, false)));
            }
        }
        out
    }

    pub fn to_wbxml(&self) -> Vec<u8> {
        let mut out = HEADER.to_vec();
        let mut page = 0u8;
        let mut stack: Vec<(usize, bool)> = vec![(0, false)];
        if self.nodes.is_empty() {
            return out;
        }
        while let Some((index, closing)) = stack.pop() {
            if closing {
                out.push(super::END);
                continue;
            }
            let Some(node) = self.nodes.get(index) else {
                continue;
            };
            if node.tag.page() != page {
                page = node.tag.page();
                out.extend_from_slice(&[SWITCH_PAGE, page]);
            }
            if matches!(node.value, Value::None) && node.children.is_empty() {
                out.push(node.tag.token());
                continue;
            }
            out.push(node.tag.token() | TAG_CONTENT);
            match &node.value {
                Value::Text(text) => {
                    out.push(STR_I);
                    out.extend_from_slice(text);
                    out.push(0);
                }
                Value::Opaque(data) => {
                    out.push(OPAQUE);
                    write_mb_u_int32(&mut out, u32::try_from(data.len()).unwrap_or(u32::MAX));
                    out.extend_from_slice(data);
                }
                Value::None => {}
            }
            stack.push((index, true));
            stack.extend(node.children.iter().rev().map(|&c| (c, false)));
        }
        out
    }

    pub fn is_opaque(tag: Tag) -> bool {
        tag.info().value == ValueEncoding::Opaque
    }
}

fn push_indent(out: &mut String, n: usize) {
    out.extend(std::iter::repeat_n(' ', n));
}

fn push_name(out: &mut String, tag: Tag, root_page: u8) {
    if tag.page() != root_page {
        out.push_str(
            &page_name(tag.page())
                .unwrap_or("unknown")
                .to_ascii_lowercase(),
        );
        out.push(':');
    }
    match tag.name() {
        Some(name) => out.push_str(name),
        None => {
            let _ = write!(out, "T{:02X}", tag.token());
        }
    }
}
