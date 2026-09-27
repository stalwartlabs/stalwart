/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Format,
    output::{Output, Separator},
    package::Package,
    xml::{
        Handler, Skip, Tag, Text,
        attr::{push_decoded, split_prefix},
    },
};

pub(crate) const CONTENT: &[u8] = b"content.xml";
const STYLES: &[u8] = b"styles.xml";
const OBJECT_CONTENT: &[u8] = b"/content.xml";

pub(crate) fn format_from_mimetype(mimetype: &[u8]) -> Option<Format> {
    hashify::map!(mimetype.trim_ascii(), Format,
        b"application/vnd.oasis.opendocument.text" => Format::Odt,
        b"application/vnd.oasis.opendocument.text-template" => Format::Odt,
        b"application/vnd.oasis.opendocument.text-master" => Format::Odt,
        b"application/vnd.oasis.opendocument.text-master-template" => Format::Odt,
        b"application/vnd.oasis.opendocument.text-web" => Format::Odt,
        b"application/vnd.oasis.opendocument.spreadsheet" => Format::Ods,
        b"application/vnd.oasis.opendocument.spreadsheet-template" => Format::Ods,
        b"application/vnd.oasis.opendocument.presentation" => Format::Odp,
        b"application/vnd.oasis.opendocument.presentation-template" => Format::Odp,
    )
    .copied()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Element {
    Body,
    MasterStyles,
    TextBody,
    SpreadsheetBody,
    PresentationBody,
    Ignored(Ignored),
    Space,
    Newline,
    Block,
    Frame,
    Boundary,
    PageField,
    Cell,
    Table,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ignored {
    TrackedChanges,
    BinaryData,
    IndexSource,
    Metadata,
}

impl Element {
    fn classify(name: &[u8]) -> Option<Element> {
        let (_, local) = split_prefix(name);
        match Element::parse(local) {
            Some(Element::Ignored(Ignored::Metadata)) => {
                let prefix = name.get(..name.len() - local.len()).unwrap_or_default();
                hashify::set!(prefix, b"dc:", b"meta:")
                    .then_some(Element::Ignored(Ignored::Metadata))
            }
            element => element,
        }
    }

    fn parse(local: &[u8]) -> Option<Element> {
        hashify::map!(local, Element,
            b"body" => Element::Body,
            b"master-styles" => Element::MasterStyles,
            b"header" => Element::Block,
            b"footer" => Element::Block,
            b"header-left" => Element::Block,
            b"footer-left" => Element::Block,
            b"header-first" => Element::Block,
            b"footer-first" => Element::Block,
            b"text" => Element::TextBody,
            b"spreadsheet" => Element::SpreadsheetBody,
            b"presentation" => Element::PresentationBody,
            b"tracked-changes" => Element::Ignored(Ignored::TrackedChanges),
            b"binary-data" => Element::Ignored(Ignored::BinaryData),
            b"table-of-content-source" => Element::Ignored(Ignored::IndexSource),
            b"alphabetical-index-source" => Element::Ignored(Ignored::IndexSource),
            b"illustration-index-source" => Element::Ignored(Ignored::IndexSource),
            b"table-index-source" => Element::Ignored(Ignored::IndexSource),
            b"object-index-source" => Element::Ignored(Ignored::IndexSource),
            b"user-index-source" => Element::Ignored(Ignored::IndexSource),
            b"bibliography-source" => Element::Ignored(Ignored::IndexSource),
            b"creator" => Element::Ignored(Ignored::Metadata),
            b"creator-initials" => Element::Ignored(Ignored::Metadata),
            b"date" => Element::Ignored(Ignored::Metadata),
            b"date-string" => Element::Ignored(Ignored::Metadata),
            b"s" => Element::Space,
            b"tab" => Element::Space,
            b"line-break" => Element::Newline,
            b"p" => Element::Newline,
            b"h" => Element::Newline,
            b"list-item" => Element::Block,
            b"table-row" => Element::Block,
            b"frame" => Element::Frame,
            b"page" => Element::Block,
            b"note-body" => Element::Block,
            b"annotation" => Element::Block,
            b"title" => Element::Block,
            b"desc" => Element::Block,
            b"note-citation" => Element::Space,
            b"ruby-text" => Element::Boundary,
            b"page-number" => Element::PageField,
            b"page-count" => Element::PageField,
            b"table-cell" => Element::Cell,
            b"covered-table-cell" => Element::Cell,
            b"table" => Element::Table,
        )
        .copied()
    }
}

struct OdfText {
    scope: Element,
    active: u32,
    skip: Skip<Element>,
    body_kind: Option<Format>,
    awaiting_body_kind: bool,
    requires_body_kind: bool,
    unsupported_body: bool,
}

impl OdfText {
    fn new(scope: Element, requires_body_kind: bool) -> Self {
        OdfText {
            scope,
            active: 0,
            skip: Skip::default(),
            body_kind: None,
            awaiting_body_kind: false,
            requires_body_kind,
            unsupported_body: false,
        }
    }
}

fn table_name<'a>(tag: &Tag<'a>) -> Option<&'a [u8]> {
    tag.attributes()
        .find_map(|(name, value)| match split_prefix(name) {
            (true, local) if hashify::set!(local, b"name") => Some(value),
            _ => None,
        })
}

fn is_prompt_frame(tag: &Tag<'_>) -> bool {
    tag.attributes()
        .any(|(name, value)| match split_prefix(name) {
            (true, b"placeholder") => value == b"true",
            (true, b"class") => hashify::set!(
                value,
                b"title",
                b"subtitle",
                b"outline",
                b"notes",
                b"text",
                b"object",
                b"chart",
                b"table",
                b"graphic",
                b"orgchart",
                b"page",
                b"handout",
            ),
            _ => false,
        })
}

impl Handler for OdfText {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        let element = Element::classify(tag.name);
        if element == Some(self.scope) {
            self.active = self.active.saturating_add(1);
            self.awaiting_body_kind = self.scope == Element::Body;
            return;
        }
        if self.active == 0 || self.skip.on_start(element) {
            return;
        }
        if self.awaiting_body_kind {
            self.awaiting_body_kind = false;
            self.body_kind = match element {
                Some(Element::TextBody) => Some(Format::Odt),
                Some(Element::SpreadsheetBody) => Some(Format::Ods),
                Some(Element::PresentationBody) => Some(Format::Odp),
                _ => None,
            };
            self.unsupported_body = self.requires_body_kind && self.body_kind.is_none();
        }
        match element {
            Some(ignored @ Element::Ignored(_)) => self.skip.begin(ignored),
            Some(Element::PageField) if self.scope == Element::MasterStyles => {
                self.skip.begin(Element::PageField)
            }
            Some(Element::Frame) if self.scope == Element::MasterStyles && is_prompt_frame(tag) => {
                self.skip.begin(Element::Frame)
            }
            Some(Element::Space | Element::Boundary) => out.separator(Separator::Space),
            Some(Element::Newline) => out.separator(Separator::Newline),
            Some(Element::Table) if self.body_kind == Some(Format::Ods) => {
                if let Some(name) = table_name(tag) {
                    out.separator(Separator::Newline);
                    push_decoded(name, out);
                    out.separator(Separator::Newline);
                }
            }
            _ => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        let element = Element::classify(name);
        if element == Some(self.scope) {
            self.active = self.active.saturating_sub(1);
            return;
        }
        if self.active == 0 || self.skip.on_end(element) {
            return;
        }
        match element {
            Some(Element::Newline | Element::Block | Element::Frame) => {
                out.separator(Separator::Newline)
            }
            Some(Element::Cell | Element::Boundary) => out.separator(Separator::Space),
            _ => {}
        }
    }

    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        if self.active > 0 && !self.skip.active() {
            text.push(out);
        }
    }

    fn aborted(&self) -> bool {
        self.unsupported_body
    }
}

pub(crate) fn extract(
    package: &mut Package<'_, '_>,
    declared: Option<Format>,
    out: &mut Output<'_>,
) -> Option<Format> {
    let mut content = OdfText::new(Element::Body, declared.is_none());
    if !package.scan(CONTENT, &mut content, out) {
        return None;
    }
    let format = declared.or(content.body_kind)?;
    out.separator(Separator::Newline);
    package.scan(STYLES, &mut OdfText::new(Element::MasterStyles, false), out);
    out.separator(Separator::Newline);
    let archive = package.archive;
    for member in archive.members().filter(|member| {
        member.name.len() > OBJECT_CONTENT.len() && member.name.ends_with(OBJECT_CONTENT)
    }) {
        if package.stopped(out) {
            break;
        }
        if package.scan_member(&member, &mut OdfText::new(Element::Body, false), out) {
            out.separator(Separator::Newline);
        }
    }
    Some(format)
}
