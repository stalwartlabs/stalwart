/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    output::{Output, Separator},
    xml::{Handler, Skip, Tag, local_name},
};
use mail_parser::decoders::html::add_html_token;

const MAX_ENTITY_TOKEN: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Element {
    Block,
    Cell,
    Head,
    Script,
    Style,
    Template,
    Ruby,
}

impl Element {
    fn parse(local: &[u8]) -> Option<Element> {
        hashify::map_ignore_case!(local, Element,
            b"head" => Element::Head,
            b"script" => Element::Script,
            b"style" => Element::Style,
            b"template" => Element::Template,
            b"rt" => Element::Ruby,
            b"rp" => Element::Ruby,
            b"p" => Element::Block,
            b"div" => Element::Block,
            b"br" => Element::Block,
            b"li" => Element::Block,
            b"ul" => Element::Block,
            b"ol" => Element::Block,
            b"tr" => Element::Block,
            b"h1" => Element::Block,
            b"h2" => Element::Block,
            b"h3" => Element::Block,
            b"h4" => Element::Block,
            b"h5" => Element::Block,
            b"h6" => Element::Block,
            b"blockquote" => Element::Block,
            b"pre" => Element::Block,
            b"section" => Element::Block,
            b"article" => Element::Block,
            b"header" => Element::Block,
            b"footer" => Element::Block,
            b"nav" => Element::Block,
            b"aside" => Element::Block,
            b"table" => Element::Block,
            b"dt" => Element::Block,
            b"dd" => Element::Block,
            b"dl" => Element::Block,
            b"hr" => Element::Block,
            b"figure" => Element::Block,
            b"figcaption" => Element::Block,
            b"address" => Element::Block,
            b"main" => Element::Block,
            b"body" => Element::Block,
            b"caption" => Element::Block,
            b"title" => Element::Block,
            b"td" => Element::Cell,
            b"th" => Element::Cell,
        )
        .copied()
    }
}

#[derive(Default)]
pub(crate) struct HtmlText {
    skip: Skip<Element>,
    entity: String,
}

impl HtmlText {
    pub(crate) fn reset(&mut self) {
        self.skip.reset();
    }
}

impl Handler for HtmlText {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        let element = Element::parse(tag.local());
        if self.skip.on_start(element) {
            return;
        }
        match element {
            Some(Element::Block) => out.separator(Separator::Newline),
            Some(Element::Cell) => out.separator(Separator::Space),
            Some(skipped) => self.skip.begin(skipped),
            None => {}
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        let element = Element::parse(local_name(name));
        if self.skip.on_end(element) {
            return;
        }
        match element {
            Some(Element::Block) => out.separator(Separator::Newline),
            Some(Element::Cell) => out.separator(Separator::Space),
            _ => {}
        }
    }

    fn text(&mut self, text: &[u8], out: &mut Output<'_>) {
        if !self.skip.active() {
            out.push_utf8(text);
        }
    }

    fn entity(&mut self, name: &[u8], out: &mut Output<'_>) {
        if self.skip.active() {
            return;
        }
        let mut token = [0u8; MAX_ENTITY_TOKEN];
        let Some(slot) = token.get_mut(..name.len() + 2) else {
            return;
        };
        let [first, middle @ .., last] = slot else {
            return;
        };
        *first = b'&';
        middle.copy_from_slice(name);
        *last = b';';
        self.entity.clear();
        add_html_token(&mut self.entity, slot, false);
        if !self.entity.starts_with('&') {
            out.push_str(&self.entity);
        }
    }
}
