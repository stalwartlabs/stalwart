/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::is_dropped_with_content;
use html5ever::{
    LocalName, TokenizerResult,
    tendril::StrTendril,
    tokenizer::{
        BufferQueue, TagKind, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
    },
};
use std::cell::{Cell, RefCell};

pub(super) const MAX_RECONSTRUCTION_COST: u64 = 1 << 18;

const FORMATTING_TAGS: usize = 14;

fn formatting_index(name: &str) -> Option<usize> {
    hashify::map!(name.as_bytes(), usize,
        "a" => 0,
        "b" => 1,
        "big" => 2,
        "code" => 3,
        "em" => 4,
        "font" => 5,
        "i" => 6,
        "nobr" => 7,
        "s" => 8,
        "small" => 9,
        "strike" => 10,
        "strong" => 11,
        "tt" => 12,
        "u" => 13,
    )
    .copied()
}

fn is_line_break(name: &str) -> bool {
    hashify::set!(
        name.as_bytes(),
        "blockquote",
        "br",
        "div",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "li",
        "p",
        "pre",
        "table",
        "tr",
    )
}

pub(super) fn reconstruction_cost(html: &str) -> u64 {
    tokenize(html, FormattingCost::default()).cost.get()
}

pub(super) fn text_fallback(html: &str) -> String {
    let text = tokenize(html, TextContent::default()).text.into_inner();
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("<br>"),
            ch => out.push(ch),
        }
    }
    out
}

fn tokenize<S: TokenSink>(html: &str, sink: S) -> S {
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let queue = BufferQueue::default();
    queue.push_back(StrTendril::from_slice(html));
    while let TokenizerResult::Script(_) = tokenizer.feed(&queue) {}
    tokenizer.end();
    tokenizer.sink
}

#[derive(Default)]
struct FormattingCost {
    open: [Cell<u32>; FORMATTING_TAGS],
    total: Cell<u64>,
    cost: Cell<u64>,
}

impl FormattingCost {
    fn charge(&self) {
        self.cost
            .set(self.cost.get().saturating_add(self.total.get()));
    }
}

impl TokenSink for FormattingCost {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        match token {
            Token::TagToken(tag) => {
                let open = formatting_index(&tag.name).and_then(|index| self.open.get(index));
                match (tag.kind, open) {
                    (TagKind::StartTag, Some(open)) => {
                        open.set(open.get().saturating_add(1));
                        self.total.set(self.total.get().saturating_add(1));
                        self.charge();
                    }
                    (TagKind::StartTag, None) => self.charge(),
                    (TagKind::EndTag, Some(open)) if open.get() > 0 => {
                        open.set(open.get() - 1);
                        self.total.set(self.total.get().saturating_sub(1));
                    }
                    (TagKind::EndTag, _) => {}
                }
            }
            Token::CharacterTokens(_) | Token::NullCharacterToken => self.charge(),
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

#[derive(Default)]
struct TextContent {
    text: RefCell<String>,
    skipping: RefCell<Option<(LocalName, u32)>>,
}

impl TokenSink for TextContent {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        let mut skipping = self.skipping.borrow_mut();
        match token {
            Token::TagToken(tag) => {
                if skipping.is_none() {
                    if matches!(tag.kind, TagKind::StartTag) {
                        if is_dropped_with_content(&tag.name) {
                            *skipping = Some((tag.name, 0));
                        } else if is_line_break(&tag.name) {
                            self.text.borrow_mut().push('\n');
                        }
                    }
                } else if let Some((name, depth)) = skipping.as_mut()
                    && *name == tag.name
                {
                    match (tag.kind, depth.checked_sub(1)) {
                        (TagKind::StartTag, _) => *depth = depth.saturating_add(1),
                        (TagKind::EndTag, Some(left)) => *depth = left,
                        (TagKind::EndTag, None) => *skipping = None,
                    }
                }
            }
            Token::CharacterTokens(text) if skipping.is_none() => {
                self.text.borrow_mut().push_str(&text);
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}
