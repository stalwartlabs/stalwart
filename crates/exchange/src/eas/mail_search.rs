/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{context::EasContext, sync::estimate::mail_folder};
use crate::folders::FolderNode;
use ::email::cache::{email::MessageCacheAccess, mailbox::MailboxCacheAccess};
use common::{MessageStoreCache, Server, cache::email::MessageRef};
use exchange_proto::eas::kql::{FreeText, KqlNode, KqlProperty};
use nlp::language::Language;
use smallvec::SmallVec;
use std::mem;
use store::{
    roaring::RoaringBitmap,
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchFilter, SearchQuery,
    },
    write::SearchIndex,
};
use trc::AddContext;
use utils::cheeky_hash::CheekyHash;

pub const MAX_TEXT_TOKENS: usize = 16;
const MIN_PREFIX_CHARS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeError {
    UnknownFolder,
    NotMail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextFit {
    Complete,
    Truncated,
    Unconstrained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextFields {
    #[default]
    Email,
    Calendar,
    Contacts,
}

#[derive(Debug, Clone, Copy)]
enum TextTarget {
    Fields,
    Email(&'static [EmailSearchField]),
}

#[derive(Debug, Clone, Copy)]
pub struct MailHit {
    pub document_id: u32,
    pub mailbox_id: u32,
}

#[derive(Debug, Default)]
pub struct MailHits {
    pub top: Vec<MailHit>,
    pub total: usize,
}

#[derive(Default)]
pub struct MailSearch {
    pub scope: Option<RoaringBitmap>,
    pub text: Vec<SearchFilter>,
    pub tokens: usize,
    pub after: Option<u64>,
    pub before: Option<u64>,
    pub thread_id: Option<u32>,
    pub empty: bool,
    pub fields: TextFields,
}

impl TextFields {
    pub fn index(self) -> SearchIndex {
        match self {
            TextFields::Email => SearchIndex::Email,
            TextFields::Calendar => SearchIndex::Calendar,
            TextFields::Contacts => SearchIndex::Contacts,
        }
    }

    fn push(self, filters: &mut Vec<SearchFilter>, text: &str, language: Language) {
        filters.push(SearchFilter::Or);
        match self {
            TextFields::Email => filters.extend([
                SearchFilter::has_text(EmailSearchField::From, text, Language::None),
                SearchFilter::has_text(EmailSearchField::To, text, Language::None),
                SearchFilter::has_text(EmailSearchField::Cc, text, Language::None),
                SearchFilter::has_text(EmailSearchField::Bcc, text, Language::None),
                SearchFilter::has_text(EmailSearchField::Subject, text, language),
                SearchFilter::has_text(EmailSearchField::Body, text, language),
                SearchFilter::has_text(EmailSearchField::Attachment, text, language),
            ]),
            TextFields::Calendar => filters.extend([
                SearchFilter::has_text(CalendarSearchField::Title, text, language),
                SearchFilter::has_text(CalendarSearchField::Description, text, language),
                SearchFilter::has_text(CalendarSearchField::Location, text, language),
            ]),
            TextFields::Contacts => filters.extend([
                SearchFilter::has_keyword(ContactSearchField::Name, text),
                SearchFilter::has_keyword(ContactSearchField::Nickname, text),
                SearchFilter::has_keyword(ContactSearchField::Organization, text),
                SearchFilter::has_keyword(ContactSearchField::Email, text),
                SearchFilter::has_keyword(ContactSearchField::Phone, text),
                SearchFilter::has_keyword(ContactSearchField::Address, text),
                SearchFilter::has_keyword(ContactSearchField::OnlineService, text),
                SearchFilter::has_text(ContactSearchField::Note, text, language),
            ]),
        }
        filters.push(SearchFilter::End);
    }
}

impl MailSearch {
    pub fn add_folder(
        &mut self,
        ctx: &EasContext<'_>,
        cache: &MessageStoreCache,
        collection_id: &str,
        deep: bool,
    ) -> Result<(), ScopeError> {
        let node =
            FolderNode::from_eas_collection_id(collection_id).ok_or(ScopeError::UnknownFolder)?;
        self.scope.get_or_insert_default();
        let folder = mail_folder(ctx, node).ok_or(ScopeError::NotMail)?;
        if !cache.mailboxes.has_mailbox_id(&folder.id) {
            return Err(ScopeError::UnknownFolder);
        }
        self.add_mailbox(cache, folder.id, deep);
        Ok(())
    }

    pub fn add_mailbox(&mut self, cache: &MessageStoreCache, mailbox_id: u32, deep: bool) {
        let scope = self.scope.get_or_insert_default();
        if deep {
            *scope |= mailbox_tree(cache, mailbox_id);
        } else {
            scope.insert(mailbox_id);
        }
    }

    pub fn push_text(&mut self, text: &str, language: Language) -> TextFit {
        let mut tokens = TextTokens { rest: text }.filter_map(TextToken::parse);
        let mut taken = tokens
            .by_ref()
            .take(MAX_TEXT_TOKENS.saturating_sub(self.tokens))
            .peekable();
        let mut terms = SmallVec::<[TextTerm<'_>; MAX_TEXT_TOKENS]>::new();
        while let Some(token) = taken.next() {
            self.tokens += 1;
            let position = match taken.peek() {
                Some(_) => TokenPosition::Inner,
                None => TokenPosition::Last,
            };
            terms.extend(token.term(position));
        }
        match terms.as_slice() {
            [] => {}
            [term] => self.push_term(*term, language),
            terms => {
                self.text.push(SearchFilter::And);
                for term in terms {
                    self.push_term(*term, language);
                }
                self.text.push(SearchFilter::End);
            }
        }
        if tokens.next().is_some() {
            TextFit::Truncated
        } else if terms.is_empty() {
            TextFit::Unconstrained
        } else {
            TextFit::Complete
        }
    }

    pub fn push_free_text(&mut self, text: &str, language: Language) {
        let nodes = match FreeText::parse(text, |value| {
            TextToken::parse(value).is_some_and(|token| token.term(TokenPosition::Inner).is_some())
        }) {
            FreeText::Keywords(text) => {
                self.push_text(text, language);
                return;
            }
            FreeText::Query(nodes) => nodes,
        };
        let last = nodes
            .iter()
            .rposition(|node| matches!(node, KqlNode::Term { .. }));
        for (index, node) in nodes.iter().enumerate() {
            match *node {
                KqlNode::And => self.text.push(SearchFilter::And),
                KqlNode::Or => self.text.push(SearchFilter::Or),
                KqlNode::Not => self.text.push(SearchFilter::Not),
                KqlNode::End => self.text.push(SearchFilter::End),
                KqlNode::Term { property, value } => {
                    let position = if last == Some(index) {
                        TokenPosition::Last
                    } else {
                        TokenPosition::Inner
                    };
                    let target = property.map_or(TextTarget::Fields, |property| {
                        TextTarget::Email(property_fields(property))
                    });
                    if let Some(term) =
                        TextToken::parse(value).and_then(|token| token.term(position))
                    {
                        self.push_term_in(term, target, language);
                    }
                }
            }
        }
    }

    fn push_term(&mut self, term: TextTerm<'_>, language: Language) {
        self.push_term_in(term, TextTarget::Fields, language);
    }

    fn push_term_in(&mut self, term: TextTerm<'_>, target: TextTarget, language: Language) {
        match term {
            TextTerm::Prefix { word, prefix } => {
                self.text.push(SearchFilter::Or);
                self.push_target(target, word, language);
                self.push_target(target, &format!("{prefix}*"), language);
                self.text.push(SearchFilter::End);
            }
            TextTerm::Split { word, head, tail } => {
                self.text.push(SearchFilter::Or);
                self.push_target(target, word, language);
                self.text.push(SearchFilter::And);
                self.push_target(target, head, language);
                self.push_target(target, &format!("{tail}*"), language);
                self.text.push(SearchFilter::End);
                self.text.push(SearchFilter::End);
            }
            TextTerm::Word(word) => self.push_target(target, word, language),
        }
    }

    fn push_target(&mut self, target: TextTarget, text: &str, language: Language) {
        match target {
            TextTarget::Fields => self.fields.push(&mut self.text, text, language),
            TextTarget::Email(fields) => {
                self.text.push(SearchFilter::Or);
                self.text.extend(fields.iter().map(|field| {
                    let language = match field {
                        EmailSearchField::From
                        | EmailSearchField::To
                        | EmailSearchField::Cc
                        | EmailSearchField::Bcc => Language::None,
                        _ => language,
                    };
                    SearchFilter::has_text(field.clone(), text, language)
                }));
                self.text.push(SearchFilter::End);
            }
        }
    }

    pub async fn run(
        self,
        server: &Server,
        account_id: u32,
        cache: &MessageStoreCache,
    ) -> trc::Result<Vec<MailHit>> {
        self.run_top(server, account_id, cache, usize::MAX)
            .await
            .map(|hits| hits.top)
    }

    pub async fn run_top(
        mut self,
        server: &Server,
        account_id: u32,
        cache: &MessageStoreCache,
        top: usize,
    ) -> trc::Result<MailHits> {
        if self.empty {
            return Ok(MailHits::default());
        }
        let mut matches = cache
            .emails
            .iter()
            .filter(|message| self.accepts(message))
            .map(|message| message.document_id())
            .collect::<RoaringBitmap>();
        let text = mem::take(&mut self.text);
        if !text.is_empty() && !matches.is_empty() {
            matches = server
                .search_store()
                .filter_account(
                    SearchQuery::new(self.fields.index())
                        .with_filters(text)
                        .with_account_id(account_id)
                        .with_mask(matches),
                )
                .await
                .caused_by(trc::location!())?;
        }
        let mut rows = Vec::with_capacity(usize::try_from(matches.len()).unwrap_or_default());
        rows.extend(matches.iter().filter_map(|document_id| {
            let message = cache.email_by_id(&document_id)?;
            Some((
                message.received_at(),
                document_id,
                self.mailbox_of(&message)?,
            ))
        }));
        let total = rows.len();
        if top < total {
            rows.select_nth_unstable_by(top, |a, b| b.cmp(a));
            rows.truncate(top);
        }
        rows.sort_unstable_by(|a, b| b.cmp(a));
        Ok(MailHits {
            top: rows
                .into_iter()
                .map(|(_, document_id, mailbox_id)| MailHit {
                    document_id,
                    mailbox_id,
                })
                .collect(),
            total,
        })
    }

    fn mailbox_of(&self, message: &MessageRef<'_>) -> Option<u32> {
        message
            .mailboxes()
            .iter()
            .map(|mailbox| mailbox.mailbox_id)
            .find(|mailbox_id| {
                self.scope
                    .as_ref()
                    .is_none_or(|scope| scope.contains(*mailbox_id))
            })
    }

    fn accepts(&self, message: &MessageRef<'_>) -> bool {
        let received_at = message.received_at();
        self.after.is_none_or(|after| received_at > after)
            && self.before.is_none_or(|before| received_at < before)
            && self
                .thread_id
                .is_none_or(|thread_id| message.thread_id() == thread_id)
            && self.mailbox_of(message).is_some()
    }
}

fn property_fields(property: KqlProperty) -> &'static [EmailSearchField] {
    match property {
        KqlProperty::From => &[EmailSearchField::From],
        KqlProperty::To => &[EmailSearchField::To],
        KqlProperty::Cc => &[EmailSearchField::Cc],
        KqlProperty::Bcc => &[EmailSearchField::Bcc],
        KqlProperty::Participants => &[
            EmailSearchField::From,
            EmailSearchField::To,
            EmailSearchField::Cc,
            EmailSearchField::Bcc,
        ],
        KqlProperty::Recipients => &[
            EmailSearchField::To,
            EmailSearchField::Cc,
            EmailSearchField::Bcc,
        ],
        KqlProperty::Subject => &[EmailSearchField::Subject],
        KqlProperty::Body => &[EmailSearchField::Body],
        KqlProperty::Attachment => &[EmailSearchField::Attachment],
    }
}

pub fn mailbox_tree(cache: &MessageStoreCache, root: u32) -> RoaringBitmap {
    let mut subtree = RoaringBitmap::from_iter([root]);
    loop {
        let before = subtree.len();
        for mailbox in cache.mailboxes.items.iter() {
            if mailbox.parent_id != u32::MAX && subtree.contains(mailbox.parent_id) {
                subtree.insert(mailbox.document_id);
            }
        }
        if subtree.len() == before {
            break;
        }
    }
    subtree
}

pub fn search_terms(text: &str) -> impl Iterator<Item = &str> {
    TextTokens { rest: text }
        .filter_map(TextToken::parse)
        .take(MAX_TEXT_TOKENS)
        .filter(|token| token.term(TokenPosition::Last).is_some())
        .map(|token| token.word.trim_matches(|c| matches!(c, '"' | '\'')))
}

pub struct TextTokens<'x> {
    pub rest: &'x str,
}

impl<'x> Iterator for TextTokens<'x> {
    type Item = &'x str;

    fn next(&mut self) -> Option<&'x str> {
        let text = self.rest.trim_start();
        let quote = text.chars().next()?;
        let (token, rest) = matches!(quote, '"' | '\'')
            .then(|| split_phrase(text, quote))
            .flatten()
            .unwrap_or_else(|| text.split_once(char::is_whitespace).unwrap_or((text, "")));
        self.rest = rest;
        Some(token)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenPosition {
    Inner,
    Last,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TextToken<'x> {
    word: &'x str,
    starred: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TextTerm<'x> {
    Word(&'x str),
    Prefix {
        word: &'x str,
        prefix: &'x str,
    },
    Split {
        word: &'x str,
        head: &'x str,
        tail: &'x str,
    },
}

impl<'x> TextToken<'x> {
    fn parse(token: &'x str) -> Option<Self> {
        let word = token.trim_end_matches('*');
        (!word.is_empty()).then_some(TextToken {
            word,
            starred: word.len() < token.len(),
        })
    }

    fn term(self, position: TokenPosition) -> Option<TextTerm<'x>> {
        if !self.word.chars().any(char::is_alphanumeric) {
            return None;
        }
        let prefix = self
            .word
            .trim_end_matches(|c: char| c.is_ascii_punctuation());
        if prefix.len() > CheekyHash::HASH_SIZE || !prefix.chars().all(char::is_alphanumeric) {
            return Some(
                self.split(prefix, position)
                    .unwrap_or(TextTerm::Word(self.word)),
            );
        }
        let reaches_floor = reaches_floor(prefix);
        match (reaches_floor, self.starred, position) {
            (false, true, _) => None,
            (true, true, _) | (true, false, TokenPosition::Last) => Some(TextTerm::Prefix {
                word: self.word,
                prefix,
            }),
            (false, false, _) | (true, false, TokenPosition::Inner) => {
                Some(TextTerm::Word(self.word))
            }
        }
    }

    fn split(self, prefix: &'x str, position: TokenPosition) -> Option<TextTerm<'x>> {
        if self.word.starts_with(['"', '\'']) {
            return None;
        }
        let (head, tail) = prefix.rsplit_once(|c: char| !c.is_alphanumeric())?;
        let head = head.trim_end_matches(|c: char| !c.is_alphanumeric());
        (!head.is_empty()
            && tail.len() <= CheekyHash::HASH_SIZE
            && reaches_floor(tail)
            && (self.starred || position == TokenPosition::Last))
            .then_some(TextTerm::Split {
                word: self.word,
                head,
                tail,
            })
    }
}

fn reaches_floor(prefix: &str) -> bool {
    prefix.chars().nth(MIN_PREFIX_CHARS - 1).is_some()
}

fn split_phrase(text: &str, quote: char) -> Option<(&str, &str)> {
    let body = text.strip_prefix(quote)?;
    body.match_indices(quote).find_map(|(pos, _)| {
        let (phrase, rest) = text.split_at_checked(pos.checked_add(2)?)?;
        rest.chars()
            .next()
            .is_none_or(char::is_whitespace)
            .then_some((phrase, rest))
    })
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/eas/mail_search/tests.rs"]
mod tests;
