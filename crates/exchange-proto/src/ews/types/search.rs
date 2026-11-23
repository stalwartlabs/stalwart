/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ids::{BaseFolderId, DistinguishedFolderId, FolderId},
    value::{EwsValue, M, T, XSI},
};
use crate::{
    ews::{
        parser::{Parser, Result},
        responses::ResponseMessage,
    },
    xml::{Ns, XmlWriter},
};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq)]
pub struct MailboxSearchScope<'a> {
    pub folder: Option<BaseFolderId<'a>>,
    pub deep: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SearchScope<'a> {
    pub mailbox: Option<MailboxSearchScope<'a>>,
}

impl<'a> SearchScope<'a> {
    pub fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut scope = SearchScope::default();
        while let Some(child) = p.child()? {
            if child.local == "PrimaryMailboxSearchScope" {
                p.expect_types(&child)?;
                scope.mailbox = Some(MailboxSearchScope::parse(p)?);
            } else {
                p.skip()?;
            }
        }
        Ok(scope)
    }
}

impl<'a> MailboxSearchScope<'a> {
    fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let mut scope = MailboxSearchScope {
            folder: None,
            deep: false,
        };
        while let Some(child) = p.child()? {
            hashify::fnc_map!(child.local.as_bytes(),
                "FolderScope" => {
                    p.expect_types(&child)?;
                    scope.folder = parse_folder_scope(p)?;
                },
                "IsDeepTraversal" => {
                    p.expect_types(&child)?;
                    scope.deep = EwsValue::parse(p, &child.attrs)?;
                },
                _ => {
                    p.skip()?;
                }
            );
        }
        Ok(scope)
    }
}

fn parse_folder_scope<'a>(p: &mut Parser<'a>) -> Result<Option<BaseFolderId<'a>>> {
    let mut folder = None;
    while let Some(child) = p.child()? {
        hashify::fnc_map!(child.local.as_bytes(),
            "FolderId" => {
                p.expect_types(&child)?;
                folder = Some(BaseFolderId::Folder(FolderId::parse(p, &child.attrs)?));
            },
            "WellKnownFolder" => {
                p.expect_types(&child)?;
                folder = Some(BaseFolderId::Distinguished(DistinguishedFolderId::parse(
                    p,
                    &child.attrs,
                )?));
            },
            _ => {
                p.skip()?;
            }
        );
    }
    Ok(folder)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SearchItemTypes {
    pub mail: bool,
}

impl SearchItemTypes {
    pub fn parse(text: &str) -> Self {
        SearchItemTypes {
            mail: has_token(text, |token| hashify::set!(token, "MailItems")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SuggestionKinds {
    pub people: bool,
}

impl SuggestionKinds {
    pub fn parse(text: &str) -> Self {
        SuggestionKinds {
            people: has_token(text, |token| hashify::set!(token, "People", "All")),
        }
    }
}

fn has_token(text: &str, matches: impl Fn(&[u8]) -> bool) -> bool {
    text.split_ascii_whitespace()
        .any(|token| matches(token.as_bytes()))
}

#[derive(Debug, Clone, PartialEq)]
pub struct PeopleSuggestion<'x> {
    pub display_name: Cow<'x, str>,
    pub address: Cow<'x, str>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchSuggestions<'x> {
    pub batch_id: u64,
    pub instance_id: Cow<'x, str>,
    pub trigger: Cow<'x, str>,
    pub people: Vec<PeopleSuggestion<'x>>,
}

impl ResponseMessage for SearchSuggestions<'_> {
    fn write_body(&self, w: &mut XmlWriter<'_>) {
        w.start(M, "SearchSuggestions");
        w.leaf_u64(T, "TDSuggestionsBatchId", self.batch_id);
        w.leaf(T, "TDSuggestionsInstanceId", &self.instance_id);
        w.start(T, "Suggestions").ns_decl(XSI, Ns::Xsi.uri());
        for (id, person) in (1u64..).zip(&self.people) {
            w.start(T, "Suggestion")
                .attr("xsi:type", "t:PeopleSuggestionType");
            w.leaf(T, "SuggestedQuery", &person.address);
            w.leaf(T, "DisplayText", &person.display_name);
            w.leaf(T, "SuggestionType", "People");
            w.leaf(T, "Trigger", &self.trigger);
            w.leaf_u64(T, "TDSuggestionId", id);
            w.leaf_bool(T, "IsDeletable", false);
            w.leaf(T, "PrimarySmtpAddress", &person.address);
            w.leaf(T, "PersonType", "Person");
            w.end(T, "Suggestion");
        }
        w.end(T, "Suggestions");
        w.end(M, "SearchSuggestions");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchResultsSummary<'x> {
    pub more_results: bool,
    pub count: usize,
    pub total: usize,
    pub terms: &'x [&'x str],
}

impl SearchResultsSummary<'_> {
    pub fn start(w: &mut XmlWriter<'_>) {
        w.start(M, "SearchResults");
        w.start("", "Items")
            .ns_decl("", Ns::Types.uri())
            .ns_decl(XSI, Ns::Xsi.uri());
    }

    pub fn finish(&self, w: &mut XmlWriter<'_>) {
        w.end("", "Items");
        w.leaf_bool(T, "MoreResultsAvailable", self.more_results);
        w.leaf_i64(T, "RefinerTelemetryBatchId", 0);
        w.leaf_i64(T, "SearchResultsCount", count(self.count));
        w.leaf_i64(T, "TotalResultsCount", count(self.total));
        w.start(T, "SearchTerms");
        for term in self.terms {
            w.leaf(T, "SearchTerm", term);
        }
        w.end(T, "SearchTerms");
        w.end(M, "SearchResults");
    }
}

fn count(value: usize) -> i64 {
    i32::try_from(value).map_or(i64::from(i32::MAX), i64::from)
}
