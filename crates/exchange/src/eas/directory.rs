/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::context::EasContext;
use crate::mapi::nspi::{
    book::{AbEntry, AbResource, Book, BookResult, ResourceDetail},
    page::{RowKey, fold, fold_cmp_folded},
    scan::{AbView, Detail},
    table::anr,
};
use common::Server;
use exchange_proto::eas::{
    commands::{
        ItemRange,
        resolve_recipients::PictureOptions,
        search::{GalEntry, GalPicture},
    },
    status::PictureStatus,
};
use std::borrow::Cow;
use types::type_state::DataType;

pub const MAX_GAL_RESULTS: u32 = 100;

pub fn open_directory<'x>(server: &'x Server, ctx: &'x EasContext<'_>) -> Option<Book<'x>> {
    ctx.allows_type(DataType::Principal)
        .then(|| Book::new(server, &ctx.access_token))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    Prefix,
}

pub struct GalQuery<'q> {
    query: &'q str,
    lower: String,
}

pub struct GalPage {
    pub entries: Vec<AbEntry>,
    pub total: u32,
    pub range: Option<ItemRange>,
}

impl<'q> GalQuery<'q> {
    pub fn new(query: &'q str) -> Option<Self> {
        let query = query.trim();
        (!query.is_empty()).then(|| GalQuery {
            query,
            lower: fold(query),
        })
    }

    pub fn matches(&self, view: &AbView<'_>) -> bool {
        anr(view, &self.lower)
    }

    pub fn query(&self) -> &str {
        self.query
    }

    pub fn folded(&self) -> &str {
        &self.lower
    }

    pub fn classify(&self, view: &AbView<'_>) -> Option<MatchKind> {
        if self.is_exact(view) {
            Some(MatchKind::Exact)
        } else if self.matches(view) {
            Some(MatchKind::Prefix)
        } else {
            None
        }
    }

    pub fn is_exact(&self, view: &AbView<'_>) -> bool {
        fold_cmp_folded(view.display_name, &self.lower).is_eq()
            || view.account.eq_ignore_ascii_case(self.query)
            || view
                .addresses()
                .any(|address| address.eq_ignore_ascii_case(self.query))
    }

    pub async fn page(
        &self,
        book: &mut Book<'_>,
        requested: Option<ItemRange>,
    ) -> BookResult<GalPage> {
        let window = requested.unwrap_or(ItemRange {
            start: 0,
            end: MAX_GAL_RESULTS - 1,
        });
        let last = window
            .end
            .min(window.start.saturating_add(MAX_GAL_RESULTS - 1));
        let count = last.checked_sub(window.start).map_or(0, |span| {
            usize::try_from(span).map_or(usize::MAX, |span| span + 1)
        });
        let first = usize::try_from(window.start).unwrap_or(usize::MAX);
        let page = book
            .window(Detail::Addresses, first, count, |_, view| {
                self.matches(view)
            })
            .await?;
        book.set_resource_detail(ResourceDetail::Full);
        let entries = load_entries(book, &page.rows).await?;
        Ok(GalPage {
            range: returned_range(Some(window), entries.len()),
            total: u32::try_from(page.total).unwrap_or(u32::MAX),
            entries,
        })
    }
}

pub async fn load_entries(book: &mut Book<'_>, rows: &[RowKey]) -> BookResult<Vec<AbEntry>> {
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(entry) = book.entry(row).await? {
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub fn gal_entry<'b>(entry: &'b AbEntry, picture: Option<&PictureOptions>) -> GalEntry<'b> {
    GalEntry {
        display_name: Some(Cow::Borrowed(&entry.display_name)),
        alias: Some(Cow::Borrowed(&entry.account)),
        email_address: Some(Cow::Borrowed(&entry.smtp)),
        office: entry
            .resource
            .as_ref()
            .and_then(AbResource::details)
            .and_then(|details| details.location.as_deref())
            .map(Cow::Borrowed),
        picture: picture.map(|_| GalPicture {
            status: Some(u32::from(PictureStatus::NO_PICTURE.0)),
            data: None,
        }),
        ..Default::default()
    }
}

pub fn page_range(requested: Option<ItemRange>, total: u32, cap: u32) -> Option<ItemRange> {
    let requested = requested.unwrap_or(ItemRange {
        start: 0,
        end: cap.saturating_sub(1),
    });
    let last = total.checked_sub(1)?;
    let end = requested
        .end
        .min(requested.start.saturating_add(cap.saturating_sub(1)))
        .min(last);
    (requested.start <= end).then_some(ItemRange {
        start: requested.start,
        end,
    })
}

pub fn returned_range(range: Option<ItemRange>, returned: usize) -> Option<ItemRange> {
    let range = range?;
    let last = u32::try_from(returned.checked_sub(1)?).ok()?;
    Some(ItemRange {
        start: range.start,
        end: range.start.saturating_add(last),
    })
}
