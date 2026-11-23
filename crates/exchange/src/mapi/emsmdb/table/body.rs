/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{TableRow, filter::RowFilter};
use crate::{
    folders::FolderNode,
    mapi::{
        emsmdb::{
            execute::{MailboxView, RopContext, RopError},
            state::{TableKind, TableObject},
        },
        ids::{IdSpace, MapiId},
    },
    store::{FolderKind, FolderRef},
};
use email::{
    cache::email::MessageAccess,
    message::query::{MailCondition, MailFilter, MailTextField, QueryFilter},
};
use exchange_proto::mapi::ErrorCode;
use store::{roaring::RoaringBitmap, search::SearchQuery, write::SearchIndex};
use trc::AddContext;

pub(super) const MAX_BODY_TERMS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EmailRows {
    Mailbox(u32),
    Search,
}

pub(super) struct RowDocuments {
    rows: EmailRows,
    mailbox: MailboxView,
}

impl RowDocuments {
    pub(super) fn document(&self, key: u64) -> Option<u32> {
        let id = MapiId::from_counter(key).filter(|id| id.space == IdSpace::Email)?;
        Some(match self.rows {
            EmailRows::Mailbox(container) => self.mailbox.email_document(container, id.id),
            EmailRows::Search => id.id,
        })
    }
}

impl RopContext<'_, '_> {
    pub(super) async fn body_rows(
        &mut self,
        table: &TableObject,
        filter: &RowFilter<'_>,
    ) -> Result<Option<EmailRows>, RopError> {
        if !matches!(table.kind, TableKind::Contents { associated: false }) || !filter.uses_body() {
            return Ok(None);
        }
        let Some(node) = table.folder.id().and_then(MapiId::to_node) else {
            return Ok(None);
        };
        Ok(match node {
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Mailbox,
                id,
            }) => Some(EmailRows::Mailbox(id)),
            FolderNode::Stored(FolderRef {
                kind: FolderKind::Virtual,
                ..
            }) => self
                .folder_tree(table.folder.mailbox_id)
                .await?
                .get(node)
                .filter(|entry| entry.search)
                .map(|_| EmailRows::Search),
            _ => None,
        })
    }

    pub(super) async fn resolve_body_terms(
        &mut self,
        mailbox_id: u32,
        rows: EmailRows,
        filter: &mut RowFilter<'_>,
        table_rows: &[TableRow],
    ) -> Result<Option<RowDocuments>, RopError> {
        if !filter.uses_body() {
            return Ok(None);
        }
        let terms = filter.body_terms().collect::<Vec<_>>();
        if terms.len() > MAX_BODY_TERMS {
            return Err(RopError::Code(ErrorCode::TOO_COMPLEX));
        }
        let documents = RowDocuments {
            rows,
            mailbox: self.mailbox(mailbox_id).await?,
        };
        let Some(messages) = documents.mailbox.messages.as_ref() else {
            return Ok(None);
        };
        let mask = table_rows
            .iter()
            .filter_map(|row| documents.document(row.key))
            .collect::<RoaringBitmap>();
        if mask.is_empty() {
            return Ok(None);
        }
        let server = self.request.server;
        let mut resolved = Vec::<(u16, RoaringBitmap)>::with_capacity(terms.len());
        for (position, &(index, text)) in terms.iter().enumerate() {
            if let Some(matches) = terms
                .get(..position)
                .and_then(|previous| previous.iter().position(|(_, seen)| *seen == text))
                .and_then(|seen| resolved.get(seen))
                .map(|(_, matches)| matches.clone())
            {
                resolved.push((index, matches));
                continue;
            }
            let matches = match QueryFilter::parse(
                vec![MailFilter::Condition(MailCondition::Text(
                    MailTextField::Body,
                    text.to_owned(),
                ))],
                messages,
                MessageAccess::All,
                server.core.email.default_language,
            ) {
                Some(mut query) => server
                    .search_store()
                    .filter_account(
                        SearchQuery::new(SearchIndex::Email)
                            .with_filters(query.residual_filters())
                            .with_account_id(mailbox_id)
                            .with_mask(mask.clone()),
                    )
                    .await
                    .caused_by(trc::location!())?,
                None => RoaringBitmap::new(),
            };
            resolved.push((index, matches));
        }
        drop(terms);
        for (index, matches) in resolved {
            filter.resolve_documents(index, matches);
        }
        Ok(Some(documents))
    }
}
