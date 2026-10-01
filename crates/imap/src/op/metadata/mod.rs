/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod edit;
mod get;
mod list;
mod select;
mod set;

pub(crate) use list::ListMetadataTarget;

use super::ImapContext;
use crate::{
    core::{AccountView, MailboxId, Session, SessionData},
    spawn_op,
};
use common::{
    MailboxCache, MessageStoreCache, auth::AccessToken, network::SessionStream,
    sharing::EffectiveAcl,
};
use compact_str::CompactString;
use email::cache::mailbox::MailboxCacheAccess;
use imap_proto::{
    Command, ResponseCode,
    protocol::metadata::{Depth, Entry, EntryValue, MetadataCode, Scope},
    receiver::Request,
};
use registry::schema::enums::Permission;
use std::{sync::Arc, time::Instant};
use tokio::sync::OwnedSemaphorePermit;
use types::{acl::Acl, metadata::MetadataKinds, special_use::SpecialUse};
use utils::map::bitmap::Bitmap;

const SERVER_DOCUMENT_ID: u32 = 0;
const SPECIAL_USE_ENTRY: &str = "/specialuse";
const READ_RIGHTS: [Acl; 2] = [Acl::Read, Acl::ReadItems];
const MIN_REQUESTED_ENTRIES: usize = 64;

struct MetadataMailbox {
    account_id: u32,
    mailbox_id: u32,
    kinds: MetadataKinds,
    role: SpecialUse,
    rights: Bitmap<Acl>,
    cache: Arc<MessageStoreCache>,
}

impl<T: SessionStream> Session<T> {
    pub async fn handle_get_metadata(
        &mut self,
        request: Request<Command>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        self.assert_has_permission(Permission::ImapMetadataGet)?;

        let op_start = Instant::now();
        let arguments = request.parse_get_metadata(self.is_utf8)?;
        let data = self.state.session_data();
        let is_utf8 = self.is_utf8;

        spawn_op!(
            permit,
            data,
            data.get_metadata(arguments, is_utf8, op_start).await
        )
    }

    pub async fn handle_set_metadata(
        &mut self,
        request: Request<Command>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> trc::Result<()> {
        self.assert_has_permission(Permission::ImapMetadataGet)?;

        let op_start = Instant::now();
        let arguments = request.parse_set_metadata(self.is_utf8)?;
        let data = self.state.session_data();

        spawn_op!(permit, data, {
            let response = data.set_metadata(arguments, op_start).await?;
            data.write_bytes(response.into_bytes()).await
        })
    }
}

impl<T: SessionStream> SessionData<T> {
    async fn metadata_mailbox(
        &self,
        tag: &str,
        mailbox_name: &str,
        access_token: &AccessToken,
    ) -> trc::Result<MetadataMailbox> {
        let mut caches = self
            .synchronize_mailboxes(false)
            .await
            .imap_ctx(tag, trc::location!())?
            .caches;
        let mailbox = self
            .get_mailbox_by_name(mailbox_name)
            .ok_or_else(|| mailbox_not_found(tag))?;
        let cache = caches
            .fetch(&self.server, mailbox.account_id)
            .await
            .imap_ctx(tag, trc::location!())?;
        let (kinds, role, rights) = cache
            .mailbox_by_id(&mailbox.mailbox_id)
            .map(|cached| {
                (
                    cached.metadata_kinds,
                    cached.role,
                    mailbox_rights(access_token, mailbox.account_id, cached),
                )
            })
            .ok_or_else(|| mailbox_not_found(tag))?;

        Ok(MetadataMailbox {
            account_id: mailbox.account_id,
            mailbox_id: mailbox.mailbox_id,
            kinds,
            role,
            rights,
            cache,
        })
    }

    pub(crate) fn assert_metadata_request(&self, tag: &str, entries: usize) -> trc::Result<()> {
        if entries
            <= self
                .server
                .core
                .metadata
                .max_entries
                .saturating_mul(2)
                .max(MIN_REQUESTED_ENTRIES)
        {
            Ok(())
        } else {
            Err(trc::ImapEvent::Error
                .into_err()
                .details("Too many metadata entries requested.")
                .code(ResponseCode::Limit)
                .id(CompactString::from(tag)))
        }
    }
}

impl MetadataMailbox {
    fn id(&self) -> MailboxId {
        MailboxId {
            account_id: self.account_id,
            mailbox_id: self.mailbox_id,
        }
    }

    fn assert_rights(&self, tag: &str, rights: &[Acl]) -> trc::Result<()> {
        if rights.iter().all(|right| self.rights.contains(*right)) {
            Ok(())
        } else {
            Err(trc::ImapEvent::Error
                .into_err()
                .details(
                    "You do not have enough permissions to access annotations on this mailbox.",
                )
                .code(ResponseCode::NoPerm)
                .id(CompactString::from(tag)))
        }
    }
}

fn mailbox_rights(
    access_token: &AccessToken,
    account_id: u32,
    mailbox: &MailboxCache,
) -> Bitmap<Acl> {
    if access_token.is_member(account_id) {
        Bitmap::all()
    } else {
        mailbox.acls.as_slice().effective_acl(access_token)
    }
}

fn reads_private_container(entries: &[Entry<'_>], depth: Depth) -> bool {
    entries.iter().any(|entry| {
        entry.scope == Scope::Private && (depth != Depth::Zero || entry.path != SPECIAL_USE_ENTRY)
    })
}

fn special_use_value(role: SpecialUse) -> Option<&'static [u8]> {
    AccountView::special_use_attribute(&role).map(|attribute| attribute.as_bytes())
}

fn mailbox_not_found(tag: &str) -> trc::Error {
    trc::ImapEvent::Error
        .into_err()
        .details("Mailbox does not exist.")
        .code(ResponseCode::NonExistent)
        .id(CompactString::from(tag))
}

fn metadata_error(tag: &str, code: MetadataCode) -> trc::Error {
    trc::ImapEvent::Error
        .into_err()
        .details(match code {
            MetadataCode::MaxSize(_) => "Annotation value or mailbox annotations too large.",
            MetadataCode::TooMany => "Too many annotations.",
            MetadataCode::NoPrivate => "Private annotations are not supported.",
            MetadataCode::LongEntries(_) => "Annotation value too large.",
        })
        .code(ResponseCode::Metadata(code))
        .id(CompactString::from(tag))
}

fn owned_entries(entries: Vec<EntryValue<'_>>) -> Option<Box<[EntryValue<'static>]>> {
    (!entries.is_empty()).then(|| entries.into_iter().map(EntryValue::into_owned).collect())
}
