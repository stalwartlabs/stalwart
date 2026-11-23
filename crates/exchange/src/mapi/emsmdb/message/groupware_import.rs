/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    groupware_save::{CalendarItem, GroupwareFolder, card_error, event_error},
    import::ImportSave,
    save::{SaveTarget, Saved},
};
use crate::{
    cache::ExchangeCacheFetch,
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError},
            state::MessageObject,
        },
        ids::{IdSpace, MapiId},
    },
    store::{
        account::ExchangeAccountStore,
        alias::{GroupwareAlias, GroupwareKind, set_groupware_alias},
        object::{
            ConflictState, ExchangeObject, ExchangeObjectStore, ExchangeObjectWrite, ObjectVersion,
            OwnerStamp,
        },
    },
};
use common::cache::exchange::GroupwarePlacement;
use exchange_proto::{common::Guid, convert::ical::meeting_uid, mapi::ErrorCode};
use groupware::{
    cache::GroupwareCache,
    calendar::write::{EventWriteError, assert_unique_uid as assert_unique_event_uid},
    contact::write::{CardWriteError, assert_unique_uid as assert_unique_card_uid},
};
use std::mem;
use store::write::{BatchBuilder, PendingId};
use trc::{AddContext, EventType, LimitEvent};
use types::collection::SyncCollection;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::mapi::emsmdb) enum PinnedRow {
    New,
    Existing,
}

enum ImportWrite {
    Create(String),
    Adopt(u32),
    Edit(u32),
}

impl RopContext<'_, '_> {
    pub(super) async fn save_groupware_import(
        &mut self,
        message: &MessageObject,
        folder: GroupwareFolder,
        target: SaveTarget,
        (collector, import): (u32, ImportSave),
    ) -> Result<Saved, RopError> {
        let kind = folder.kind();
        let Some(item) = import.item else {
            let saved = self.save_groupware(message, folder, target, None).await?;
            self.pin_groupware_version(
                message.mailbox_id,
                (kind, saved.id.id),
                saved.change.or(import.stored_change),
                (
                    import.version,
                    match target.base {
                        Some(_) => PinnedRow::Existing,
                        None => PinnedRow::New,
                    },
                ),
            )
            .await;
            return Ok(
                match target.base.and(MapiId::from_counter(message.message)) {
                    Some(client) => Saved {
                        id: client,
                        ..saved
                    },
                    None => saved,
                },
            );
        };
        let placement = GroupwarePlacement {
            folder: kind.folder(folder.container()),
            item,
        };
        let space = IdSpace::of_groupware(kind);
        let (saved, alias, row) = match self
            .import_write(message, folder, placement, collector)
            .await?
        {
            ImportWrite::Create(uid) => (
                self.save_groupware(message, folder, target, Some(uid))
                    .await?,
                true,
                PinnedRow::New,
            ),
            ImportWrite::Adopt(document_id) => (
                self.save_existing(message, folder, target, MapiId::new(space, document_id))
                    .await?,
                true,
                PinnedRow::Existing,
            ),
            ImportWrite::Edit(document_id) => (
                self.save_existing(message, folder, target, MapiId::new(space, document_id))
                    .await?,
                false,
                PinnedRow::Existing,
            ),
        };
        let document_id = saved.id.id;
        if alias {
            set_groupware_alias(
                self.request.server,
                message.mailbox_id,
                GroupwareAlias {
                    kind,
                    container: folder.container(),
                    document_id,
                    item,
                },
            )
            .await
            .caused_by(trc::location!())?;
        }
        self.record_stream_alias(collector, document_id, placement)?;
        self.pin_groupware_version(
            message.mailbox_id,
            (kind, document_id),
            saved.change.or(import.stored_change),
            (import.version, row),
        )
        .await;
        Ok(Saved {
            id: MapiId::new(IdSpace::Email, item),
            ..saved
        })
    }

    pub(in crate::mapi::emsmdb) async fn pin_groupware_version(
        &mut self,
        account_id: u32,
        item: (GroupwareKind, u32),
        change_id: Option<u64>,
        pinned: (ConflictState, PinnedRow),
    ) {
        let Some(change_id) = change_id else {
            return;
        };
        if let Err(err) = self
            .write_groupware_version(account_id, item, change_id, pinned)
            .await
        {
            trc::error!(
                err.account_id(account_id)
                    .document_id(item.1)
                    .details("Failed to store the client version of a groupware import")
                    .caused_by(trc::location!())
            );
        }
    }

    async fn write_groupware_version(
        &mut self,
        account_id: u32,
        (kind, document_id): (GroupwareKind, u32),
        change_id: u64,
        (conflict, row): (ConflictState, PinnedRow),
    ) -> trc::Result<()> {
        let server = self.request.server;
        let owner = server
            .exchange_quota_owner(self.request.access_token, account_id)
            .await?;
        let max_size = server.core.exchange.max_object_size;
        let collection = kind.collection();
        let mut unread = row == PinnedRow::New;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let previous = if mem::take(&mut unread) {
                None
            } else {
                server
                    .exchange_object(account_id, collection, document_id)
                    .await
                    .caused_by(trc::location!())?
            };
            if previous
                .as_ref()
                .and_then(|previous| previous.version.change_id())
                .is_some_and(|pinned| pinned > change_id)
            {
                return Ok(());
            }
            let next = match &previous {
                Some(previous) => previous.deserialize::<ExchangeObject>()?,
                None => ExchangeObject::default(),
            };
            let mut batch = BatchBuilder::new();
            let built = ExchangeObjectWrite {
                owner,
                collection,
                document_id: PendingId::Assigned(document_id),
                stamp: OwnerStamp::Logged,
                version: ObjectVersion::ClientAt {
                    conflict: conflict.clone(),
                    change_id,
                },
                previous: previous.as_ref(),
                next: Some(next),
                max_size,
            }
            .build(&mut batch);
            match built {
                Ok(()) => {}
                Err(err) if err.matches(EventType::Limit(LimitEvent::SizeRequest)) => {
                    return Ok(());
                }
                Err(err) => return Err(err),
            }
            match server.commit_batch(batch).await {
                Ok(_) => {
                    if previous.is_none() {
                        server.mark_exchange_stale(account_id);
                        self.invalidate_mailbox();
                    }
                    return Ok(());
                }
                Err(err) if err.is_assertion_failure() => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    async fn save_existing(
        &mut self,
        message: &MessageObject,
        folder: GroupwareFolder,
        target: SaveTarget,
        stored: MapiId,
    ) -> Result<Saved, RopError> {
        let existing = MessageObject {
            message: stored.counter(),
            ..message.clone()
        };
        let target = SaveTarget {
            base: Some(stored),
            ..target
        };
        self.save_groupware(&existing, folder, target, None).await
    }

    async fn import_write(
        &mut self,
        message: &MessageObject,
        folder: GroupwareFolder,
        placement: GroupwarePlacement,
        collector: u32,
    ) -> Result<ImportWrite, RopError> {
        let account_id = message.mailbox_id;
        let uid = self.import_uid(message, folder, placement.item).await?;
        let collection = match folder {
            GroupwareFolder::AddressBook(_) => SyncCollection::AddressBook,
            GroupwareFolder::Calendar(..) => SyncCollection::Calendar,
        };
        let resources = self
            .request
            .server
            .fetch_groupware_resources(account_id, account_id, collection)
            .await
            .caused_by(trc::location!())?;
        let holder = match folder {
            GroupwareFolder::AddressBook(address_book) => {
                match assert_unique_card_uid(&resources, address_book, Some(&uid)) {
                    Ok(()) => None,
                    Err(CardWriteError::UidConflict { document_id, .. }) => Some(document_id),
                    Err(err) => return Err(card_error(err)),
                }
            }
            GroupwareFolder::Calendar(calendar, _) => {
                match assert_unique_event_uid(
                    &resources,
                    self.request.access_token,
                    account_id,
                    calendar,
                    Some(&uid),
                ) {
                    Ok(()) => None,
                    Err(EventWriteError::UidConflict { document_id, .. }) => Some(document_id),
                    Err(err) => return Err(event_error(err)),
                }
            }
        };
        let Some(document_id) = holder else {
            return Ok(ImportWrite::Create(uid));
        };
        let kind = placement.folder.kind;
        let streamed = self.stream_aliases(collector)?.placement(kind, document_id);
        let aliased = match streamed {
            Some(aliased) => Some(aliased),
            None => self
                .mailbox(account_id)
                .await?
                .exchange
                .groupware_aliases
                .placement(kind, document_id),
        };
        match aliased {
            None => Ok(ImportWrite::Adopt(document_id)),
            Some(aliased) if aliased == placement => Ok(ImportWrite::Edit(document_id)),
            Some(aliased)
                if aliased.folder != placement.folder
                    && !resources.item_by_id(document_id).is_some_and(|item| {
                        item.child_names()
                            .iter()
                            .any(|name| name.parent_id == aliased.folder.id)
                    }) =>
            {
                Ok(ImportWrite::Adopt(document_id))
            }
            Some(_) => Err(RopError::Code(ErrorCode::SYNC_CONFLICT)),
        }
    }

    async fn import_uid(
        &mut self,
        message: &MessageObject,
        folder: GroupwareFolder,
        item: u32,
    ) -> Result<String, RopError> {
        if let GroupwareFolder::Calendar(_, CalendarItem::Event) = folder
            && let Some(uid) = meeting_uid(&self.staged_message(message)?.content.props)
        {
            return Ok(uid.into_owned());
        }
        let guids = self.store_guids(message.mailbox_id).await?;
        Ok(client_uid(guids.mailbox, item))
    }
}

fn client_uid(mailbox: Guid, item: u32) -> String {
    format!(
        "{:032x}-{:012x}",
        u128::from_be_bytes(mailbox.0),
        MapiId::new(IdSpace::Email, item).to_eid().counter.get()
    )
}
