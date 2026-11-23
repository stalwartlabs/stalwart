/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    load::embedded,
    object_row::{decode_property, encode_key, encode_property},
    open_columns,
};
use crate::{
    cache::ExchangeCacheFetch,
    mapi::{
        emsmdb::{
            execute::{RopContext, RopError, RopResult},
            state::RecipientColumns,
        },
        ids::{IdSpace, MapiId},
    },
    store::{
        account::ExchangeAccountStore,
        object::{ExchangeObject, ExchangeObjectWrite, ObjectVersion, OwnerStamp},
    },
};
use exchange_proto::{
    ids::Eid,
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropKeyRef, tags},
        rop::{
            DecodedRop,
            requests::{GetMessageStatus, SetMessageStatus},
            responses::{
                GetAddressTypesResponse, GetMessageStatusResponse, SetMessageStatusResponse,
            },
        },
    },
};
use store::write::{BatchBuilder, PendingId};
use types::collection::Collection;

const ADDRESS_TYPES: [&[u8]; 2] = [b"SMTP", b"EX"];
const MAX_ATTEMPTS: usize = 3;

struct StatusTarget {
    mailbox_id: u32,
    document_id: u32,
}

impl RopContext<'_, '_> {
    pub async fn get_message_status(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetMessageStatus,
    ) -> RopResult {
        let target = self.status_target(rop, request.message_id).await?;
        let message_status_flags = match target {
            Some(target) => {
                let row = self
                    .object_row(target.mailbox_id, target.document_id)
                    .await?;
                match row {
                    Some(row) => {
                        let key = status_key();
                        status_of(&key, row.unarchive::<ExchangeObject>()?.property(&key))
                    }
                    None => 0,
                }
            }
            None => 0,
        };
        self.respond(
            rop,
            index,
            &GetMessageStatusResponse {
                message_status_flags,
            },
        )
    }

    pub async fn set_message_status(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetMessageStatus,
    ) -> RopResult {
        let target = self
            .status_target(rop, request.message_id)
            .await?
            .ok_or(ErrorCode::NOT_SUPPORTED)?;
        let mask = request.message_status_mask;
        let server = self.request.server;
        let owner = server
            .exchange_quota_owner(self.request.access_token, target.mailbox_id)
            .await?;
        let key = status_key();
        for _ in 0..MAX_ATTEMPTS {
            let previous = self
                .object_row(target.mailbox_id, target.document_id)
                .await?;
            let mut next = previous
                .as_ref()
                .map(|previous| previous.deserialize::<ExchangeObject>())
                .transpose()?
                .unwrap_or_default();
            let previous_flags = status_of(&key, next.property(&key));
            let next_flags = (previous_flags & !mask) | (request.message_status_flags & mask);
            if next_flags != previous_flags {
                if next_flags == 0 {
                    next.remove_property(&key);
                } else {
                    let property = encode_property(
                        PropKeyRef::Tag(tags::MESSAGE_STATUS.id()),
                        &OwnedPropValue::I32(i32::from_ne_bytes(next_flags.to_ne_bytes())),
                    );
                    next.set_property(property.key, property.value);
                }
                let mut batch = BatchBuilder::new();
                ExchangeObjectWrite {
                    owner,
                    collection: Collection::Email,
                    document_id: PendingId::Assigned(target.document_id),
                    stamp: OwnerStamp::Logged,
                    version: ObjectVersion::Kept,
                    previous: previous.as_ref(),
                    next: (!next.is_empty()).then_some(next),
                    max_size: server.core.exchange.max_object_size,
                }
                .build(&mut batch)?;
                match server.commit_batch(batch).await {
                    Ok(_) => {
                        server.mark_exchange_stale(target.mailbox_id);
                        self.invalidate_mailbox();
                    }
                    Err(err) if err.is_assertion_failure() => {
                        server.mark_exchange_stale(target.mailbox_id);
                        self.invalidate_mailbox();
                        continue;
                    }
                    Err(err) => return Err(err.caused_by(trc::location!()).into()),
                }
            }
            return self.respond(
                rop,
                index,
                &SetMessageStatusResponse {
                    message_status_flags: previous_flags,
                },
            );
        }
        Err(RopError::Code(ErrorCode::OBJECT_MODIFIED))
    }

    pub fn get_address_types(&mut self, rop: &DecodedRop<'_>, index: u8) -> RopResult {
        self.input(rop.header.input_handle)?;
        self.respond(
            rop,
            index,
            &GetAddressTypesResponse {
                address_types: &ADDRESS_TYPES,
            },
        )
    }

    pub async fn reload_cached_information(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let message = self.message_object(handle)?;
        let root = self.message_root(&message).await?;
        let content = embedded(&root, &message.path).ok_or(ErrorCode::OBJECT_DELETED)?;
        let columns = open_columns(content);
        self.respond_open(rop, index, content, None)?;
        if columns == RecipientColumns::Fixed {
            self.set_recipient_columns(handle, columns);
        }
        Ok(())
    }

    async fn status_target(
        &mut self,
        rop: &DecodedRop<'_>,
        message_id: Eid,
    ) -> Result<Option<StatusTarget>, RopError> {
        let folder = self.open_folder_at(self.input(rop.header.input_handle)?)?;
        let id = MapiId::from_eid(message_id)
            .filter(|id| !id.space.is_folder())
            .ok_or(ErrorCode::NOT_FOUND)?;
        let folder_id = MapiId::from_node(folder.node);
        if !self
            .message_in_folder(folder.mailbox_id, folder_id, id)
            .await?
        {
            return Err(RopError::Code(ErrorCode::NOT_FOUND));
        }
        Ok(self
            .mailbox(folder.mailbox_id)
            .await?
            .stored_item(folder_id.counter(), id)
            .filter(|stored| stored.space == IdSpace::Email)
            .map(|stored| StatusTarget {
                mailbox_id: folder.mailbox_id,
                document_id: stored.id,
            }))
    }
}

fn status_key() -> Vec<u8> {
    encode_key(PropKeyRef::Tag(tags::MESSAGE_STATUS.id()))
}

fn status_of(key: &[u8], value: Option<&[u8]>) -> u32 {
    match value.and_then(|value| decode_property(key, value)) {
        Some((_, OwnedPropValue::I32(flags))) => u32::from_ne_bytes(flags.to_ne_bytes()),
        _ => 0,
    }
}
