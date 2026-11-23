/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    execute::{RopContext, RopError, RopResult},
    state::ServerObject,
};
use crate::store::named::{AccountNamedProps, ExchangeNamedProperties};
use exchange_proto::mapi::{
    ErrorCode,
    prop::{FIRST_NAMED_ID, NamedPropMap, PropId, PropKey, PropKeyRef, PropertyName, sets},
    rop::{
        DecodedRop, ResponseHeader,
        requests::{GetNamesFromPropertyIds, GetPropertyIdsFromNames, QueryNamedProperties},
        responses::{
            GetNamesFromPropertyIdsResponse, GetPropertyIdsFromNamesResponse,
            QueryNamedPropertiesResponse,
        },
    },
};
use smallvec::SmallVec;

const MNID_CREATE: u8 = 0x02;
const DELEGATE_NAMED_LIMIT: usize = 0x4000;
const UNRESOLVED: PropId = PropId(0);
const FIRST_NON_MAPI_ID: u16 = 0x8000;

enum NameLookup {
    Fixed(PropId),
    Store(PropKey),
}

impl RopContext<'_, '_> {
    pub(super) fn logon_mailbox(&self, rop: &DecodedRop<'_>) -> Result<u32, RopError> {
        let handle = self.input(rop.header.input_handle)?;
        self.state
            .logon_of(handle)
            .map(|(_, logon)| logon.mailbox_id)
            .ok_or(RopError::Code(ErrorCode::NULL_OBJECT))
    }

    pub async fn get_property_ids_from_names(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetPropertyIdsFromNames<'_>,
    ) -> RopResult {
        let mailbox_id = self.logon_mailbox(rop)?;
        if request.property_names.is_empty() {
            return self.enumerate_named_ids(rop, index, mailbox_id).await;
        }
        let mut scratch = String::new();
        let names: Vec<NameLookup> = request
            .property_names
            .iter()
            .map(|name| match name {
                PropertyName::Lid { set, lid } if set == sets::PS_MAPI => NameLookup::Fixed(
                    u16::try_from(lid)
                        .ok()
                        .filter(|lid| *lid < FIRST_NON_MAPI_ID)
                        .map_or(UNRESOLVED, PropId),
                ),
                PropertyName::Name { set, .. } if set == sets::PS_MAPI => {
                    NameLookup::Fixed(UNRESOLVED)
                }
                name => name
                    .to_key_ref(&mut scratch)
                    .map_or(NameLookup::Fixed(UNRESOLVED), |key| {
                        NameLookup::Store(key.to_key())
                    }),
            })
            .collect();
        let keys: Vec<PropKeyRef<'_>> = names
            .iter()
            .filter_map(|name| match name {
                NameLookup::Store(key) => Some(key.as_ref()),
                NameLookup::Fixed(_) => None,
            })
            .collect();
        let create = (request.flags & MNID_CREATE != 0).then(|| {
            if self.request.access_token.is_account_id(mailbox_id) {
                usize::MAX
            } else {
                DELEGATE_NAMED_LIMIT
            }
        });
        let mailbox = self.mailbox(mailbox_id).await?;
        let resolved = if keys.is_empty() {
            Vec::new()
        } else {
            self.request
                .server
                .named_property_ids(mailbox_id, &mailbox.exchange, &keys, create)
                .await?
        };
        if create.is_some() && !keys.is_empty() {
            self.invalidate_mailbox();
        }
        let mut resolved = resolved.into_iter();
        let ids: SmallVec<[PropId; 16]> = names
            .iter()
            .map(|name| match name {
                NameLookup::Fixed(id) => *id,
                NameLookup::Store(_) => resolved.next().flatten().unwrap_or(UNRESOLVED),
            })
            .collect();
        let code = if create.is_some() && ids.contains(&UNRESOLVED) {
            ErrorCode::WARN_WITH_ERRORS
        } else {
            ErrorCode::SUCCESS
        };
        self.writer
            .response(
                ResponseHeader::new(rop.header.id.response_id(), index, code),
                &GetPropertyIdsFromNamesResponse { property_ids: &ids },
            )
            .map_err(RopError::from)
    }

    async fn enumerate_named_ids(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        mailbox_id: u32,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        if !matches!(self.state.get(handle), Some(ServerObject::Logon(_))) {
            return self.respond(
                rop,
                index,
                &GetPropertyIdsFromNamesResponse { property_ids: &[] },
            );
        }
        let cache = self.mailbox(mailbox_id).await?.exchange;
        let names = AccountNamedProps::new(&cache);
        let ids: Vec<PropId> = (FIRST_NAMED_ID.0..=u16::MAX)
            .map(PropId)
            .take_while(|id| names.key(*id).is_some())
            .collect();
        self.respond(
            rop,
            index,
            &GetPropertyIdsFromNamesResponse { property_ids: &ids },
        )
    }

    pub async fn query_named_properties(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &QueryNamedProperties,
    ) -> RopResult {
        let mailbox_id = self.logon_mailbox(rop)?;
        let cache = self.mailbox(mailbox_id).await?.exchange;
        let names = AccountNamedProps::new(&cache);
        let mut entries = Vec::new();
        for id in (FIRST_NAMED_ID.0..=u16::MAX).map(PropId) {
            let Some(key) = names.key(id) else {
                if names.may_be_newer(id) {
                    break;
                }
                continue;
            };
            let (set, is_string) = match key {
                PropKeyRef::Lid { set, .. } => (set, false),
                PropKeyRef::Name { set, .. } => (set, true),
                PropKeyRef::Tag(_) => continue,
            };
            let filtered = if is_string {
                request.query_flags & QueryNamedProperties::NO_STRINGS != 0
            } else {
                request.query_flags & QueryNamedProperties::NO_IDS != 0
            };
            if !filtered && request.property_guid.is_none_or(|guid| guid == set) {
                entries.push((id, key));
            }
        }
        self.respond(
            rop,
            index,
            &QueryNamedPropertiesResponse { entries: &entries },
        )
    }

    pub async fn get_names_from_property_ids(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &GetNamesFromPropertyIds<'_>,
    ) -> RopResult {
        let mailbox_id = self.logon_mailbox(rop)?;
        let mut cache = self.mailbox(mailbox_id).await?.exchange;
        let newer = {
            let names = AccountNamedProps::new(&cache);
            request.property_ids.iter().any(|id| {
                id.0 >= FIRST_NAMED_ID.0 && names.key(id).is_none() && names.may_be_newer(id)
            })
        };
        if newer {
            cache = self
                .request
                .server
                .reload_named_properties(mailbox_id)
                .await?;
            self.invalidate_mailbox();
        }
        let names = AccountNamedProps::new(&cache);
        let keys: SmallVec<[PropKeyRef<'_>; 16]> = request
            .property_ids
            .iter()
            .map(|id| {
                if id.0 < FIRST_NON_MAPI_ID {
                    PropKeyRef::Lid {
                        set: sets::PS_MAPI,
                        lid: u32::from(id.0),
                    }
                } else {
                    names.key(id).unwrap_or(PropKeyRef::Tag(id))
                }
            })
            .collect();
        self.respond(
            rop,
            index,
            &GetNamesFromPropertyIdsResponse {
                property_names: &keys,
            },
        )
    }
}
