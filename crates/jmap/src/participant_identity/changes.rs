/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{changes::get::IntermediateChangesResponse, participant_identity::set::identity_state};
use common::Server;
use groupware::calendar::ParticipantIdentities;
use jmap_proto::{
    method::changes::{ChangesRequest, ChangesResponse},
    request::method::MethodObject,
    types::state::State,
};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes},
};
use trc::AddContext;
use types::{collection::Collection, field::PrincipalField, id::Id};

pub trait ParticipantIdentityChanges: Sync + Send {
    fn participant_identity_changes(
        &self,
        request: ChangesRequest,
    ) -> impl Future<Output = trc::Result<IntermediateChangesResponse>> + Send;
}

impl ParticipantIdentityChanges for Server {
    async fn participant_identity_changes(
        &self,
        request: ChangesRequest,
    ) -> trc::Result<IntermediateChangesResponse> {
        let identities = self
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
                request.account_id.document_id(),
                Collection::Principal,
                0,
                PrincipalField::ParticipantIdentities,
            ))
            .await
            .caused_by(trc::location!())?
            .map(|archive| archive.deserialize::<ParticipantIdentities>())
            .transpose()
            .caused_by(trc::location!())?
            .unwrap_or_default();
        let since = match &request.since_state {
            State::Initial => 0,
            State::Exact(change_id) => u32::try_from(*change_id)
                .map_err(|_| trc::JmapEvent::CannotCalculateChanges.into_err())?,
            State::Intermediate(_) => {
                return Err(trc::JmapEvent::CannotCalculateChanges.into_err());
            }
        };
        let max_changes = match request.max_changes {
            Some(0) => {
                return Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details("maxChanges must be greater than 0."));
            }
            Some(max_changes) => max_changes.min(self.core.jmap.changes_max_results),
            None => self.core.jmap.changes_max_results,
        };

        let changes = identities
            .changes_since(since, max_changes)
            .ok_or_else(|| trc::JmapEvent::CannotCalculateChanges.into_err())?;

        Ok(IntermediateChangesResponse {
            response: ChangesResponse {
                account_id: request.account_id,
                old_state: request.since_state,
                new_state: identity_state(changes.new_change_id),
                has_more_changes: changes.has_more_changes,
                created: changes.created.into_iter().map(Id::from).collect(),
                updated: changes.updated.into_iter().map(Id::from).collect(),
                destroyed: changes.destroyed.into_iter().map(Id::from).collect(),
                updated_properties: None,
            },
            object: MethodObject::ParticipantIdentity,
            only_container_changes: false,
        })
    }
}
