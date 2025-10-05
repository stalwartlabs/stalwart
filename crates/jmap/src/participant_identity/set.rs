/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::participant_identity::ParticipantIdentity,
};

pub trait ParticipantIdentitySet: Sync + Send {
    fn participant_identity_set(
        &self,
        request: SetRequest<'_, ParticipantIdentity>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<ParticipantIdentity>>> + Send;
}

impl ParticipantIdentitySet for Server {
    async fn participant_identity_set(
        &self,
        mut request: SetRequest<'_, ParticipantIdentity>,
        access_token: &AccessToken,
        _session: &HttpSessionData,
    ) -> trc::Result<SetResponse<ParticipantIdentity>> {
        todo!()
    }
}
