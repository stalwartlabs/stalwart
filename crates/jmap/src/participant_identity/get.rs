/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::participant_identity::ParticipantIdentity,
};

pub trait ParticipantIdentityGet: Sync + Send {
    fn participant_identity_get(
        &self,
        request: GetRequest<ParticipantIdentity>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<ParticipantIdentity>>> + Send;
}

impl ParticipantIdentityGet for Server {
    async fn participant_identity_get(
        &self,
        mut request: GetRequest<ParticipantIdentity>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<ParticipantIdentity>> {
        todo!()
    }
}
