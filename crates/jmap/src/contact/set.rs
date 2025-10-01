/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::contact::ContactCard,
};

pub trait ContactCardSet: Sync + Send {
    fn contact_card_set(
        &self,
        request: SetRequest<'_, ContactCard>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<ContactCard>>> + Send;
}

impl ContactCardSet for Server {
    async fn contact_card_set(
        &self,
        mut request: SetRequest<'_, ContactCard>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<SetResponse<ContactCard>> {
        todo!()
    }
}
