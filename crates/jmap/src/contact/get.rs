/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::contact::ContactCard,
};

pub trait ContactCardGet: Sync + Send {
    fn contact_card_get(
        &self,
        request: GetRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<ContactCard>>> + Send;
}

impl ContactCardGet for Server {
    async fn contact_card_get(
        &self,
        mut request: GetRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<ContactCard>> {
        todo!()
    }
}
