/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::copy::{CopyRequest, CopyResponse},
    object::contact::ContactCard,
    request::{Call, RequestMethod},
};

pub trait JmapContactCardCopy: Sync + Send {
    fn contact_card_copy<'x>(
        &self,
        request: CopyRequest<'x, ContactCard>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<CopyResponse<ContactCard>>> + Send;
}

impl JmapContactCardCopy for Server {
    async fn contact_card_copy<'x>(
        &self,
        request: CopyRequest<'x, ContactCard>,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> trc::Result<CopyResponse<ContactCard>> {
        todo!()
    }
}
