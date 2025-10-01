/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{QueryRequest, QueryResponse},
    object::contact::ContactCard,
};

pub trait ContactCardQuery: Sync + Send {
    fn contact_card_query(
        &self,
        request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl ContactCardQuery for Server {
    async fn contact_card_query(
        &self,
        mut request: QueryRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        todo!()
    }
}
