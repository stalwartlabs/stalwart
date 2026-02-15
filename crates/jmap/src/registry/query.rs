/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{QueryRequest, QueryResponse},
    object::registry::Registry,
};

pub trait RegistryQuery: Sync + Send {
    fn registry_query(
        &self,
        request: QueryRequest<Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl RegistryQuery for Server {
    async fn registry_query(
        &self,
        mut request: QueryRequest<Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        todo!()
    }
}
