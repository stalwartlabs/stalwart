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
use registry::schema::prelude::ObjectType;

pub trait RegistryQuery: Sync + Send {
    fn registry_query(
        &self,
        object_type: ObjectType,
        request: QueryRequest<Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl RegistryQuery for Server {
    async fn registry_query(
        &self,
        object_type: ObjectType,
        mut request: QueryRequest<Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        todo!()
    }
}
