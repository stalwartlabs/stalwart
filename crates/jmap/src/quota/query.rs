/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::query::{QueryRequest, QueryResponse},
    object::quota::Quota,
    types::state::State,
};
use std::future::Future;
use types::id::Id;

pub trait QuotaQuery: Sync + Send {
    fn quota_query(
        &self,
        request: QueryRequest<Quota>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl QuotaQuery for Server {
    async fn quota_query(
        &self,
        request: QueryRequest<Quota>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        Ok(QueryResponse {
            account_id: request.account_id,
            query_state: State::Initial,
            can_calculate_changes: false,
            position: 0,
            ids: if access_token.quota > 0 {
                vec![Id::new(0)]
            } else {
                vec![]
            },
            total: Some(1),
            limit: None,
        })
    }
}
