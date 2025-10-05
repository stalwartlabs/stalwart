/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::method::availability::{GetAvailabilityRequest, GetAvailabilityResponse};
use std::future::Future;

pub trait PrincipalGetAvailability: Sync + Send {
    fn principal_get_availability(
        &self,
        request: GetAvailabilityRequest,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetAvailabilityResponse>> + Send;
}

impl PrincipalGetAvailability for Server {
    async fn principal_get_availability(
        &self,
        mut request: GetAvailabilityRequest,
        access_token: &AccessToken,
    ) -> trc::Result<GetAvailabilityResponse> {
        todo!()
    }
}
