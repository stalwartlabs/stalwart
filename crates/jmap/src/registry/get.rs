/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::registry::Registry,
};

pub trait RegistryGet: Sync + Send {
    fn registry_get(
        &self,
        request: GetRequest<Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<Registry>>> + Send;
}

impl RegistryGet for Server {
    async fn registry_get(
        &self,
        mut request: GetRequest<Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<Registry>> {
        todo!()
    }
}
