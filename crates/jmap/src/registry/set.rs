/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::registry::Registry,
};

pub trait RegistrySet: Sync + Send {
    fn registry_set(
        &self,
        request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<Registry>>> + Send;
}

impl RegistrySet for Server {
    async fn registry_set(
        &self,
        mut request: SetRequest<'_, Registry>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<Registry>> {
        todo!()
    }
}
