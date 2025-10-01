/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    method::set::{SetRequest, SetResponse},
    object::addressbook::AddressBook,
};

pub trait AddressBookSet: Sync + Send {
    fn address_book_set(
        &self,
        request: SetRequest<'_, AddressBook>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<SetResponse<AddressBook>>> + Send;
}

impl AddressBookSet for Server {
    async fn address_book_set(
        &self,
        mut request: SetRequest<'_, AddressBook>,
        access_token: &AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<SetResponse<AddressBook>> {
        todo!()
    }
}
