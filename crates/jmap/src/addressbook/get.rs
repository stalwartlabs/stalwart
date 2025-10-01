/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::addressbook::AddressBook,
};

pub trait AddressBookGet: Sync + Send {
    fn address_book_get(
        &self,
        request: GetRequest<AddressBook>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<GetResponse<AddressBook>>> + Send;
}

impl AddressBookGet for Server {
    async fn address_book_get(
        &self,
        mut request: GetRequest<AddressBook>,
        access_token: &AccessToken,
    ) -> trc::Result<GetResponse<AddressBook>> {
        todo!()
    }
}
