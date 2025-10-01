/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::{Server, auth::AccessToken};
use jmap_proto::{
    method::parse::{ParseRequest, ParseResponse},
    object::contact::ContactCard,
};

pub trait ContactCardParse: Sync + Send {
    fn contact_card_parse(
        &self,
        request: ParseRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<ParseResponse<ContactCard>>> + Send;
}

impl ContactCardParse for Server {
    async fn contact_card_parse(
        &self,
        request: ParseRequest<ContactCard>,
        access_token: &AccessToken,
    ) -> trc::Result<ParseResponse<ContactCard>> {
        todo!()
    }
}
