/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::registry::mapping::RegistryGetResponse;
use registry::{
    jmap::IntoValue,
    schema::{
        prelude::ObjectType,
        structs::{Account, AccountSettings},
    },
};
use types::id::Id;

pub(crate) async fn account_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let Some(Account::User(mut account)) = get
        .server
        .registry()
        .object::<Account>(get.account_id.into())
        .await?
    else {
        return Ok(get.not_found_any());
    };
    if get.access_token.tenant_id().is_some_and(|id| {
        account
            .member_tenant_id
            .is_none_or(|aid| aid.document_id() != id)
    }) {
        return Ok(get.not_found_any());
    }

    match get.object_type {
        ObjectType::AccountSettings => {
            let mut ids = get
                .ids
                .take()
                .unwrap_or_else(|| vec![Id::singleton()])
                .into_iter();

            for id in ids.by_ref() {
                if id == Id::singleton() {
                    get.insert(
                        id,
                        AccountSettings {
                            encryption_at_rest: account.encryption_at_rest,
                            locale: account.locale,
                            otp_auth: account.otp_auth,
                            secret: account.secret,
                        }
                        .into_value(),
                    );
                    break;
                } else {
                    get.not_found(id);
                }
            }

            get.response.not_found.extend(ids);
        }
        ObjectType::Credential => {
            let ids = if let Some(ids) = get.ids.take() {
                ids
            } else {
                account
                    .credentials
                    .keys()
                    .map(|id| Id::from(*id))
                    .collect::<Vec<_>>()
            };

            for id in ids {
                if let Some(credential) = account.credentials.remove(&id.document_id()) {
                    get.insert(id, credential.into_value());
                } else {
                    get.not_found(id);
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(get)
}
