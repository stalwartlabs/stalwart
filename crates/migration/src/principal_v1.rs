/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    email_v1::migrate_emails_v011, encryption_v1::migrate_encryption_params_v011, get_document_ids,
    identity_v1::migrate_identities_v011, mailbox::migrate_mailboxes,
    push_v1::migrate_push_subscriptions_v011, sieve_v1::migrate_sieve_v011,
    submission::migrate_email_submissions, threads::migrate_threads,
};
use common::Server;
use directory::{
    Permission, Principal, PrincipalData, ROLE_ADMIN, ROLE_USER, Type,
    backend::internal::{PrincipalField, PrincipalSet, SpecialSecrets},
};
use nlp::tokenizers::word::WordTokenizer;
use std::{slice::Iter, time::Instant};
use store::{
    Deserialize, Serialize, ValueKey,
    ahash::{AHashMap, AHashSet},
    backend::MAX_TOKEN_LENGTH,
    roaring::RoaringBitmap,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, DirectoryClass, ValueClass},
};
use trc::AddContext;
use types::collection::Collection;
use utils::codec::leb128::Leb128Iterator;

pub(crate) async fn migrate_principals_v0_11(server: &Server) -> trc::Result<RoaringBitmap> {
    // Obtain email ids
    let principal_ids = get_document_ids(server, u32::MAX, Collection::Principal)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    let num_principals = principal_ids.len();
    if num_principals == 0 {
        return Ok(principal_ids);
    }
    let mut num_migrated = 0;

    for principal_id in principal_ids.iter() {
        match server
            .store()
            .get_value::<LegacyPrincipal>(ValueKey {
                account_id: u32::MAX,
                collection: Collection::Principal.into(),
                document_id: principal_id,
                class: ValueClass::Directory(DirectoryClass::Principal(principal_id)),
            })
            .await
        {
            Ok(Some(legacy)) => {
                let mut principal = Principal::from_legacy(legacy);
                principal.sort();
                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(u32::MAX)
                    .with_collection(Collection::Principal)
                    .with_document(principal_id);

                build_search_index(&mut batch, principal_id, &principal);

                batch.set(
                    ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                    Archiver::new(principal)
                        .serialize()
                        .caused_by(trc::location!())?,
                );
                num_migrated += 1;

                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
            }
            Ok(None) => (),
            Err(err) => {
                if server
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey {
                        account_id: u32::MAX,
                        collection: Collection::Principal.into(),
                        document_id: principal_id,
                        class: ValueClass::Directory(DirectoryClass::Principal(principal_id)),
                    })
                    .await
                    .is_err()
                {
                    return Err(err.account_id(principal_id).caused_by(trc::location!()));
                }
            }
        }
    }

    // Increment document id counter
    if num_migrated > 0 {
        server
            .store()
            .assign_document_ids(
                u32::MAX,
                Collection::Principal,
                principal_ids
                    .max()
                    .map(|id| id as u64)
                    .unwrap_or(num_principals)
                    + 1,
            )
            .await
            .caused_by(trc::location!())?;

        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!("Migrated {num_migrated} principals",)
        );
    }

    Ok(principal_ids)
}

pub(crate) async fn migrate_principal_v0_11(server: &Server, account_id: u32) -> trc::Result<()> {
    let start_time = Instant::now();
    let num_emails = migrate_emails_v011(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_mailboxes = migrate_mailboxes(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_params = migrate_encryption_params_v011(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_subscriptions = migrate_push_subscriptions_v011(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_sieve = migrate_sieve_v011(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_submissions = migrate_email_submissions(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_threads = migrate_threads(server, account_id)
        .await
        .caused_by(trc::location!())?;
    let num_identities = migrate_identities_v011(server, account_id)
        .await
        .caused_by(trc::location!())?;

    if num_emails > 0
        || num_mailboxes > 0
        || num_params > 0
        || num_subscriptions > 0
        || num_sieve > 0
        || num_submissions > 0
        || num_threads > 0
        || num_identities > 0
    {
        trc::event!(
            Server(trc::ServerEvent::Startup),
            Details = format!(
                "Migrated accountId {account_id} with {num_emails} emails, {num_mailboxes} mailboxes, {num_params} encryption params, {num_submissions} email submissions, {num_sieve} sieve scripts, {num_subscriptions} push subscriptions, {num_threads} threads, and {num_identities} identities"
            ),
            Elapsed = start_time.elapsed()
        );
    }

    Ok(())
}

trait FromLegacy {
    fn from_legacy(legacy: LegacyPrincipal) -> Self;
}

impl FromLegacy for Principal {
    fn from_legacy(legacy: LegacyPrincipal) -> Self {
        let mut legacy = legacy.0;
        let mut principal = Principal {
            id: legacy.id,
            typ: legacy.typ,
            name: legacy.name().to_string(),
            data: Default::default(),
        };

        // Map fields
        let mut has_secret = false;
        for secret in legacy
            .take_str_array(PrincipalField::Secrets)
            .unwrap_or_default()
        {
            if secret.is_otp_secret() {
                principal.data.push(PrincipalData::OtpAuth(secret));
            } else if secret.is_app_secret() {
                principal.data.push(PrincipalData::AppPassword(secret));
            } else if !has_secret {
                principal.data.push(PrincipalData::Password(secret));
                has_secret = true;
            }
        }
        for (idx, email) in legacy
            .take_str_array(PrincipalField::Emails)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            if idx == 0 {
                principal
                    .data
                    .push(PrincipalData::PrimaryEmail(email.clone()));
            } else {
                principal
                    .data
                    .push(PrincipalData::EmailAlias(email.clone()));
            }
        }
        if let Some(picture) = legacy.take_str(PrincipalField::Picture) {
            principal.data.push(PrincipalData::Picture(picture));
        }
        for url in legacy
            .take_str_array(PrincipalField::Urls)
            .unwrap_or_default()
        {
            principal.data.push(PrincipalData::Url(url));
        }
        for member in legacy
            .take_str_array(PrincipalField::ExternalMembers)
            .unwrap_or_default()
        {
            principal.data.push(PrincipalData::ExternalMember(member));
        }

        if let Some(quotas) = legacy.take_int_array(PrincipalField::Quota) {
            for (idx, quota) in quotas.into_iter().take(Type::MAX_ID + 2).enumerate() {
                if quota != 0 {
                    if idx != 0 {
                        principal.data.push(PrincipalData::DirectoryQuota {
                            quota: quota as u32,
                            typ: Type::from_u8((idx - 1) as u8),
                        });
                    } else {
                        principal.data.push(PrincipalData::DiskQuota(quota));
                    }
                }
            }
        }

        // Map permissions
        let mut permissions = AHashMap::new();
        for field in [
            PrincipalField::EnabledPermissions,
            PrincipalField::DisabledPermissions,
        ] {
            let is_disabled = field == PrincipalField::DisabledPermissions;
            if let Some(ids) = legacy.take_int_array(field) {
                for id in ids {
                    if Permission::from_id(id as u32).is_some() {
                        permissions.insert(id as u32, is_disabled);
                    }
                }
            }
        }
        if !permissions.is_empty() {
            for (k, v) in permissions {
                principal.data.push(PrincipalData::Permission {
                    permission_id: k,
                    grant: !v,
                });
            }
        }

        principal
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LegacyPrincipal(PrincipalSet);

impl Deserialize for LegacyPrincipal {
    fn deserialize(bytes: &[u8]) -> trc::Result<Self> {
        deserialize(bytes).ok_or_else(|| {
            trc::StoreEvent::DataCorruption
                .caused_by(trc::location!())
                .ctx(trc::Key::Value, bytes)
        })
    }
}

const INT_MARKER: u8 = 1 << 7;

fn deserialize(bytes: &[u8]) -> Option<LegacyPrincipal> {
    let mut bytes = bytes.iter();

    match *bytes.next()? {
        1 => {
            // Version 1 (legacy)
            let id = bytes.next_leb128()?;
            let type_id = *bytes.next()?;

            let mut principal = PrincipalSet {
                id,
                typ: Type::from_u8(type_id),
                ..Default::default()
            };

            principal.set(PrincipalField::Quota, bytes.next_leb128::<u64>()?);
            principal.set(PrincipalField::Name, deserialize_string(&mut bytes)?);
            if let Some(description) = deserialize_string(&mut bytes).filter(|s| !s.is_empty()) {
                principal.set(PrincipalField::Description, description);
            }
            for key in [PrincipalField::Secrets, PrincipalField::Emails] {
                for _ in 0..bytes.next_leb128::<usize>()? {
                    principal.append_str(key, deserialize_string(&mut bytes)?);
                }
            }

            LegacyPrincipal(principal.with_field(
                PrincipalField::Roles,
                if type_id != 4 { ROLE_USER } else { ROLE_ADMIN },
            ))
            .into()
        }
        2 => {
            // Version 2
            let typ = Type::from_u8(*bytes.next()?);
            let num_fields = bytes.next_leb128::<usize>()?;

            let mut principal = PrincipalSet {
                id: u32::MAX,
                typ,
                fields: AHashMap::with_capacity(num_fields),
            };

            for _ in 0..num_fields {
                let id = *bytes.next()?;
                let num_values = bytes.next_leb128::<usize>()?;

                if (id & INT_MARKER) == 0 {
                    let field = PrincipalField::from_id(id)?;
                    if num_values == 1 {
                        principal.set(field, deserialize_string(&mut bytes)?);
                    } else {
                        let mut values = Vec::with_capacity(num_values);
                        for _ in 0..num_values {
                            values.push(deserialize_string(&mut bytes)?);
                        }
                        principal.set(field, values);
                    }
                } else {
                    let field = PrincipalField::from_id(id & !INT_MARKER)?;
                    if num_values == 1 {
                        principal.set(field, bytes.next_leb128::<u64>()?);
                    } else {
                        let mut values = Vec::with_capacity(num_values);
                        for _ in 0..num_values {
                            values.push(bytes.next_leb128::<u64>()?);
                        }
                        principal.set(field, values);
                    }
                }
            }

            LegacyPrincipal(principal).into()
        }
        _ => None,
    }
}

fn deserialize_string(bytes: &mut Iter<'_, u8>) -> Option<String> {
    let len = bytes.next_leb128()?;
    let mut string = Vec::with_capacity(len);
    for _ in 0..len {
        string.push(*bytes.next()?);
    }
    String::from_utf8(string).ok()
}

pub(crate) fn build_search_index(batch: &mut BatchBuilder, principal_id: u32, new: &Principal) {
    let mut new_words = AHashSet::new();

    for word in [Some(new.name.as_str()), new.description()]
        .into_iter()
        .chain(new.email_addresses().map(Some))
        .flatten()
    {
        new_words.extend(WordTokenizer::new(word, MAX_TOKEN_LENGTH).map(|t| t.word));
    }

    for word in new_words {
        batch.set(
            DirectoryClass::Index {
                word: word.as_bytes().to_vec(),
                principal_id,
            },
            vec![],
        );
    }
}
