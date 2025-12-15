/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::Server;
use groupware::contact::{AddressBook, AddressBookPreferences};
use store::{
    Serialize, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder, serialize::rkyv_deserialize},
};
use trc::AddContext;
use types::{acl::AclGrant, collection::Collection, dead_property::DeadProperty, field::Field};

use crate::get_document_ids;

#[derive(
    rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, Debug, Default, Clone, PartialEq, Eq,
)]
#[rkyv(derive(Debug))]
pub struct AddressBookV2 {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub sort_order: u32,
    pub is_default: bool,
    pub subscribers: Vec<u32>,
    pub dead_properties: DeadProperty,
    pub acls: Vec<AclGrant>,
    pub created: i64,
    pub modified: i64,
}

pub(crate) async fn migrate_addressbook_v013(server: &Server, account_id: u32) -> trc::Result<u64> {
    let document_ids = get_document_ids(server, account_id, Collection::AddressBook)
        .await
        .caused_by(trc::location!())?
        .unwrap_or_default();
    if document_ids.is_empty() {
        return Ok(0);
    }
    let mut num_migrated = 0;

    for document_id in document_ids.iter() {
        let Some(archive) = server
            .store()
            .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                account_id,
                Collection::AddressBook,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
        else {
            continue;
        };

        match archive.unarchive_untrusted::<AddressBookV2>() {
            Ok(book) => {
                let book = rkyv_deserialize::<_, AddressBookV2>(book).unwrap();
                let new_book = AddressBook {
                    name: book.name,
                    preferences: vec![AddressBookPreferences {
                        account_id,
                        name: book
                            .display_name
                            .unwrap_or_else(|| "Address Book".to_string()),
                        description: book.description,
                        sort_order: book.sort_order,
                    }],
                    subscribers: book.subscribers,
                    dead_properties: book.dead_properties,
                    acls: book.acls,
                    created: book.created,
                    modified: book.modified,
                };

                let mut batch = BatchBuilder::new();
                batch
                    .with_account_id(account_id)
                    .with_collection(Collection::AddressBook)
                    .with_document(document_id)
                    .set(
                        Field::ARCHIVE,
                        Archiver::new(new_book)
                            .serialize()
                            .caused_by(trc::location!())?,
                    );
                server
                    .store()
                    .write(batch.build_all())
                    .await
                    .caused_by(trc::location!())?;
                num_migrated += 1;
            }
            Err(err) => {
                if let Err(err_) = archive.unarchive_untrusted::<AddressBook>() {
                    trc::error!(err_.caused_by(trc::location!()));
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }
    }

    Ok(num_migrated)
}
