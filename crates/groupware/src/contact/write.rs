/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{ArchivedContactCard, ArchivedContactCardContent, ContactCard, ContactCardContent};
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
use crate::SizeWriter;
// SPDX-SnippetEnd
use crate::DestroyArchive;
use calcard::vcard::{VCard, VCardProperty, VCardValue};
use common::{DavName, GroupwareResources, Server, auth::AccessToken};
use registry::schema::enums::StorageQuota;
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder},
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
    field::ContactField,
};

const URN_UUID_PREFIX: &str = "urn:uuid:";
const UUID_GROUP_LENGTHS: [usize; 5] = [8, 4, 4, 4, 12];

pub struct CardWriter<'x> {
    pub server: &'x Server,
    pub access_token: &'x AccessToken,
    pub account_id: u32,
    pub resources: &'x GroupwareResources,
}

#[derive(Debug)]
pub enum CardWriteError {
    NotFound,
    Forbidden,
    UidChanged(Option<String>),
    UidConflict { document_id: u32, href: String },
    Store(trc::Error),
}

pub struct StoredCard {
    document_id: u32,
    addressbook_id: u32,
    card: Archive<ArchiveBytes>,
    content: Archive<ArchiveBytes>,
}

pub struct NewCard {
    addressbook_id: u32,
}

pub struct CardCreate {
    pub name: String,
    pub vcard: VCard,
    pub size: Option<usize>,
}

pub struct CardDeletion {
    document_id: u32,
    addressbook_id: u32,
    card: Archive<ArchiveBytes>,
}

pub struct WrittenCard {
    pub document_id: u32,
    pub etag: String,
    pub change_id: Option<u64>,
    pub serves_submitted: bool,
}

pub type CardWriteResult<T> = Result<T, CardWriteError>;

impl CardWriter<'_> {
    fn assert_access(&self, addressbook_id: u32, acl: Acl) -> CardWriteResult<()> {
        if self.access_token.is_member(self.account_id)
            || self
                .resources
                .has_access_to_container(self.access_token, addressbook_id, acl)
        {
            Ok(())
        } else {
            Err(CardWriteError::Forbidden)
        }
    }

    pub async fn prepare_update(
        &self,
        addressbook_id: u32,
        document_id: u32,
    ) -> CardWriteResult<StoredCard> {
        self.assert_access(addressbook_id, Acl::ModifyItems)?;
        let (card, content) = self
            .server
            .archive_and_field(
                self.account_id,
                Collection::ContactCard,
                document_id,
                ContactField::Content.field(),
            )
            .await
            .caused_by(trc::location!())?;
        Ok(StoredCard {
            document_id,
            addressbook_id,
            card: card.ok_or(CardWriteError::NotFound)?,
            content: content.ok_or(CardWriteError::NotFound)?,
        })
    }

    pub async fn update(
        &self,
        stored: StoredCard,
        mut vcard: VCard,
    ) -> CardWriteResult<WrittenCard> {
        let server = self.server;
        let account_id = self.account_id;
        let document_id = stored.document_id;
        let card = stored.card()?;
        let content = stored.content()?;

        let restored_uid = match (
            content.inner.card.uid().filter(|uid| !uid.is_empty()),
            vcard.uid().filter(|uid| !uid.is_empty()),
        ) {
            (Some(stored_uid), Some(uid)) if is_same_uid(stored_uid, uid) => {
                (stored_uid != uid).then_some(stored_uid)
            }
            (None, uid) => {
                assert_unique_uid(self.resources, stored.addressbook_id, uid)?;
                None
            }
            _ => {
                return Err(CardWriteError::UidChanged(
                    self.resources
                        .format_resource_path_by_parent(document_id, stored.addressbook_id),
                ));
            }
        };
        if let Some(stored_uid) = restored_uid
            && let Some(value) = vcard
                .entries
                .iter_mut()
                .find(|entry| entry.name == VCardProperty::Uid)
                .and_then(|entry| entry.values.first_mut())
        {
            *value = VCardValue::Text(stored_uid.to_string());
        }

        let new_card = card
            .deserialize::<ContactCard>()
            .caused_by(trc::location!())?;
        let new_content = ContactCardContent { card: vcard };

        let account = server.account(account_id).await?;
        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        let extra_bytes =
            (SizeWriter::vcard(&new_content.card, server.core.groupware.vcard_version) as u64)
                .saturating_sub(u32::from(card.inner.size) as u64);
        #[cfg(feature = "enterprise")]
        if extra_bytes > 0 {
            server
                .has_available_tenant_quota(&account, extra_bytes)
                .await?;
        }
        // SPDX-SnippetEnd

        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        server.limit_disk_quota(&mut batch, &account);
        let etag = new_card
            .update_full(
                new_content,
                server.core.groupware.vcard_version,
                self.access_token.changed_by(),
                card,
                content.inner,
                account_id,
                document_id,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        let change_id = server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?
            .change_id(account_id, SyncCollection::AddressBook);

        Ok(WrittenCard {
            document_id,
            etag,
            change_id,
            serves_submitted: restored_uid.is_none(),
        })
    }

    pub fn prepare_create(&self, addressbook_id: u32) -> CardWriteResult<NewCard> {
        self.assert_access(addressbook_id, Acl::AddItems)?;
        Ok(NewCard { addressbook_id })
    }

    pub async fn create(&self, new: NewCard, input: CardCreate) -> CardWriteResult<WrittenCard> {
        let server = self.server;
        let account_id = self.account_id;
        let resources = self.resources;

        assert_unique_uid(resources, new.addressbook_id, input.vcard.uid())?;

        let account = server.account(account_id).await?;
        server.assert_object_quota(&account, StorageQuota::MaxContactCards, 1, || {
            resources.resources.count(false)
        })?;

        // SPDX-SnippetBegin
        // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
        // SPDX-License-Identifier: LicenseRef-SEL
        #[cfg(feature = "enterprise")]
        {
            let size = input.size.unwrap_or_else(|| {
                SizeWriter::vcard(&input.vcard, server.core.groupware.vcard_version)
            });
            if size != 0 {
                server
                    .has_available_tenant_quota(&account, size as u64)
                    .await?;
            }
        }
        // SPDX-SnippetEnd

        let card = ContactCard {
            names: vec![DavName {
                name: input.name,
                parent_id: new.addressbook_id,
            }],
            ..Default::default()
        };
        let content = ContactCardContent { card: input.vcard };

        let mut batch = BatchBuilder::new();
        batch.with_account_id(account_id);
        server.limit_disk_quota(&mut batch, &account);
        let slot = batch.reserve_document_id(account_id, Collection::ContactCard);
        let etag = card
            .insert(
                content,
                server.core.groupware.vcard_version,
                self.access_token.changed_by(),
                account_id,
                slot,
                None,
                &mut batch,
            )
            .caused_by(trc::location!())?;
        let assigned_ids = server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;

        Ok(WrittenCard {
            document_id: assigned_ids.slot(slot),
            etag,
            change_id: assigned_ids.change_id(account_id, SyncCollection::AddressBook),
            serves_submitted: true,
        })
    }

    pub async fn prepare_delete(
        &self,
        addressbook_id: u32,
        document_id: u32,
    ) -> CardWriteResult<CardDeletion> {
        self.assert_access(addressbook_id, Acl::RemoveItems)?;
        let card = self
            .server
            .store()
            .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                self.account_id,
                Collection::ContactCard,
                document_id,
            ))
            .await
            .caused_by(trc::location!())?
            .ok_or(CardWriteError::NotFound)?;
        Ok(CardDeletion {
            document_id,
            addressbook_id,
            card,
        })
    }

    pub async fn delete(
        &self,
        deletion: CardDeletion,
        delete_path: Option<String>,
    ) -> CardWriteResult<()> {
        let mut batch = BatchBuilder::new();
        DestroyArchive(deletion.card()?)
            .delete(
                self.server,
                self.access_token.changed_by(),
                self.account_id,
                deletion.document_id,
                deletion.addressbook_id,
                delete_path,
                &mut batch,
            )
            .await
            .caused_by(trc::location!())?;
        self.server
            .commit_batch(batch)
            .await
            .caused_by(trc::location!())?;
        Ok(())
    }
}

impl StoredCard {
    pub fn document_id(&self) -> u32 {
        self.document_id
    }

    pub fn card(&self) -> trc::Result<Archive<&ArchivedContactCard>> {
        self.card.to_unarchived::<ContactCard>()
    }

    pub fn content(&self) -> trc::Result<Archive<&ArchivedContactCardContent>> {
        self.content.to_unarchived::<ContactCardContent>()
    }
}

impl CardDeletion {
    pub fn card(&self) -> trc::Result<Archive<&ArchivedContactCard>> {
        self.card.to_unarchived::<ContactCard>()
    }
}

impl From<trc::Error> for CardWriteError {
    fn from(err: trc::Error) -> Self {
        CardWriteError::Store(err)
    }
}

pub fn assert_unique_uid(
    resources: &GroupwareResources,
    addressbook_id: u32,
    uid: Option<&str>,
) -> CardWriteResult<()> {
    let Some(uid) = uid else {
        return Ok(());
    };

    if let Some(path) = resources.children_with_uid(addressbook_id, uid).next() {
        return Err(CardWriteError::UidConflict {
            document_id: path.document_id(),
            href: resources.format_resource(path),
        });
    }

    Ok(())
}

pub fn is_same_uid(uid: &str, other: &str) -> bool {
    uid == other
        || matches!(
            (uuid_of(uid), uuid_of(other)),
            (Some(uuid), Some(other_uuid)) if uuid.eq_ignore_ascii_case(other_uuid)
        )
}

fn uuid_of(uid: &str) -> Option<&str> {
    let uuid = uid
        .split_at_checked(URN_UUID_PREFIX.len())
        .filter(|(prefix, _)| prefix.eq_ignore_ascii_case(URN_UUID_PREFIX))
        .map_or(uid, |(_, uuid)| uuid);
    let mut groups = uuid.split('-');

    (UUID_GROUP_LENGTHS.iter().all(|&len| {
        groups
            .next()
            .is_some_and(|group| group.len() == len && group.bytes().all(|b| b.is_ascii_hexdigit()))
    }) && groups.next().is_none())
    .then_some(uuid)
}
