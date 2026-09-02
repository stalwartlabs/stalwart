/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    AddressBook, ArchivedAddressBook, ArchivedContactCard, ArchivedContactCardContent, ContactCard,
    ContactCardContent,
};
use crate::DestroyArchive;
use calcard::vcard::VCardVersion;
use common::{
    Server,
    auth::AccountTenantIds,
    storage::index::{GroupwareWrite, ObjectIndexBuilder, SplitCurrent, SplitUpdate},
};
use store::{
    ValueKey,
    write::{Archive, ArchiveBytes, BatchBuilder, PendingId, Slot, now},
};
use trc::AddContext;
use types::{
    collection::{Collection, VanishedCollection},
    field::ContactField,
};

impl ContactCard {
    #[allow(clippy::too_many_arguments)]
    pub fn update_full(
        self,
        content: ContactCardContent,
        version: VCardVersion,
        changed_by: AccountTenantIds,
        card: Archive<&ArchivedContactCard>,
        card_content: &ArchivedContactCardContent,
        account_id: u32,
        document_id: u32,
        parent_id: Option<Slot>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<String> {
        let mut new_card = self;
        new_card.modified = now() as i64;

        let update = SplitUpdate::full(card, card_content, new_card, content, version)?;
        let etag = update.etag();

        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard)
            .with_document(document_id)
            .custom(update.into_builder(changed_by, parent_id))?
            .commit_point();

        Ok(etag)
    }

    pub fn update_meta(
        self,
        changed_by: AccountTenantIds,
        card: Archive<&ArchivedContactCard>,
        account_id: u32,
        document_id: u32,
        parent_id: Option<Slot>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<String> {
        let mut new_card = self;
        new_card.modified = now() as i64;

        let update = SplitUpdate::meta_only(card, new_card);
        let etag = update.etag();

        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard)
            .with_document(document_id)
            .custom(update.into_builder(changed_by, parent_id))?
            .commit_point();

        Ok(etag)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        self,
        content: ContactCardContent,
        version: VCardVersion,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: impl Into<PendingId>,
        parent_id: Option<Slot>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<String> {
        // Build card
        let mut card = self;
        let now = now() as i64;
        card.modified = now;
        card.created = now;

        let changes = GroupwareWrite::full(card, content, version)?;
        let etag = format!("\"{}\"", changes.meta().etag);

        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard)
            .with_pending_document(document_id.into())
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(changes)
                    .with_changed_by(changed_by)
                    .with_pending_id_opt(parent_id),
            )?
            .commit_point();

        Ok(etag)
    }
}

impl AddressBook {
    pub fn insert(
        self,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: impl Into<PendingId>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<&mut BatchBuilder> {
        // Build address book
        let mut book = self;
        let now = now() as i64;
        book.modified = now;
        book.created = now;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::AddressBook)
            .with_pending_document(document_id.into())
            .custom(
                ObjectIndexBuilder::<(), _>::new()
                    .with_changes(book)
                    .with_changed_by(changed_by),
            )
            .map(|b| b.commit_point())
    }

    pub fn update<'x>(
        self,
        changed_by: AccountTenantIds,
        book: Archive<&ArchivedAddressBook>,
        account_id: u32,
        document_id: u32,
        batch: &'x mut BatchBuilder,
    ) -> trc::Result<&'x mut BatchBuilder> {
        // Build address book
        let mut new_book = self;
        new_book.modified = now() as i64;

        // Prepare write batch
        batch
            .with_account_id(account_id)
            .with_collection(Collection::AddressBook)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::new()
                    .with_current(book)
                    .with_changes(new_book)
                    .with_changed_by(changed_by),
            )
            .map(|b| b.commit_point())
    }
}

impl DestroyArchive<Archive<&ArchivedAddressBook>> {
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_with_cards(
        self,
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: u32,
        children_ids: Vec<u32>,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        // Process deletions
        let addressbook_id = document_id;
        for document_id in children_ids {
            if let Some(card_) = server
                .store()
                .get_value::<Archive<ArchiveBytes>>(ValueKey::archive(
                    account_id,
                    Collection::ContactCard,
                    document_id,
                ))
                .await?
            {
                DestroyArchive(
                    card_
                        .to_unarchived::<ContactCard>()
                        .caused_by(trc::location!())?,
                )
                .delete(
                    server,
                    changed_by,
                    account_id,
                    document_id,
                    addressbook_id,
                    None,
                    batch,
                )
                .await?;
            }
        }

        self.delete(changed_by, account_id, document_id, delete_path, batch)
    }

    pub fn delete(
        self,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let book = self.0;
        // Delete addressbook
        batch
            .with_account_id(account_id)
            .with_collection(Collection::AddressBook)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_changed_by(changed_by)
                    .with_current(book),
            )
            .caused_by(trc::location!())?;

        if let Some(delete_path) = delete_path {
            batch.log_vanished_item(VanishedCollection::AddressBook, delete_path);
        }

        batch.commit_point();

        Ok(())
    }
}

impl DestroyArchive<Archive<&ArchivedContactCard>> {
    #[allow(clippy::too_many_arguments)]
    pub async fn delete(
        self,
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: u32,
        addressbook_id: u32,
        delete_path: Option<String>,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let card = self.0;
        if let Some(delete_idx) = card
            .inner
            .names
            .iter()
            .position(|name| name.parent_id == addressbook_id)
        {
            batch
                .with_account_id(account_id)
                .with_collection(Collection::ContactCard);

            if card.inner.names.len() > 1 {
                // Unlink addressbook id from card
                let mut new_card = card
                    .deserialize::<ContactCard>()
                    .caused_by(trc::location!())?;
                new_card.names.swap_remove(delete_idx);
                let update = SplitUpdate::meta_only(card, new_card);
                batch
                    .with_document(document_id)
                    .custom(update.into_builder(changed_by, None))
                    .caused_by(trc::location!())?;
            } else {
                // Delete card
                let content_ = card_content(server, account_id, document_id).await?;
                batch
                    .with_document(document_id)
                    .custom(
                        ObjectIndexBuilder::<_, ()>::new()
                            .with_changed_by(changed_by)
                            .with_current(card_current(card, content_.as_ref())?),
                    )
                    .caused_by(trc::location!())?;
            }

            if let Some(delete_path) = delete_path {
                batch.log_vanished_item(VanishedCollection::AddressBook, delete_path);
            }

            batch.commit_point();
        }

        Ok(())
    }

    pub async fn delete_all(
        self,
        server: &Server,
        changed_by: AccountTenantIds,
        account_id: u32,
        document_id: u32,
        batch: &mut BatchBuilder,
    ) -> trc::Result<()> {
        let content_ = card_content(server, account_id, document_id).await?;

        batch
            .with_account_id(account_id)
            .with_collection(Collection::ContactCard)
            .with_document(document_id)
            .custom(
                ObjectIndexBuilder::<_, ()>::new()
                    .with_changed_by(changed_by)
                    .with_current(card_current(self.0, content_.as_ref())?),
            )
            .caused_by(trc::location!())
            .map(|b| {
                b.commit_point();
            })
    }
}

async fn card_content(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<Archive<ArchiveBytes>>> {
    server
        .store()
        .get_value::<Archive<ArchiveBytes>>(ValueKey::property(
            account_id,
            Collection::ContactCard,
            document_id,
            ContactField::Content,
        ))
        .await
        .caused_by(trc::location!())
}

fn card_current<'x>(
    card: Archive<&'x ArchivedContactCard>,
    content: Option<&'x Archive<ArchiveBytes>>,
) -> trc::Result<SplitCurrent<'x, ArchivedContactCard>> {
    match content {
        Some(content) => content
            .to_unarchived::<ContactCardContent>()
            .caused_by(trc::location!())
            .map(|content| SplitCurrent::Full {
                meta: card,
                content: content.inner,
            }),
        None => Ok(SplitCurrent::MetaOnly(card)),
    }
}
