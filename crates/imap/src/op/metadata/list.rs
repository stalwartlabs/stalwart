/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    READ_RIGHTS, SPECIAL_USE_ENTRY, mailbox_rights, owned_entries, reads_private_container,
    select::{EntrySource, PrivateEntries, SelectOptions, select_entries},
    special_use_value,
};
use crate::{core::SessionData, op::ImapContext};
use common::{
    MailboxCache, auth::AccessToken, network::SessionStream, storage::metadata::MetadataContainers,
};
use imap_proto::protocol::{
    list::ListItem,
    metadata::{Depth, Entry, Scope},
};
use registry::schema::enums::Permission;
use store::roaring::RoaringBitmap;
use types::{collection::Collection, metadata::MetadataKinds, special_use::SpecialUse};

#[derive(Debug, Clone, Copy)]
pub(crate) struct ListMetadataTarget {
    item: usize,
    account_id: u32,
    mailbox_id: u32,
    kinds: MetadataKinds,
    role: SpecialUse,
}

impl ListMetadataTarget {
    pub(crate) fn new(
        item: usize,
        account_id: u32,
        mailbox_id: u32,
        mailbox: &MailboxCache,
        access_token: &AccessToken,
    ) -> Option<Self> {
        let rights = mailbox_rights(access_token, account_id, mailbox);
        READ_RIGHTS
            .iter()
            .all(|right| rights.contains(*right))
            .then_some(ListMetadataTarget {
                item,
                account_id,
                mailbox_id,
                kinds: mailbox.metadata_kinds,
                role: mailbox.role,
            })
    }
}

impl<T: SessionStream> SessionData<T> {
    pub(crate) async fn list_metadata(
        &self,
        tag: &str,
        requested: &[Entry<'static>],
        targets: &[ListMetadataTarget],
        list_items: &mut [ListItem],
        access_token: &AccessToken,
    ) -> trc::Result<()> {
        let viewer = self
            .server
            .metadata_viewer(access_token, Permission::ImapMetadataPrivate);
        let has_shared = requested.iter().any(|entry| entry.scope == Scope::Shared);
        let options = SelectOptions {
            depth: Depth::Zero,
            max_size: None,
        };
        let has_private = viewer.is_some() && reads_private_container(requested, options.depth);

        for account_targets in targets.chunk_by(|a, b| a.account_id == b.account_id) {
            let Some(account_id) = account_targets.first().map(|target| target.account_id) else {
                continue;
            };

            let flagged = account_targets
                .iter()
                .filter(|target| has_shared && target.kinds.contains(MetadataKinds::IMAP))
                .map(|target| target.mailbox_id)
                .collect::<RoaringBitmap>();
            let shared = self
                .server
                .load_metadata_containers(account_id, Collection::Mailbox, &flagged)
                .await
                .imap_ctx(tag, trc::location!())?;

            let private = match viewer.filter(|_| has_private) {
                Some(viewer)
                    if self
                        .server
                        .metadata_viewer_state(viewer, account_id, Collection::Mailbox)
                        .await
                        .imap_ctx(tag, trc::location!())?
                        .containers
                        > 0 =>
                {
                    let listed = account_targets
                        .iter()
                        .map(|target| target.mailbox_id)
                        .collect::<RoaringBitmap>();
                    self.server
                        .load_private_metadata_containers(
                            account_id,
                            viewer.account_id(),
                            Collection::Mailbox,
                            &listed,
                        )
                        .await
                        .imap_ctx(tag, trc::location!())?
                }
                _ => MetadataContainers::default(),
            };

            for target in account_targets {
                let shared_source = shared
                    .get(target.mailbox_id)
                    .map(|container| EntrySource::new(container.view().imap()))
                    .unwrap_or_default();
                let mut private_source = private
                    .get(target.mailbox_id)
                    .map(|container| EntrySource::new(container.view().imap()))
                    .unwrap_or_default();
                if let Some(value) = special_use_value(target.role) {
                    private_source.insert(SPECIAL_USE_ENTRY, value);
                }
                let private_entries = match viewer {
                    Some(_) => PrivateEntries::All(&private_source),
                    None => PrivateEntries::SpecialUse(&private_source),
                };
                let selection = select_entries(requested, options, &shared_source, private_entries);
                if let Some(item) = list_items.get_mut(target.item) {
                    item.metadata = owned_entries(selection.entries);
                }
            }
        }

        Ok(())
    }
}
