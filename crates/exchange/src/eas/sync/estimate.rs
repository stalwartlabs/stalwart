/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    KeyInput, KeyState,
    changes::{ChangeScope, ItemEntry, Watermark},
    email::MailTarget,
    filter_cutoff, resolve_key,
    state::{ClientView, CollectionOptions},
};
use crate::{
    eas::context::{EasContext, EasDataKind},
    folders::FolderNode,
    store::{
        FolderKind, FolderRef,
        eas::{EasFolderState, EasStore},
    },
};
use ahash::AHashMap;
use common::{MailboxCache, MessageStoreCache, Server};
use exchange_proto::eas::{commands::sync::SyncOptions, types::Class};
use std::hash::{DefaultHasher, Hash, Hasher};
use trc::AddContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pending {
    Count(u64),
    NotPrimed,
    InvalidKey,
    InvalidCollection,
}

pub fn mail_folder(ctx: &EasContext<'_>, node: FolderNode) -> Option<FolderRef> {
    match node {
        FolderNode::Stored(
            folder @ FolderRef {
                kind: FolderKind::Mailbox,
                ..
            },
        ) if ctx.allows(EasDataKind::Mail) => Some(folder),
        _ => None,
    }
}

pub enum Prepared {
    Ready(FolderProbe),
    NotPrimed,
    InvalidKey,
}

pub struct FolderProbe {
    pub(super) mailbox_id: u32,
    pub(super) view: ClientView,
    pub(super) watermark: Watermark,
    pub(super) cutoff: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailHierarchy {
    change_id: u64,
    digest: u64,
}

#[derive(Default)]
pub struct MailProbes {
    mailboxes: AHashMap<u32, usize>,
    buckets: Vec<Vec<ItemEntry>>,
    probes: Vec<(usize, FolderProbe)>,
}

impl FolderProbe {
    pub fn count(&self, entries: &[ItemEntry], snapshot: u64) -> u64 {
        ChangeScope {
            current: entries,
            cutoff: self.cutoff,
            snapshot,
            window: usize::MAX,
            bytes: usize::MAX,
            own: None,
        }
        .count(&self.view, self.watermark)
    }
}

impl MailHierarchy {
    pub fn new(cache: &MessageStoreCache) -> Self {
        MailHierarchy {
            change_id: cache.mailboxes.change_id,
            digest: hierarchy_digest(&cache.mailboxes.items),
        }
    }

    pub fn matches(&mut self, cache: &MessageStoreCache) -> bool {
        if cache.mailboxes.change_id == self.change_id {
            return true;
        }
        if hierarchy_digest(&cache.mailboxes.items) != self.digest {
            return false;
        }
        self.change_id = cache.mailboxes.change_id;
        true
    }
}

fn hierarchy_digest(mailboxes: &[MailboxCache]) -> u64 {
    mailboxes.iter().fold(0u64, |digest, mailbox| {
        let mut hasher = DefaultHasher::new();
        (mailbox.document_id, mailbox.parent_id, &*mailbox.name).hash(&mut hasher);
        digest.wrapping_add(hasher.finish())
    })
}

impl MailProbes {
    pub fn push(&mut self, probe: FolderProbe) -> usize {
        let next = self.buckets.len();
        let bucket = *self.mailboxes.entry(probe.mailbox_id).or_insert(next);
        if bucket == next {
            self.buckets.push(Vec::new());
        }
        self.probes.push((bucket, probe));
        self.probes.len() - 1
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    pub fn clear(&mut self) {
        self.mailboxes.clear();
        self.buckets.clear();
        self.probes.clear();
    }

    pub fn has_missing_mailbox(&self, cache: &MessageStoreCache) -> bool {
        self.mailboxes
            .keys()
            .any(|mailbox_id| !cache.mailboxes.index.contains_key(mailbox_id))
    }

    pub fn scan(&mut self, cache: &MessageStoreCache, mut pending: impl FnMut(usize)) {
        if self.probes.is_empty() {
            return;
        }
        for bucket in &mut self.buckets {
            bucket.clear();
        }
        for message in cache.emails.iter() {
            for uid in message.mailboxes() {
                if let Some(bucket) = self
                    .mailboxes
                    .get(&uid.mailbox_id)
                    .and_then(|bucket| self.buckets.get_mut(*bucket))
                {
                    bucket.push(ItemEntry {
                        document_id: message.document_id(),
                        change_id: message.change_id(),
                        received_at: message.received_at(),
                        size: message.size(),
                    });
                }
            }
        }
        for (index, (bucket, probe)) in self.probes.iter().enumerate() {
            if self
                .buckets
                .get(*bucket)
                .is_some_and(|entries| probe.count(entries, cache.last_change_id) > 0)
            {
                pending(index);
            }
        }
    }
}

pub async fn prepare_probe(
    server: &Server,
    ctx: &EasContext<'_>,
    folder: FolderRef,
    key: &KeyInput<'_>,
    options: &[SyncOptions],
    class: Class,
) -> trc::Result<Prepared> {
    let Some(archive) = server
        .eas_folder_state(ctx.account_id, ctx.device.slot, folder)
        .await?
    else {
        return Ok(Prepared::NotPrimed);
    };
    let state = archive
        .deserialize::<EasFolderState>()
        .caused_by(trc::location!())?;
    if state.generation == 0 {
        return Ok(Prepared::NotPrimed);
    }
    let mut view = ClientView::decode(&state.synced).unwrap_or_default();
    let key = match resolve_key(key, Some(&state), &view) {
        Some((KeyState::Current, key)) => key,
        Some((KeyState::Replay, key)) => {
            view.rewind();
            key
        }
        Some((KeyState::Initial, _)) => return Ok(Prepared::NotPrimed),
        None => return Ok(Prepared::InvalidKey),
    };

    let stored_options;
    let options = if options.is_empty() {
        stored_options = CollectionOptions::decode(&state.options).unwrap_or_default();
        stored_options.options.as_slice()
    } else {
        options
    };
    let class_options = options
        .iter()
        .find(|options| options.class.is_none_or(|item_class| item_class == class));
    Ok(Prepared::Ready(FolderProbe {
        mailbox_id: folder.id,
        view,
        watermark: Watermark {
            change_id: key.change_id,
            page: key.page,
        },
        cutoff: filter_cutoff(class_options),
    }))
}

pub async fn pending_changes(
    server: &Server,
    ctx: &EasContext<'_>,
    cache: &MessageStoreCache,
    folder: FolderRef,
    key: KeyInput<'_>,
    options: &[SyncOptions],
) -> trc::Result<Pending> {
    if !cache.mailboxes.index.contains_key(&folder.id) {
        return Ok(Pending::InvalidCollection);
    }
    Ok(
        match prepare_probe(server, ctx, folder, &key, options, Class::Email).await? {
            Prepared::Ready(probe) => {
                let target = MailTarget {
                    mailbox_id: folder.id,
                    trash_id: None,
                    deletes_as_moves: true,
                };
                Pending::Count(probe.count(&target.entries(cache), cache.last_change_id))
            }
            Prepared::NotPrimed => Pending::NotPrimed,
            Prepared::InvalidKey => Pending::InvalidKey,
        },
    )
}
