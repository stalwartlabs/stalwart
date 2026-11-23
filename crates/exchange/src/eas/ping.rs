/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext,
    folder_sync::is_current,
    response::EasResponse,
    sync::{
        KeyInput, MIN_HEARTBEAT,
        estimate::{MailHierarchy, MailProbes, Prepared, mail_folder, prepare_probe},
        groupware::{GroupwareProbe, GroupwareProbes, GroupwareTarget, Hierarchy},
        max_heartbeat, write_device,
    },
    wait::{ChangeWait, WaitOutcome},
};
use crate::{
    folders::{ExchangeFolders, FolderNode, FolderTree},
    store::{
        FolderRef,
        eas::{EasPing, EasStore, StoredFolder},
    },
};
use ::email::cache::MessageCacheFetch;
use common::Server;
use exchange_proto::{
    common::token::TokenBuf,
    eas::{
        commands::ping::{PingRequest, PingResponse},
        http::Command,
        status::PingStatus,
        types::Class,
        wbxml::Decoder,
    },
};
use utils::map::bitmap::Bitmap;

pub trait EasPingCommand: Sync + Send {
    fn eas_ping(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

struct Watched {
    collection_id: TokenBuf,
    source: Source,
}

#[derive(Clone, Copy)]
enum Source {
    Mailbox(FolderRef),
    Groupware(FolderRef, GroupwareTarget),
    Unwatched,
}

impl EasPingCommand for Server {
    async fn eas_ping(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let has_body = decoder.is_some();
        let request = match decoder {
            Some(decoder) => match PingRequest::parse(decoder, ctx.version) {
                Ok(request) => request,
                Err(err) => {
                    return Ok(EasResponse::status(
                        Command::Ping,
                        err.status(Command::Ping),
                    ));
                }
            },
            None => PingRequest::default(),
        };

        let (device_archive, device_state) = self
            .eas_device_state_seen(ctx.account_id, ctx.device.slot)
            .await?;

        let tree = self
            .exchange_folder_tree(ctx.account_id, ctx.data_types)
            .await?;
        let folders = match &request.folders {
            Some(folders) => {
                let mut stored = Vec::with_capacity(folders.len());
                for folder in folders {
                    match FolderNode::from_eas_collection_id(&folder.id) {
                        Some(node) => stored.push(node.to_stored()),
                        None => return Ok(respond(PingStatus::FOLDER_SYNC_REQUIRED)),
                    }
                }
                stored
            }
            None => match &device_state.ping {
                Some(ping) => ping.folders.clone(),
                None if has_body && request.heartbeat.is_none() => {
                    return Ok(respond(PingStatus::SYNTAX_ERROR));
                }
                None => return Ok(respond(PingStatus::MISSING_PARAMETERS)),
            },
        };
        let heartbeat = match request
            .heartbeat
            .or_else(|| device_state.ping.as_ref().map(|ping| ping.heartbeat))
        {
            Some(heartbeat) => heartbeat,
            None => return Ok(respond(PingStatus::MISSING_PARAMETERS)),
        };
        let max = max_heartbeat(self);
        if !(MIN_HEARTBEAT..=max).contains(&heartbeat) {
            return Ok(limit(
                ctx,
                if heartbeat < MIN_HEARTBEAT {
                    MIN_HEARTBEAT
                } else {
                    max
                },
            ));
        }
        if folders.is_empty() {
            return Ok(respond(PingStatus::MISSING_PARAMETERS));
        }
        if !is_current(&device_state.hierarchy, &tree) {
            return Ok(respond(PingStatus::FOLDER_SYNC_REQUIRED));
        }

        let next = EasPing { heartbeat, folders };
        let watched = watched_folders(ctx, &next.folders, &tree);
        let Some(watched) = watched else {
            return Ok(respond(PingStatus::FOLDER_SYNC_REQUIRED));
        };
        if device_state.ping.as_ref() != Some(&next) {
            let mut state = device_state;
            state.ping = Some(next);
            write_device(self, ctx, device_archive.as_ref(), state).await?;
        }

        let mut wait = ChangeWait::new(self, ctx, heartbeat);
        let mut probes = MailProbes::default();
        let mut groupware = GroupwareProbes::default();
        let mut probed = Vec::new();
        let mut groupware_probed = Vec::new();
        let mut changed = Vec::new();
        for folder in &watched {
            let collection_id = folder.collection_id.as_str();
            let (container, class) = match folder.source {
                Source::Mailbox(mailbox) => (mailbox, Class::Email),
                Source::Groupware(container, target) => (container, target.kind.class()),
                Source::Unwatched => continue,
            };
            let prepared =
                prepare_probe(self, ctx, container, &KeyInput::Current, &[], class).await?;
            match (prepared, folder.source) {
                (Prepared::Ready(probe), Source::Groupware(_, target)) => {
                    groupware.push(GroupwareProbe::new(target, probe));
                    groupware_probed.push(collection_id);
                }
                (Prepared::Ready(probe), _) => {
                    probes.push(probe);
                    probed.push(collection_id);
                }
                (Prepared::NotPrimed, _) => changed.push(collection_id),
                (Prepared::InvalidKey, _) => {}
            }
        }
        let mut seen = None;
        let mut hierarchy = None;
        let mut woken = Bitmap::new();
        loop {
            if !probes.is_empty() {
                let cache = self.get_cached_messages(ctx.account_id).await?;
                let digest = hierarchy.get_or_insert_with(|| MailHierarchy::new(&cache));
                if !digest.matches(&cache) || probes.has_missing_mailbox(&cache) {
                    return Ok(respond(PingStatus::FOLDER_SYNC_REQUIRED));
                }
                if seen != Some(cache.last_change_id) {
                    seen = Some(cache.last_change_id);
                    probes.scan(&cache, |index| {
                        if let Some(collection_id) = probed.get(index) {
                            changed.push(*collection_id);
                        }
                    });
                }
            }
            if !groupware.is_empty()
                && groupware
                    .scan(self, ctx.account_id, woken, |index, count| {
                        if count > 0
                            && let Some(collection_id) = groupware_probed.get(index)
                        {
                            changed.push(*collection_id);
                        }
                    })
                    .await?
                    == Hierarchy::Changed
            {
                return Ok(respond(PingStatus::FOLDER_SYNC_REQUIRED));
            }
            if !changed.is_empty() {
                let response = PingResponse {
                    status: PingStatus::CHANGES,
                    folders: changed,
                    max_folders: None,
                    heartbeat: None,
                };
                return Ok(EasResponse::encode(ctx.version, |encoder| {
                    response.encode(encoder)
                }));
            }
            match wait.next().await {
                WaitOutcome::Changed(types) => woken = types,
                WaitOutcome::Expired => return Ok(respond(PingStatus::EXPIRED)),
            }
        }
    }
}

fn watched_folders(
    ctx: &EasContext<'_>,
    folders: &[StoredFolder],
    tree: &FolderTree,
) -> Option<Vec<Watched>> {
    let mut watched = Vec::with_capacity(folders.len());
    for stored in folders {
        let node = FolderNode::from_eas_stored(*stored).filter(|node| tree.get(*node).is_some())?;
        let source = match (mail_folder(ctx, node), node) {
            (Some(mailbox), _) => Source::Mailbox(mailbox),
            (None, FolderNode::Stored(container)) => GroupwareTarget::resolve(ctx, tree, node)
                .map_or(Source::Unwatched, |target| {
                    Source::Groupware(container, target)
                }),
            (None, FolderNode::Special(_)) => Source::Unwatched,
        };
        watched.push(Watched {
            collection_id: node.eas_collection_id(),
            source,
        });
    }
    Some(watched)
}

fn respond(status: PingStatus) -> EasResponse {
    EasResponse::status(Command::Ping, status.into())
}

fn limit(ctx: &EasContext<'_>, heartbeat: u32) -> EasResponse {
    let response = PingResponse {
        status: PingStatus::INVALID_HEARTBEAT,
        folders: Vec::new(),
        max_folders: None,
        heartbeat: Some(heartbeat),
    };
    EasResponse::encode(ctx.version, |encoder| response.encode(encoder))
}
