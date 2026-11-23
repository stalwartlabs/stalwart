/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EasContext,
    response::EasResponse,
    sync::{
        KeyInput,
        estimate::{Pending, Prepared, mail_folder, pending_changes, prepare_probe},
        groupware::{GroupwareProbe, GroupwareProbes, GroupwareTarget},
    },
};
use crate::folders::{ExchangeFolders, FolderNode};
use ::email::cache::MessageCacheFetch;
use common::Server;
use exchange_proto::eas::{
    commands::{
        SyncKeyStr,
        get_item_estimate::{
            EstimateCollection, EstimateResult, GetItemEstimateRequest, GetItemEstimateResponse,
        },
        sync::options::FilterFit,
    },
    http::Command,
    status::{CommonStatus, GetItemEstimateStatus},
    types::Class,
    wbxml::Decoder,
};
use utils::map::bitmap::Bitmap;

pub trait EasGetItemEstimate: Sync + Send {
    fn eas_get_item_estimate(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> impl Future<Output = trc::Result<EasResponse>> + Send;
}

impl EasGetItemEstimate for Server {
    async fn eas_get_item_estimate(
        &self,
        ctx: &EasContext<'_>,
        decoder: Option<&mut Decoder<'_>>,
    ) -> trc::Result<EasResponse> {
        let Some(decoder) = decoder else {
            return Ok(EasResponse::status(
                Command::GetItemEstimate,
                CommonStatus::INVALID_XML.into(),
            ));
        };
        let request = match GetItemEstimateRequest::parse(decoder, ctx.version) {
            Ok(request) => request,
            Err(err) => {
                return Ok(EasResponse::status(
                    Command::GetItemEstimate,
                    err.status(Command::GetItemEstimate),
                ));
            }
        };

        if request
            .collections
            .iter()
            .any(EstimateCollection::mixes_classes)
        {
            return Ok(EasResponse::status(
                Command::GetItemEstimate,
                GetItemEstimateStatus::INVALID_SYNC_KEY.into(),
            ));
        }

        let mut cache = None;
        let mut tree = None;
        let mut responses = Vec::with_capacity(request.collections.len());
        let mut groupware = GroupwareProbes::default();
        let mut groupware_slots = Vec::new();
        for collection in &request.collections {
            let collection_id = collection.collection_id.as_ref();
            let node = FolderNode::from_eas_collection_id(collection_id);
            let mail = node.and_then(|node| mail_folder(ctx, node));
            let target = match (mail, node) {
                (None, Some(node @ FolderNode::Stored(folder))) => {
                    let tree = match &tree {
                        Some(tree) => tree,
                        None => tree.insert(
                            self.exchange_folder_tree(ctx.account_id, ctx.data_types)
                                .await?,
                        ),
                    };
                    GroupwareTarget::resolve(ctx, tree, node).map(|target| (folder, target))
                }
                _ => None,
            };
            let class = match (&mail, &target) {
                (Some(_), _)
                    if collection
                        .options
                        .iter()
                        .any(|options| options.class == Some(Class::Notes)) =>
                {
                    Some(Class::Notes)
                }
                (Some(_), _) => Some(Class::Email),
                (None, Some((_, target))) => Some(target.kind.class()),
                (None, None) => None,
            };
            match class.map(|class| collection.filter_fit(class)) {
                Some(FilterFit::OutOfClass) => {
                    return Ok(EasResponse::status(
                        Command::GetItemEstimate,
                        CommonStatus::SERVER_ERROR.into(),
                    ));
                }
                Some(FilterFit::Invalid) => {
                    responses.push(EstimateResult {
                        status: CommonStatus::INVALID_XML.into(),
                        collection_id: Some(collection_id),
                        estimate: None,
                    });
                    continue;
                }
                Some(FilterFit::Fits) | None => {}
            }
            if collection.conversation_mode.is_some()
                && collection.sync_key.is_some()
                && class.is_some_and(|class| class != Class::Email)
            {
                return Ok(EasResponse::status(
                    Command::GetItemEstimate,
                    GetItemEstimateStatus::INVALID_SYNC_KEY.into(),
                ));
            }
            let sync_key = match &collection.sync_key {
                Some(sync_key) => sync_key,
                None => {
                    responses.push(EstimateResult {
                        status: CommonStatus::INVALID_XML.into(),
                        collection_id: None,
                        estimate: None,
                    });
                    continue;
                }
            };
            let primed = sync_key.0 != SyncKeyStr::INITIAL;
            let pending = match (mail, target) {
                (Some(_), _) | (None, Some(_)) if !primed => Pending::NotPrimed,
                (Some(folder), _) => {
                    let cache = match &cache {
                        Some(cache) => cache,
                        None => cache.insert(self.get_cached_messages(ctx.account_id).await?),
                    };
                    pending_changes(
                        self,
                        ctx,
                        cache,
                        folder,
                        KeyInput::Sent(sync_key.as_str()),
                        &collection.options,
                    )
                    .await?
                }
                (None, Some((folder, target))) => match prepare_probe(
                    self,
                    ctx,
                    folder,
                    &KeyInput::Sent(sync_key.as_str()),
                    &collection.options,
                    target.kind.class(),
                )
                .await?
                {
                    Prepared::Ready(probe) => {
                        groupware.push(GroupwareProbe::new(target, probe));
                        groupware_slots.push(responses.len());
                        Pending::InvalidCollection
                    }
                    Prepared::NotPrimed => Pending::NotPrimed,
                    Prepared::InvalidKey => Pending::InvalidKey,
                },
                (None, None) => Pending::InvalidCollection,
            };
            let (status, estimate) = match pending {
                Pending::Count(count) => (
                    GetItemEstimateStatus::SUCCESS,
                    Some(u32::try_from(count).unwrap_or(u32::MAX)),
                ),
                Pending::NotPrimed => (GetItemEstimateStatus::NOT_PRIMED, None),
                Pending::InvalidKey => (GetItemEstimateStatus::INVALID_SYNC_KEY, None),
                Pending::InvalidCollection => (GetItemEstimateStatus::INVALID_COLLECTION, None),
            };
            responses.push(EstimateResult {
                status,
                collection_id: Some(collection_id),
                estimate,
            });
        }

        if !groupware.is_empty() {
            groupware
                .scan(self, ctx.account_id, Bitmap::new(), |index, count| {
                    if let Some(response) = groupware_slots
                        .get(index)
                        .and_then(|slot| responses.get_mut(*slot))
                    {
                        response.status = GetItemEstimateStatus::SUCCESS;
                        response.estimate = Some(u32::try_from(count).unwrap_or(u32::MAX));
                    }
                })
                .await?;
        }

        let response = GetItemEstimateResponse {
            status: None,
            responses,
        };
        Ok(EasResponse::encode(ctx.version, |encoder| {
            response.encode(encoder)
        }))
    }
}
