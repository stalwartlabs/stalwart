/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    api::query::QueryResponseBuilder,
    blob::download::BlobDownload,
    registry::{
        mapping::{RegistryGetResponse, RegistryQueryResponse, RegistrySetResponse},
        query::RegistryQueryFilters,
    },
};
use jmap_proto::{error::set::SetError, types::state::State};
use jmap_tools::JsonPointer;
use mail_parser::{MessageParser, parsers::fields::thread::thread_name};
use registry::{
    jmap::{IntoValue, JsonPointerPatch, RegistryJsonPatch},
    schema::{
        enums::Permission,
        prelude::{ObjectType, Property},
        structs::SpamTrainingSample,
    },
    types::{EnumImpl, ObjectImpl, datetime::UTCDateTime, id::ObjectId},
};
use std::str::FromStr;
use store::{
    SerializeInfallible, ValueKey,
    registry::RegistryQuery,
    write::{BatchBuilder, BlobLink, BlobOp, RegistryClass, ValueClass, now},
};
use trc::AddContext;
use types::{blob::BlobClass, id::Id};

pub(crate) async fn spam_sample_set(
    mut set: RegistrySetResponse<'_>,
) -> trc::Result<RegistrySetResponse<'_>> {
    // Spam samples cannot be modified
    set.fail_all_update("Spam training samples cannot be modified.");

    let mut batch = BatchBuilder::new();
    let object_id = set.object_type.to_id();

    // Process samples to create
    let hold_samples_for = set
        .server
        .core
        .spam
        .classifier
        .as_ref()
        .map(|config| config.hold_samples_for);
    let now = now();
    'outer: for (id, value) in set.create.drain() {
        let mut sample = SpamTrainingSample::default();
        let Some(expires_at) = hold_samples_for.map(|d| now + d) else {
            set.response.not_created.append(
                id,
                SetError::forbidden()
                    .with_description("Spam classifier is not configured on the server"),
            );
            continue;
        };
        if let Err(err) = sample.patch(
            JsonPointerPatch::new(&JsonPointer::new(vec![]))
                .with_create(true)
                .with_can_set_account(!set.is_account_filtered),
            value,
        ) {
            set.response.not_created.append(id, err.into());
            continue 'outer;
        };

        if sample.blob_id.hash.is_empty() {
            set.response.not_created.append(
                id,
                SetError::invalid_properties()
                    .with_property(Property::BlobId)
                    .with_description("blobId is required"),
            );
            continue;
        }

        let Some(bytes) = set
            .server
            .blob_download(&sample.blob_id, set.access_token)
            .await?
        else {
            set.response.not_created.append(
                id,
                SetError::invalid_properties()
                    .with_property(Property::BlobId)
                    .with_description("blobId does not exist or is not accessible"),
            );
            continue;
        };

        if bytes.len() > set.server.core.email.mail_max_size {
            set.response.not_created.append(
                id,
                SetError::invalid_properties()
                    .with_property(Property::BlobId)
                    .with_description(format!(
                        "blob size exceeds maximum of {} bytes",
                        set.server.core.email.mail_max_size
                    )),
            );
            continue;
        }

        let Some(message) = MessageParser::new().parse(&bytes) else {
            set.response.not_created.append(
                id,
                SetError::invalid_properties()
                    .with_property(Property::BlobId)
                    .with_description("Blob content is not a valid email message"),
            );
            continue;
        };

        let subject = message.subject().map(thread_name).unwrap_or_default();
        let from = message
            .from()
            .and_then(|from| from.first().and_then(|addr| addr.address()))
            .unwrap_or_default();
        if subject.is_empty() && from.is_empty() {
            set.response.not_created.append(
                id,
                SetError::invalid_properties()
                    .with_property(Property::BlobId)
                    .with_description("Email message must have a subject or a from header"),
            );
            continue;
        }

        sample.subject = subject.to_string();
        sample.from = from.to_lowercase();
        sample.expires_at = UTCDateTime::from_timestamp(expires_at as i64);
        if set.is_account_filtered {
            sample.account_id = Some(set.account_id.into());
        }

        // Write sample to store
        let item_id = set.server.registry().assign_id();
        batch
            .set(
                BlobOp::Link {
                    hash: sample.blob_id.hash.clone(),
                    to: BlobLink::Temporary { until: expires_at },
                },
                ObjectId::new(ObjectType::SpamTrainingSample, item_id.into()).serialize(),
            )
            .set(
                ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: sample
                        .account_id
                        .map(|id| id.id())
                        .unwrap_or(u32::MAX as u64)
                        .serialize(),
                }),
                vec![],
            )
            .set(
                ValueClass::Registry(RegistryClass::Item { object_id, item_id }),
                sample.to_pickled_vec(),
            );

        set.response.created(id, item_id);
    }

    // Process samples to destroy
    for id in set.destroy.drain(..) {
        let item_id = id.id();

        if let Some(sample) = set
            .server
            .store()
            .get_value::<SpamTrainingSample>(ValueKey::from(ValueClass::Registry(
                RegistryClass::Item {
                    object_id,
                    item_id: id.id(),
                },
            )))
            .await?
            .filter(|sample| {
                !set.is_account_filtered
                    || sample
                        .account_id
                        .is_some_and(|account_id| account_id.document_id() == set.account_id)
            })
        {
            let account_id = sample
                .account_id
                .map(|id| id.document_id())
                .unwrap_or(u32::MAX);

            batch
                .with_account_id(account_id)
                .clear(BlobOp::Link {
                    hash: sample.blob_id.hash,
                    to: BlobLink::Temporary {
                        until: sample.expires_at.timestamp() as u64,
                    },
                })
                .clear(ValueClass::Registry(RegistryClass::Item {
                    object_id,
                    item_id,
                }))
                .clear(ValueClass::Registry(RegistryClass::Index {
                    index_id: Property::AccountId.to_id(),
                    object_id,
                    item_id,
                    key: (account_id as u64).serialize(),
                }))
                .commit_point();

            set.response.destroyed.push(id);
        } else {
            set.response.not_destroyed.append(id, SetError::not_found());
        }
    }

    if !batch.is_empty() {
        set.server
            .store()
            .write(batch.build_all())
            .await
            .caused_by(trc::location!())?;
    }

    Ok(set)
}

pub(crate) async fn spam_sample_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let object_id = get.object_type.to_id();
    let ids = if let Some(ids) = get.ids.take() {
        ids
    } else {
        let query = if !get.is_account_filtered {
            RegistryQuery::new(get.object_type).greater_than_or_equal(Property::AccountId, 0u64)
        } else {
            RegistryQuery::new(get.object_type).with_account(get.account_id)
        }
        .with_limit(get.server.core.jmap.get_max_objects);

        get.server.registry().query::<Vec<Id>>(query).await?
    };

    for id in ids {
        if let Some(mut sample) = get
            .server
            .store()
            .get_value::<SpamTrainingSample>(ValueKey::from(ValueClass::Registry(
                RegistryClass::Item {
                    object_id,
                    item_id: id.id(),
                },
            )))
            .await?
            .filter(|sample| {
                !get.is_account_filtered
                    || sample
                        .account_id
                        .is_some_and(|account_id| account_id.document_id() == get.account_id)
            })
        {
            if get.is_account_filtered {
                sample.blob_id.class = BlobClass::Reserved {
                    account_id: get.account_id,
                    expires: sample.expires_at.timestamp() as u64,
                };
            }

            get.insert(id, sample.into_value());
        } else {
            get.not_found(id);
        }
    }

    Ok(get)
}

pub(crate) async fn spam_sample_query(
    mut req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    let can_impersonate = req.access_token.has_permission(Permission::Impersonate);
    let mut account_id = None;

    req.request
        .extract_filters(|property, _, value| match property {
            Property::AccountId if can_impersonate => {
                if let Some(id) = value.as_str().and_then(|s| Id::from_str(s).ok()) {
                    account_id = Some(id);
                    true
                } else {
                    false
                }
            }

            _ => false,
        })?;

    let mut query = if let Some(account_id) = account_id {
        RegistryQuery::new(req.object_type).with_account(account_id.document_id())
    } else if !can_impersonate {
        RegistryQuery::new(req.object_type).with_account(req.request.account_id.document_id())
    } else {
        RegistryQuery::new(req.object_type).greater_than_or_equal(Property::AccountId, 0u64)
    };

    let params = req
        .request
        .extract_parameters(req.server.core.jmap.query_max_results, Some(Property::Id))?;

    if let Some(limit) = params.limit {
        query = query.with_limit(limit);
        if let Some(anchor) = params.anchor {
            query = query.with_anchor(anchor);
        } else if let Some(position) = params.position {
            query = query.with_index_start(position);
        }
    }

    let mut results = req.server.registry().query::<Vec<Id>>(query).await?;

    match params.sort_by {
        Property::Id => {
            if !params.sort_ascending {
                results.sort_unstable_by(|a, b| b.cmp(a));
            }
        }
        property => {
            return Err(trc::JmapEvent::UnsupportedSort.into_err().details(format!(
                "Property {} is not supported for sorting",
                property
            )));
        }
    }

    // Build response
    let mut response = QueryResponseBuilder::new(
        results.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    for id in results {
        if !response.add_id(id) {
            break;
        }
    }

    Ok(response)
}
