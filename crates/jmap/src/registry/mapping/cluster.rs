/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use jmap_proto::{object::registry::RegistryComparator, types::state::State};
use registry::{jmap::IntoValue, schema::prelude::Property};
use store::ahash::AHashSet;

use crate::{
    api::query::QueryResponseBuilder,
    registry::mapping::{RegistryGetResponse, RegistryQueryResponse},
};

pub(crate) async fn cluster_node_get(
    mut get: RegistryGetResponse<'_>,
) -> trc::Result<RegistryGetResponse<'_>> {
    let nodes = get.server.registry().cluster_node_list().await?;
    let mut ids = get
        .ids
        .take()
        .unwrap_or_default()
        .into_iter()
        .map(|id| id.id())
        .collect::<AHashSet<_>>();

    for node in nodes {
        if ids.is_empty() || ids.remove(&node.node_id) {
            get.insert(node.node_id.into(), node.into_value());
        }
    }

    for id in ids {
        get.not_found(id.into());
    }

    Ok(get)
}

pub(crate) async fn cluster_node_query(
    req: RegistryQueryResponse<'_>,
) -> trc::Result<QueryResponseBuilder> {
    if req
        .request
        .sort
        .as_ref()
        .and_then(|sort| sort.first())
        .is_some_and(|comp| {
            !matches!(
                comp.property,
                RegistryComparator::Property(Property::NodeId)
            )
        })
    {
        return Err(trc::JmapEvent::UnsupportedSort
            .into_err()
            .details("Only sorting by 'nodeId' is supported for cluster nodes".to_string()));
    }

    let nodes = req.server.registry().cluster_node_list().await?;

    // Build response
    let mut response = QueryResponseBuilder::new(
        nodes.len(),
        req.server.core.jmap.query_max_results,
        State::Initial,
        &req.request,
    );

    for node in nodes {
        if !response.add_id(node.node_id.into()) {
            break;
        }
    }

    Ok(response)
}
