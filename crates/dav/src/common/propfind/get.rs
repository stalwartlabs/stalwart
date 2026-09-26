/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PropFindItem, data::PropFindData};
use crate::{
    DavError,
    common::{
        DavCollection, DavQuery, SyncType,
        uri::{DavUriResource, UriResource, Urn},
    },
    file::is_symlink,
    principal::propfind::PrincipalPropFind,
};
use common::{DavResourcePath, Server, auth::AccessToken};
use dav_proto::schema::response::{MultiStatus, Response};
use groupware::calendar::EVENT_SECRET;
use hyper::StatusCode;
use std::sync::Arc;
use store::{
    ahash::AHashMap,
    query::log::{Change, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

use super::data::SyncTokenUrn;

#[allow(clippy::too_many_arguments)]
pub(super) async fn get(
    server: &Server,
    access_token: &AccessToken,
    collection_container: Collection,
    collection_children: Collection,
    sync_collection: SyncCollection,
    query: &DavQuery<'_>,
    data: &mut PropFindData,
    response: &mut MultiStatus,
    resource: UriResource<u32, Option<&str>>,
    limit: usize,
    is_sync_limited: &mut bool,
) -> crate::Result<Vec<PropFindItem>> {
    let container_has_children = collection_children != collection_container;
    response.set_namespace(collection_container.namespace());

    let account_id = resource.account_id;
    let resources = data
        .resources(server, access_token, account_id, sync_collection)
        .await
        .caused_by(trc::location!())?;

    // Obtain document ids
    let is_file = sync_collection == SyncCollection::FileNode;
    let mut file_readable = None;
    let mut display_containers = if is_file && !access_token.is_member(account_id) {
        let access = resources.file_access(access_token);
        file_readable = Some(access.readable.clone());
        let discoverable = access.discoverable.clone();
        data.accounts.entry(account_id).or_default().file_access = Some(access);
        Some(discoverable)
    } else if !access_token.is_member(account_id) {
        resources
            .shared_containers(
                access_token,
                [if container_has_children {
                    Acl::ReadItems
                } else {
                    Acl::Read
                }],
                true,
            )
            .into()
    } else {
        None
    };
    let visible_containers = display_containers
        .as_ref()
        .filter(|_| matches!(query.sync_type, SyncType::From { .. }))
        .cloned();
    let mut display_children = display_containers
        .as_ref()
        .filter(|_| container_has_children)
        .map(|containers| {
            let mut children =
                RoaringBitmap::from_iter(resources.resources.iter().filter_map(|r| {
                    if r.child_names()
                        .iter()
                        .any(|n| containers.contains(n.parent_id))
                    {
                        Some(r.document_id())
                    } else {
                        None
                    }
                }));
            if sync_collection == SyncCollection::Calendar {
                children -= resources.event_ids_with_flags(EVENT_SECRET);
            }
            children
        });

    // Filter by changelog
    let is_sync = match query.sync_type {
        SyncType::From { id, seq } => {
            let changes = server
                .store()
                .changes(account_id, sync_collection.into(), Query::Since(id))
                .await
                .caused_by(trc::location!())?;
            let mut vanished: Vec<String> = Vec::new();

            // Merge changes
            let mut total_changes = 0;
            let mut maybe_has_vanished = false;
            let mut hidden_hrefs: Vec<String> = Vec::new();
            if container_has_children {
                let mut container_changes = RoaringBitmap::new();
                let mut item_changes = RoaringBitmap::new();
                let mut item_updates = RoaringBitmap::new();
                let track_hidden_items = display_children.is_some();

                for change in changes.changes {
                    match change {
                        Change::InsertItem(id) => {
                            item_changes.insert(id as u32);
                        }
                        Change::UpdateItem(id) => {
                            maybe_has_vanished = true;
                            item_changes.insert(id as u32);
                            if track_hidden_items {
                                item_updates.insert(id as u32);
                            }
                        }
                        Change::InsertContainer(id) => {
                            container_changes.insert(id as u32);
                        }
                        Change::UpdateContainer(id) => {
                            maybe_has_vanished = true;
                            container_changes.insert(id as u32);
                        }
                        Change::DeleteContainer(_) | Change::DeleteItem(_) => {
                            maybe_has_vanished = true;
                        }
                        Change::UpdateContainerProperty(_) => (),
                    }
                }

                if let (Some(children), Some(containers)) = (&display_children, &display_containers)
                {
                    item_updates -= children;
                    hidden_hrefs.extend(item_updates.iter().filter_map(|document_id| {
                        let parent_id = resources
                            .item_by_id(document_id)?
                            .child_names()
                            .iter()
                            .map(|name| name.parent_id)
                            .find(|parent_id| containers.contains(*parent_id))?;
                        resources.format_resource_path_by_parent(document_id, parent_id)
                    }));
                }

                for (document_ids, changes) in [
                    (&mut display_containers, container_changes),
                    (&mut display_children, item_changes),
                ] {
                    if let Some(document_ids) = document_ids {
                        *document_ids &= changes;
                        total_changes += document_ids.len() as usize;
                    } else {
                        total_changes += changes.len() as usize;
                        *document_ids = Some(changes);
                    }
                }
            } else {
                let mut updates = RoaringBitmap::new();
                let track_hidden_items = is_file && display_containers.is_some();
                let changes = RoaringBitmap::from_iter(changes.changes.iter().filter_map(
                    |change| match change {
                        Change::InsertItem(id) | Change::InsertContainer(id) => Some(*id as u32),
                        Change::UpdateItem(id) | Change::UpdateContainer(id) => {
                            maybe_has_vanished = true;
                            if track_hidden_items {
                                updates.insert(*id as u32);
                            }
                            Some(*id as u32)
                        }
                        Change::DeleteContainer(_) | Change::DeleteItem(_) => {
                            maybe_has_vanished = true;
                            None
                        }
                        _ => None,
                    },
                ));

                if let Some(discoverable) = &display_containers {
                    updates -= discoverable;
                    hidden_hrefs.extend(updates.iter().filter_map(|document_id| {
                        let resource = resources.any_resource_path_by_id(document_id)?;
                        match resource.parent_id() {
                            Some(parent_id) if !discoverable.contains(parent_id) => None,
                            _ => Some(resources.format_resource(resource)),
                        }
                    }));
                }

                if let Some(document_ids) = &mut display_containers {
                    *document_ids &= changes;
                    total_changes += document_ids.len() as usize;
                } else {
                    total_changes += changes.len() as usize;
                    display_containers = Some(changes);
                }
            }

            if maybe_has_vanished
                && let Some(vanished_collection) = sync_collection.vanished_collection()
            {
                vanished = server
                    .store()
                    .vanished(account_id, vanished_collection.into(), Query::Since(id))
                    .await
                    .caused_by(trc::location!())?;
            }
            vanished.append(&mut hidden_hrefs);
            if !vanished.is_empty() {
                let scope = resource.resource.map_or_else(
                    || resources.base_path.clone(),
                    |path| resources.format_collection(path),
                );
                vanished.retain(|href| {
                    href.starts_with(scope.as_str())
                        && visible_containers.as_ref().is_none_or(|containers| {
                            let Some(path) = href.strip_prefix(resources.base_path.as_str()) else {
                                return false;
                            };
                            match path.trim_end_matches('/').rsplit_once('/') {
                                Some((parent, _)) => {
                                    resources.by_path(parent).is_some_and(|parent| {
                                        containers.contains(parent.document_id())
                                    })
                                }
                                None => true,
                            }
                        })
                });
                total_changes += vanished.len();
            }

            // Truncate changes
            if total_changes > limit {
                let mut offset = limit * seq as usize;
                let mut total_changes = 0;

                // Add vanished items to response
                for item in vanished {
                    if offset > 0 {
                        offset -= 1;
                    } else if total_changes < limit {
                        response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
                        total_changes += 1;
                    } else {
                        *is_sync_limited = true;
                    }
                }

                // Add items to document set
                for document_ids in [&mut display_containers, &mut display_children]
                    .into_iter()
                    .flatten()
                {
                    let mut new_document_ids = RoaringBitmap::new();
                    for id in document_ids.iter() {
                        if offset > 0 {
                            offset -= 1;
                        } else if total_changes < limit {
                            new_document_ids.insert(id);
                            total_changes += 1;
                        } else {
                            *is_sync_limited = true;
                        }
                    }
                    *document_ids = new_document_ids;
                }

                if *is_sync_limited {
                    response.set_sync_token(Urn::Sync { id, seq: seq + 1 }.to_string());
                }
            } else {
                // Add vanished items to response
                for item in vanished {
                    response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
                }
            }

            if !*is_sync_limited {
                response.set_sync_token(resources.sync_token());
            }

            true
        }
        SyncType::Initial => {
            response.set_sync_token(resources.sync_token());
            false
        }
        SyncType::None => false,
    };

    let mut results = Vec::new();
    if let Some(resource) = resource.resource {
        results = resources
            .subtree_with_depth(resource, query.depth)
            .filter(|item| {
                display_containers.as_ref().is_none_or(|containers| {
                    if container_has_children {
                        if item.is_container() {
                            containers.contains(item.document_id())
                        } else {
                            display_children
                                .as_ref()
                                .is_some_and(|children| children.contains(item.document_id()))
                        }
                    } else {
                        containers.contains(item.document_id())
                    }
                }) && (!query.depth_no_root || item.path() != resource)
                    && (!is_file || !is_symlink(item))
            })
            .map(|item| {
                let is_discover_only = is_discover_only(file_readable.as_ref(), &item);
                let href = if is_file && item.path() == resource {
                    requested_href(query.uri, item.is_container())
                } else {
                    resources.format_resource(item)
                };
                PropFindItem::new(href, account_id, item).with_discover_only(is_discover_only)
            })
            .collect::<Vec<_>>();
    } else {
        if !query.depth_no_root && query.sync_type.is_none_or_initial() {
            server
                .prepare_principal_propfind_response(
                    access_token,
                    collection_container,
                    [account_id].into_iter(),
                    &query.propfind,
                    response,
                )
                .await?;
        }

        if query.depth != 0 {
            results = resources
                .tree_with_depth(query.depth - 1)
                .filter(|item| {
                    display_containers.as_ref().is_none_or(|containers| {
                        if container_has_children {
                            if item.is_container() {
                                containers.contains(item.document_id())
                            } else {
                                display_children
                                    .as_ref()
                                    .is_some_and(|children| children.contains(item.document_id()))
                            }
                        } else {
                            containers.contains(item.document_id())
                        }
                    }) && (!is_file || !is_symlink(item))
                })
                .map(|item| {
                    let is_discover_only = is_discover_only(file_readable.as_ref(), &item);
                    PropFindItem::new(resources.format_resource(item), account_id, item)
                        .with_discover_only(is_discover_only)
                })
                .collect::<Vec<_>>();

            // Assisted discovery:
            // If 'bob' has access to 'jane' and `bill` calendars, a query to '/dav/cal/bob' will return:
            //    - /dav/cal/bob/default
            //    - /dav/cal/jane/default
            //    - /dav/cal/bill/default
            // This is invalid but it's the only workaround for clients which do not support multiple home-sets
            if server.core.groupware.assisted_discovery
                && !is_sync
                && account_id == access_token.account_id()
                && matches!(
                    sync_collection,
                    SyncCollection::Calendar | SyncCollection::AddressBook
                )
            {
                for shared_account_id in access_token.all_ids_by_collection(collection_container) {
                    if shared_account_id == access_token.account_id() {
                        continue;
                    }
                    let shared_resources = data
                        .resources(server, access_token, shared_account_id, sync_collection)
                        .await
                        .caused_by(trc::location!())?;
                    let shared_containers =
                        (!access_token.is_member(shared_account_id)).then(|| {
                            shared_resources.shared_containers(
                                access_token,
                                [if container_has_children {
                                    Acl::ReadItems
                                } else {
                                    Acl::Read
                                }],
                                true,
                            )
                        });
                    if shared_containers
                        .as_ref()
                        .is_none_or(|containers| !containers.is_empty())
                    {
                        results.extend(
                            shared_resources
                                .tree_with_depth(query.depth - 1)
                                .filter(|item| {
                                    item.is_container()
                                        && shared_containers.as_ref().is_none_or(|containers| {
                                            containers.contains(item.document_id())
                                        })
                                })
                                .map(|item| {
                                    PropFindItem::new(
                                        shared_resources.format_resource(item),
                                        shared_account_id,
                                        item,
                                    )
                                }),
                        );
                    }
                }
            }
        }
    }

    Ok(results)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn multiget(
    server: &Server,
    access_token: &AccessToken,
    collection_container: Collection,
    collection_children: Collection,
    sync_collection: SyncCollection,
    data: &mut PropFindData,
    response: &mut MultiStatus,
    hrefs: Vec<String>,
) -> crate::Result<Vec<PropFindItem>> {
    let mut paths = Vec::with_capacity(hrefs.len() * 2);
    let mut shared_folders_by_account: AHashMap<u32, Arc<RoaringBitmap>> =
        AHashMap::with_capacity(3);

    for item in hrefs {
        let resource = match server
            .validate_uri(access_token, &item)
            .await
            .and_then(|r| r.into_owned_uri())
        {
            Ok(resource) => resource,
            Err(DavError::Code(code)) => {
                response.add_response(Response::new_status([item], code));
                continue;
            }
            Err(err) => {
                return Err(err);
            }
        };

        let account_id = resource.account_id;
        let resources = data
            .resources(server, access_token, account_id, sync_collection)
            .await
            .caused_by(trc::location!())?;

        let document_ids = if !access_token.is_member(account_id) {
            if let Some(document_ids) = shared_folders_by_account.get(&account_id) {
                document_ids.clone().into()
            } else {
                let document_ids = Arc::new(resources.shared_containers(
                    access_token,
                    [if collection_children == collection_container {
                        Acl::ReadItems
                    } else {
                        Acl::Read
                    }],
                    true,
                ));
                shared_folders_by_account.insert(account_id, document_ids.clone());
                document_ids.into()
            }
        } else {
            None
        };

        if let Some(resource) = resource
            .resource
            .and_then(|name| resources.by_path(name))
            .filter(|resource| {
                access_token.is_member(account_id)
                    || resource
                        .resource
                        .event_flags()
                        .is_none_or(|flags| flags & EVENT_SECRET == 0)
            })
        {
            if !resource.is_container() {
                if document_ids.as_ref().is_none_or(|docs| {
                    resource
                        .parent_id()
                        .is_some_and(|parent_id| docs.contains(parent_id))
                }) {
                    paths.push(PropFindItem::new(
                        resources.format_resource(resource),
                        account_id,
                        resource,
                    ));
                } else {
                    response.add_response(
                        Response::new_status([item], StatusCode::FORBIDDEN)
                            .with_response_description(
                                "Not enough permissions to access this shared resource",
                            ),
                    );
                }
            } else {
                response.add_response(
                    Response::new_status([item], StatusCode::FORBIDDEN)
                        .with_response_description("Multiget not allowed for collections"),
                );
            }
        } else {
            response.add_response(Response::new_status([item], StatusCode::NOT_FOUND));
        }
    }

    Ok(paths)
}

pub(crate) fn requested_href(uri: &str, is_container: bool) -> String {
    if is_container && !uri.ends_with('/') {
        format!("{uri}/")
    } else {
        uri.to_string()
    }
}

fn is_discover_only(readable: Option<&RoaringBitmap>, item: &DavResourcePath<'_>) -> bool {
    readable.is_some_and(|readable| !readable.contains(item.document_id()))
}
