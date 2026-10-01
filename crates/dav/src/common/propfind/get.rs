/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{PropFindItem, data::PropFindData};
use crate::{
    DavError, DavErrorCondition,
    common::{
        DavCollection, DavQuery, SyncType,
        uri::{DavUriResource, SyncCursor, SyncToken, UriResource, Urn, canonical_dav_uri},
    },
    file::is_symlink,
    principal::propfind::PrincipalPropFind,
};
use common::{DavResourcePath, Server, auth::AccessToken};
use dav_proto::schema::response::{BaseCondition, MultiStatus, Response};
use groupware::calendar::EVENT_SECRET;
use hyper::StatusCode;
use std::{borrow::Cow, sync::Arc};
use store::{
    ahash::AHashMap,
    query::log::{Change, Changes, Query},
    roaring::RoaringBitmap,
};
use trc::AddContext;
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

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
    let min_change_id = match query.sync_type {
        SyncType::Token(
            SyncToken::State(snapshot)
            | SyncToken::ChangesPage { snapshot, .. }
            | SyncToken::InitialPage { snapshot, .. },
        ) => snapshot,
        _ => 0,
    };
    let resources = data
        .resources(
            server,
            access_token,
            account_id,
            sync_collection,
            min_change_id,
        )
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
        .filter(|_| query.sync_type.is_incremental())
        .cloned();
    let mut display_children = display_containers
        .as_ref()
        .filter(|_| container_has_children)
        .map(|containers| {
            let hide_secret = sync_collection == SyncCollection::Calendar;
            containers
                .iter()
                .flat_map(|container_id| resources.children(container_id))
                .filter(|child| {
                    !hide_secret
                        || child
                            .resource
                            .event_flags()
                            .is_none_or(|flags| flags & EVENT_SECRET == 0)
                })
                .map(|child| child.document_id())
                .collect::<RoaringBitmap>()
        });

    // Filter by changelog
    let incremental = match query.sync_type {
        SyncType::Token(SyncToken::State(id)) => Some((id, resources.highest_change_id.max(id), 0)),
        SyncType::Token(SyncToken::ChangesPage {
            from,
            snapshot,
            offset,
        }) => Some((from, snapshot, offset)),
        _ => None,
    };
    let is_sync = match incremental {
        Some((id, snapshot, offset)) => {
            let changes = if id < snapshot {
                let changes = server
                    .store()
                    .changes(
                        account_id,
                        sync_collection.into(),
                        Query::Range(id, snapshot),
                    )
                    .await
                    .caused_by(trc::location!())?;
                if changes.needs_full_rebuild(id) {
                    return Err(DavErrorCondition::new(
                        StatusCode::FORBIDDEN,
                        BaseCondition::ValidSyncToken,
                    )
                    .into());
                }
                changes
            } else {
                Changes::default()
            };

            let mut maybe_has_vanished = false;
            let mut container_changes = RoaringBitmap::new();
            let mut item_changes = RoaringBitmap::new();
            let mut updates = RoaringBitmap::new();
            let track_hidden_items =
                display_containers.is_some() && (container_has_children || is_file);
            for change in changes.changes {
                match change {
                    Change::InsertItem(id) | Change::UpdateItemMetadata(id)
                        if container_has_children =>
                    {
                        item_changes.insert(id as u32);
                    }
                    Change::UpdateItem(id) if container_has_children => {
                        maybe_has_vanished = true;
                        item_changes.insert(id as u32);
                        if track_hidden_items {
                            updates.insert(id as u32);
                        }
                    }
                    Change::InsertItem(id)
                    | Change::InsertContainer(id)
                    | Change::UpdateItemMetadata(id) => {
                        container_changes.insert(id as u32);
                    }
                    Change::UpdateItem(id) | Change::UpdateContainer(id) => {
                        maybe_has_vanished = true;
                        container_changes.insert(id as u32);
                        if track_hidden_items && !container_has_children {
                            updates.insert(id as u32);
                        }
                    }
                    Change::DeleteContainer(_) | Change::DeleteItem(_) => {
                        maybe_has_vanished = true;
                    }
                    Change::UpdateContainerPartial(id, partial) => {
                        if partial.has_metadata() {
                            container_changes.insert(id as u32);
                        }
                    }
                }
            }

            let vanished: Vec<String> = match sync_collection.vanished_collection() {
                Some(vanished_collection) if maybe_has_vanished => server
                    .store()
                    .vanished(
                        account_id,
                        vanished_collection.into(),
                        Query::Range(id, snapshot),
                    )
                    .await
                    .caused_by(trc::location!())?,
                _ => Vec::new(),
            };

            let scope = resource.resource.map_or_else(
                || resources.base_path.clone(),
                |path| resources.format_collection(path),
            );
            let is_visible_href = |href: &str| {
                href.starts_with(scope.as_str())
                    && visible_containers.as_ref().is_none_or(|containers| {
                        let Some(path) = href.strip_prefix(resources.base_path.as_str()) else {
                            return false;
                        };
                        match path.trim_end_matches('/').rsplit_once('/') {
                            Some((parent, _)) => resources
                                .by_path(parent)
                                .is_some_and(|parent| containers.contains(parent.document_id())),
                            None => true,
                        }
                    })
            };
            let hidden_href = |document_id: u32| {
                if !updates.contains(document_id) {
                    return None;
                }
                let containers = display_containers.as_ref()?;
                if container_has_children {
                    let parent_id = resources
                        .item_by_id(document_id)?
                        .child_names()
                        .iter()
                        .map(|name| name.parent_id)
                        .find(|parent_id| containers.contains(*parent_id))?;
                    resources.format_resource_path_by_parent(document_id, parent_id)
                } else {
                    let resource = resources.any_resource_path_by_id(document_id)?;
                    match resource.parent_id() {
                        Some(parent_id) if !containers.contains(parent_id) => None,
                        _ => Some(resources.format_resource(resource)),
                    }
                }
                .filter(|href| is_visible_href(href))
            };

            let mut removed = Vec::new();
            let mut page_containers = RoaringBitmap::new();
            let mut page_items = RoaringBitmap::new();
            let mut emitted = 0;
            let mut next_offset = None;
            for (entry, position) in vanished
                .into_iter()
                .map(SyncEntry::Removed)
                .chain(container_changes.iter().map(SyncEntry::Container))
                .chain(item_changes.iter().map(SyncEntry::Item))
                .skip(usize::try_from(offset).unwrap_or(usize::MAX))
                .zip(offset..)
            {
                let entry = match entry {
                    SyncEntry::Removed(href) => {
                        is_visible_href(&href).then_some(SyncEntry::Removed(href))
                    }
                    SyncEntry::Container(document_id) => {
                        if display_containers
                            .as_ref()
                            .is_none_or(|containers| containers.contains(document_id))
                        {
                            Some(SyncEntry::Container(document_id))
                        } else if container_has_children {
                            None
                        } else {
                            hidden_href(document_id).map(SyncEntry::Removed)
                        }
                    }
                    SyncEntry::Item(document_id) => {
                        if display_children
                            .as_ref()
                            .is_none_or(|children| children.contains(document_id))
                        {
                            Some(SyncEntry::Item(document_id))
                        } else {
                            hidden_href(document_id).map(SyncEntry::Removed)
                        }
                    }
                };
                if let Some(entry) = entry {
                    if emitted == limit {
                        next_offset = Some(position);
                        break;
                    }
                    match entry {
                        SyncEntry::Removed(href) => removed.push(href),
                        SyncEntry::Container(document_id) => {
                            page_containers.insert(document_id);
                        }
                        SyncEntry::Item(document_id) => {
                            page_items.insert(document_id);
                        }
                    }
                    emitted += 1;
                }
            }
            display_containers = Some(page_containers);
            display_children = Some(page_items);
            for href in removed {
                response.add_response(Response::new_status([href], StatusCode::NOT_FOUND));
            }

            *is_sync_limited = next_offset.is_some();
            response.set_sync_token(
                Urn::Sync(match next_offset {
                    Some(offset) => SyncToken::ChangesPage {
                        from: id,
                        snapshot,
                        offset,
                    },
                    None => SyncToken::State(snapshot),
                })
                .to_string(),
            );

            true
        }
        None => false,
    };
    let mut initial = match query.sync_type {
        SyncType::Initial => Some(InitialPaging {
            snapshot: resources.highest_change_id,
            after: None,
            boundary: None,
        }),
        SyncType::Token(SyncToken::InitialPage { snapshot, after }) => Some(InitialPaging {
            snapshot,
            after: Some(after),
            boundary: None,
        }),
        _ => None,
    };

    let mut results = Vec::new();
    if let Some(resource) = resource.resource {
        let paths = resources
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
            });
        results = collect_page(paths, account_id, initial.as_mut(), limit, |item| {
            let is_discover_only = is_discover_only(file_readable.as_ref(), &item);
            let href = if is_file && item.path() == resource {
                requested_href(query.uri, item.is_container())
            } else {
                resources.format_resource(item)
            };
            PropFindItem::new(href, account_id, item).with_discover_only(is_discover_only)
        });
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
            let paths = resources.tree_with_depth(query.depth - 1).filter(|item| {
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
            });
            results = collect_page(paths, account_id, initial.as_mut(), limit, |item| {
                let is_discover_only = is_discover_only(file_readable.as_ref(), &item);
                PropFindItem::new(resources.format_resource(item), account_id, item)
                    .with_discover_only(is_discover_only)
            });

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
                        .resources(server, access_token, shared_account_id, sync_collection, 0)
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

    if let Some(paging) = initial {
        results.retain(|item| {
            let cursor = item.sync_cursor();
            paging.after.is_none_or(|after| cursor > after)
                && paging.boundary.is_none_or(|boundary| cursor <= boundary)
        });
        let boundary =
            select_page(&mut results, limit, PropFindItem::sync_cursor).or(paging.boundary);
        *is_sync_limited = boundary.is_some();
        response.set_sync_token(
            Urn::Sync(match boundary {
                Some(after) => SyncToken::InitialPage {
                    snapshot: paging.snapshot,
                    after,
                },
                None => SyncToken::State(paging.snapshot),
            })
            .to_string(),
        );
    }

    Ok(results)
}

enum SyncEntry {
    Removed(String),
    Container(u32),
    Item(u32),
}

struct InitialPaging {
    snapshot: u64,
    after: Option<SyncCursor>,
    boundary: Option<SyncCursor>,
}

fn collect_page<'x>(
    paths: impl Iterator<Item = DavResourcePath<'x>>,
    account_id: u32,
    paging: Option<&mut InitialPaging>,
    limit: usize,
    to_item: impl FnMut(DavResourcePath<'x>) -> PropFindItem,
) -> Vec<PropFindItem> {
    match paging {
        Some(paging) => {
            let mut paths = paths
                .filter(|path| {
                    paging
                        .after
                        .is_none_or(|after| SyncCursor::from_path(account_id, path) > after)
                })
                .collect::<Vec<_>>();
            paging.boundary = select_page(&mut paths, limit, |path| {
                SyncCursor::from_path(account_id, path)
            });
            paths.into_iter().map(to_item).collect()
        }
        None => paths.map(to_item).collect(),
    }
}

fn select_page<T>(
    items: &mut Vec<T>,
    limit: usize,
    cursor: impl Fn(&T) -> SyncCursor,
) -> Option<SyncCursor> {
    if items.len() <= limit {
        return None;
    }
    let boundary = cursor(items.select_nth_unstable_by_key(limit - 1, &cursor).1);
    items.retain(|item| cursor(item) <= boundary);
    Some(boundary)
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
        let uri = canonical_dav_uri(&item).unwrap_or(Cow::Borrowed(item.as_str()));
        let resource = match server
            .validate_uri(access_token, &uri)
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
            .resources(server, access_token, account_id, sync_collection, 0)
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

#[cfg(test)]
mod tests {
    use super::{SyncCursor, select_page};

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, bound: u32) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((self.0 >> 33) % u64::from(bound)) as u32
        }
    }

    #[test]
    fn select_page_keeps_lowest_and_ties() {
        let mut rng = Lcg(11);
        for _ in 0..500 {
            let items = (0..rng.next(40))
                .map(|_| SyncCursor::new(rng.next(2), rng.next(2) == 0, rng.next(8), None))
                .collect::<Vec<_>>();
            let limit = rng.next(12) as usize + 1;
            let mut sorted = items.clone();
            sorted.sort_unstable();
            let mut page = items.clone();
            let boundary = select_page(&mut page, limit, |cursor| *cursor);
            page.sort_unstable();
            if items.len() <= limit {
                assert_eq!(boundary, None);
                assert_eq!(page, sorted);
            } else {
                let expected_boundary = sorted[limit - 1];
                assert_eq!(boundary, Some(expected_boundary));
                let expected = sorted
                    .iter()
                    .copied()
                    .filter(|cursor| *cursor <= expected_boundary)
                    .collect::<Vec<_>>();
                assert_eq!(page, expected);
                assert!(page.len() >= limit);
            }
        }
    }
}
