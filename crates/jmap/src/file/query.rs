/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::file_node::{FileNode, FileNodeComparator, FileNodeFilter},
    request::MaybeInvalid,
};
use store::{
    ahash::AHashMap,
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::SearchIndex,
};
use types::{acl::Acl, collection::SyncCollection};

pub trait FileNodeQuery: Sync + Send {
    fn file_node_query(
        &self,
        request: QueryRequest<FileNode>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl FileNodeQuery for Server {
    async fn file_node_query(
        &self,
        mut request: QueryRequest<FileNode>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let mut filters = Vec::with_capacity(request.filter.len());
        let cache = self
            .fetch_dav_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await?;

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    FileNodeFilter::AncestorId(MaybeInvalid::Value(id)) => {
                        if let Some(resource) =
                            cache.container_resource_path_by_id(id.document_id())
                        {
                            filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                                cache.subtree(resource.path()).map(|r| r.document_id()),
                            )))
                        } else {
                            filters.push(SearchFilter::is_in_set(RoaringBitmap::new()));
                        }
                    }
                    FileNodeFilter::DescendantId(MaybeInvalid::Value(id)) => {
                        let mut ancestors = RoaringBitmap::new();
                        let mut current = cache
                            .any_resource_path_by_id(id.document_id())
                            .and_then(|r| r.parent_id());
                        while let Some(parent_id) = current {
                            if !ancestors.insert(parent_id) {
                                break;
                            }
                            current = cache
                                .container_resource_by_id(parent_id)
                                .and_then(|r| r.parent_id());
                        }
                        filters.push(SearchFilter::is_in_set(ancestors));
                    }
                    FileNodeFilter::ParentId(MaybeInvalid::Value(id)) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )));
                    }
                    FileNodeFilter::IsTopLevel(is_top_level) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if is_top_level == r.parent_id().is_none() {
                                    Some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    FileNodeFilter::NodeType(node_type) => {
                        let want_container = match node_type.as_str() {
                            "directory" => Some(true),
                            "file" => Some(false),
                            _ => None,
                        };
                        let set = match want_container {
                            Some(is_container) => {
                                RoaringBitmap::from_iter(cache.resources.iter().filter_map(|r| {
                                    if r.is_container() == is_container {
                                        Some(r.document_id)
                                    } else {
                                        None
                                    }
                                }))
                            }
                            // TODO: support symlink nodeType once target storage exists
                            None => RoaringBitmap::new(),
                        };
                        filters.push(SearchFilter::is_in_set(set));
                    }
                    FileNodeFilter::Name(name) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if r.container_name().is_some_and(|n| n == name) {
                                    Some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    FileNodeFilter::NameMatch(name) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if r.container_name().is_some_and(|n| name.matches(n)) {
                                    Some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    FileNodeFilter::MinSize(size) => {
                        let size = size as u32;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if r.size().is_some_and(|s| s >= size) {
                                    Some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    FileNodeFilter::MaxSize(size) => {
                        let size = size as u32;
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if r.size().is_some_and(|s| s <= size) {
                                    Some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
                    }
                    // TODO: filters below require fetching archives or new indexes; ignore for now
                    FileNodeFilter::Role(_)
                    | FileNodeFilter::HasAnyRole(_)
                    | FileNodeFilter::BlobId(_)
                    | FileNodeFilter::IsExecutable(_)
                    | FileNodeFilter::CreatedBefore(_)
                    | FileNodeFilter::CreatedAfter(_)
                    | FileNodeFilter::ModifiedBefore(_)
                    | FileNodeFilter::ModifiedAfter(_)
                    | FileNodeFilter::AccessedBefore(_)
                    | FileNodeFilter::AccessedAfter(_)
                    | FileNodeFilter::Type(_)
                    | FileNodeFilter::TypeMatch(_)
                    | FileNodeFilter::Text(_)
                    | FileNodeFilter::Body(_)
                    | FileNodeFilter::AncestorId(_)
                    | FileNodeFilter::DescendantId(_)
                    | FileNodeFilter::ParentId(_)
                    | FileNodeFilter::_T(_) => {}
                },
                Filter::And => {
                    filters.push(SearchFilter::And);
                }
                Filter::Or => {
                    filters.push(SearchFilter::Or);
                }
                Filter::Not => {
                    filters.push(SearchFilter::Not);
                }
                Filter::Close => {
                    filters.push(SearchFilter::End);
                }
            }
        }

        let results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(if access_token.is_shared(account_id) {
                cache.shared_documents(access_token, [Acl::Read, Acl::ReadItems], true)
            } else {
                cache.resources.iter().map(|r| r.document_id).collect()
            })
            .filter()
            .into_bitmap();

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            cache.get_state(false),
            &request,
        );

        // Only name, size and nodeType can be sorted from the cache.
        // TODO: created/modified/type/tree sorts require archive or hierarchy traversal
        let sortable = request
            .sort
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|c| {
                matches!(
                    c.property,
                    FileNodeComparator::Name
                        | FileNodeComparator::Size
                        | FileNodeComparator::NodeType
                )
            })
            .collect::<Vec<_>>();

        if sortable.is_empty() {
            for document_id in results {
                if !response.add(0, document_id) {
                    break;
                }
            }
        } else {
            let by_id = cache
                .resources
                .iter()
                .map(|r| (r.document_id, r))
                .collect::<AHashMap<_, _>>();
            let mut ids = results.iter().collect::<Vec<_>>();
            ids.sort_unstable_by(|a, b| {
                for cmp in &sortable {
                    let ra = by_id.get(a);
                    let rb = by_id.get(b);
                    let ordering = match cmp.property {
                        FileNodeComparator::Name => ra
                            .and_then(|r| r.container_name())
                            .cmp(&rb.and_then(|r| r.container_name())),
                        FileNodeComparator::Size => {
                            ra.and_then(|r| r.size()).cmp(&rb.and_then(|r| r.size()))
                        }
                        FileNodeComparator::NodeType => {
                            // Directories sort before files
                            let a_dir = ra.map(|r| r.is_container()).unwrap_or(false);
                            let b_dir = rb.map(|r| r.is_container()).unwrap_or(false);
                            b_dir.cmp(&a_dir)
                        }
                        _ => std::cmp::Ordering::Equal,
                    };
                    let ordering = if cmp.is_ascending {
                        ordering
                    } else {
                        ordering.reverse()
                    };
                    if ordering != std::cmp::Ordering::Equal {
                        return ordering;
                    }
                }
                a.cmp(b)
            });
            for document_id in ids {
                if !response.add(0, document_id) {
                    break;
                }
            }
        }

        response.build()
    }
}
