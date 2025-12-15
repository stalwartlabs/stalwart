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
    object::file_node::{FileNode, FileNodeFilter},
    request::MaybeInvalid,
};
use store::{
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
            .fetch_dav_resources(access_token, account_id, SyncCollection::FileNode)
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
                    FileNodeFilter::ParentId(MaybeInvalid::Value(id)) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )));
                    }
                    FileNodeFilter::HasParentId(has_parent_id) => {
                        filters.push(SearchFilter::is_in_set(RoaringBitmap::from_iter(
                            cache.resources.iter().filter_map(|r| {
                                if has_parent_id == r.parent_id().is_some() {
                                    Some(r.document_id)
                                } else {
                                    None
                                }
                            }),
                        )));
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
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedFilter
                            .into_err()
                            .details(unsupported.into_string()));
                    }
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

        if request.sort.as_ref().is_some_and(|s| !s.is_empty()) {
            return Err(trc::JmapEvent::UnsupportedSort
                .into_err()
                .details("Sorting is not supported on FileNode"));
        }

        let results = SearchQuery::new(SearchIndex::InMemory)
            .with_filters(filters)
            .with_mask(if access_token.is_shared(account_id) {
                cache.shared_containers(access_token, [Acl::ReadItems], true)
            } else {
                cache.document_ids(false).collect()
            })
            .filter()
            .into_bitmap();

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            cache.get_state(false),
            &request,
        );

        for document_id in results {
            if !response.add(0, document_id) {
                break;
            }
        }

        response.build()
    }
}
