/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{JmapMethods, changes::state::JmapCacheState};
use common::{Server, auth::AccessToken};
use groupware::cache::GroupwareCache;
use jmap_proto::{
    method::query::{Filter, QueryRequest, QueryResponse},
    object::file_node::{FileNode, FileNodeFilter},
    request::MaybeInvalid,
};
use store::{query, roaring::RoaringBitmap};
use types::{
    acl::Acl,
    collection::{Collection, SyncCollection},
};

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
        let filter_mask = (access_token.is_shared(account_id))
            .then(|| cache.shared_containers(access_token, [Acl::ReadItems], true));

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => match cond {
                    FileNodeFilter::AncestorId(MaybeInvalid::Value(id)) => {
                        if let Some(resource) =
                            cache.container_resource_path_by_id(id.document_id())
                        {
                            filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
                                cache.subtree(resource.path()).map(|r| r.document_id()),
                            )))
                        } else {
                            filters.push(query::Filter::is_in_set(RoaringBitmap::new()));
                        }
                    }
                    FileNodeFilter::ParentId(MaybeInvalid::Value(id)) => {
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
                            cache.children_ids(id.document_id()),
                        )));
                    }
                    FileNodeFilter::HasParentId(has_parent_id) => {
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
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
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
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
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
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
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
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
                        filters.push(query::Filter::is_in_set(RoaringBitmap::from_iter(
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

                Filter::And | Filter::Or | Filter::Not | Filter::Close => {
                    filters.push(cond.into());
                }
            }
        }

        let mut result_set = self
            .filter(account_id, Collection::FileNode, filters)
            .await?;

        if let Some(filter_mask) = filter_mask {
            result_set.apply_mask(filter_mask);
        }

        let (response, paginate) = self
            .build_query_response(result_set.results.len() as usize, cache.get_state(false), &request)
            .await?;

        if let Some(paginate) = paginate {
            // Parse sort criteria
            /*let mut comparators = Vec::with_capacity(request.sort.as_ref().map_or(1, |s| s.len()));
            for comparator in request
                .sort
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| vec![Comparator::descending(FileNodeComparator::Updated)])
            {
                comparators.push(match comparator.property {
                    FileNodeComparator::Created => {
                        query::Comparator::field(ContactField::Created, comparator.is_ascending)
                    }
                    FileNodeComparator::Updated => {
                        query::Comparator::field(ContactField::Updated, comparator.is_ascending)
                    }
                    unsupported => {
                        return Err(trc::JmapEvent::UnsupportedSort
                            .into_err()
                            .details(unsupported.into_string()));
                    }
                });
            }*/

            if request.sort.is_some_and(|s| !s.is_empty()) {
                return Err(trc::JmapEvent::UnsupportedSort
                    .into_err()
                    .details("Sorting is not supported on FileNode"));
            }

            // Sort results
            self.sort(result_set, Default::default(), paginate, response)
                .await
        } else {
            Ok(response)
        }
    }
}
