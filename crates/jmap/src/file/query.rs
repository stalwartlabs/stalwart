/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::node::node_type_id;
use crate::{api::query::QueryResponseBuilder, changes::state::JmapCacheState};
use common::{
    GroupwareResourceRef, GroupwareResources, Server,
    auth::AccessToken,
    storage::dav::{FILE_KIND_DIRECTORY, FILE_KIND_FILE},
};
use groupware::{
    cache::GroupwareCache,
    file::{FileNode, FileNodeRole},
};
use jmap_proto::{
    method::query::{Comparator, Filter, QueryRequest, QueryResponse},
    object::file_node::{
        FileNode as FileNodeObject, FileNodeComparator, FileNodeFilter, FileNodeNodeType,
    },
    request::MaybeInvalid,
};
use std::cmp::Ordering;
use store::IterateParams;
use store::{
    U32_LEN, ValueKey,
    roaring::RoaringBitmap,
    search::{FileSearchField, SearchFilter, SearchQuery},
    write::{BlobLink, BlobOp, SearchIndex, ValueClass, key::DeserializeBigEndian},
};
use trc::AddContext;
use types::{
    blob_hash::BLOB_HASH_LEN,
    collection::{Collection, SyncCollection},
    field::Field,
    id::Id,
    media_type::MediaTypeId,
};
use utils::glob::GlobPattern;

const MAX_TREE_DEPTH: usize = 256;

pub trait FileNodeQuery: Sync + Send {
    fn file_node_query(
        &self,
        request: QueryRequest<FileNodeObject>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<QueryResponse>> + Send;
}

impl FileNodeQuery for Server {
    async fn file_node_query(
        &self,
        mut request: QueryRequest<FileNodeObject>,
        access_token: &AccessToken,
    ) -> trc::Result<QueryResponse> {
        let account_id = request.account_id.document_id();
        let cache = self
            .fetch_groupware_resources(
                access_token.account_id(),
                account_id,
                SyncCollection::FileNode,
            )
            .await?;
        let depth = request.arguments.depth.unwrap_or(0) as usize;
        let fts_enabled = self
            .core
            .email
            .index_fields
            .contains_key(&SearchIndex::File);
        let mut uses_fts = false;
        let mut filters = Vec::with_capacity(request.filter.len());
        let (mask, hidden) = if access_token.is_member(account_id) {
            (all_ids(&cache), None)
        } else {
            let access = cache.file_access(access_token);
            let hidden = &access.discoverable - &access.readable;
            (access.discoverable, Some(hidden))
        };
        let is_visible = |id: Id| mask.contains(id.document_id());
        let readable_only = |set: RoaringBitmap| match &hidden {
            Some(hidden) => set - hidden,
            None => set,
        };
        let with_hidden = |set: RoaringBitmap| match &hidden {
            Some(hidden) => set | hidden,
            None => set,
        };

        for cond in std::mem::take(&mut request.filter) {
            match cond {
                Filter::Property(cond) => {
                    let set = match cond {
                        FileNodeFilter::IsTopLevel(is_top_level) => {
                            let within = if depth == 0 {
                                matching(&cache, |r| r.parent_id().is_none())
                            } else {
                                cache
                                    .tree_with_depth(depth)
                                    .map(|resource| resource.document_id())
                                    .collect()
                            };
                            if is_top_level {
                                within
                            } else {
                                all_ids(&cache) - within
                            }
                        }
                        FileNodeFilter::ParentId(MaybeInvalid::Value(id)) if is_visible(id) => {
                            descendants(&cache, id.document_id(), depth + 1)
                        }
                        FileNodeFilter::AncestorId(MaybeInvalid::Value(id)) if is_visible(id) => {
                            descendants(&cache, id.document_id(), usize::MAX)
                        }
                        FileNodeFilter::DescendantId(MaybeInvalid::Value(id)) if is_visible(id) => {
                            let mut ancestors = RoaringBitmap::new();
                            let mut current = cache
                                .resources
                                .find_any(id.document_id())
                                .and_then(|r| r.parent_id());
                            while let Some(parent_id) = current {
                                if !ancestors.insert(parent_id) {
                                    break;
                                }
                                current = cache
                                    .resources
                                    .find_any(parent_id)
                                    .and_then(|r| r.parent_id());
                            }
                            ancestors
                        }
                        FileNodeFilter::NodeType(node_type) => {
                            let Some(kind) = FileNodeNodeType::parse(&node_type).map(node_type_id)
                            else {
                                return Err(trc::JmapEvent::UnsupportedFilter
                                    .into_err()
                                    .details(node_type));
                            };
                            matching(&cache, |r| r.file_kind() == Some(kind))
                        }
                        FileNodeFilter::Role(role) => match FileNodeRole::parse(&role) {
                            Some(role) => {
                                readable_only(matching(&cache, |r| r.file_role() == role.id()))
                            }
                            None => RoaringBitmap::new(),
                        },
                        FileNodeFilter::HasAnyRole(true) => {
                            readable_only(matching(&cache, |r| r.file_role() != 0))
                        }
                        FileNodeFilter::HasAnyRole(false) => {
                            with_hidden(matching(&cache, |r| r.file_role() == 0))
                        }
                        FileNodeFilter::BlobId(MaybeInvalid::Value(blob_id)) => {
                            let mut ids = RoaringBitmap::new();
                            let collection = u8::from(Collection::FileNode);
                            let key = |document_id| ValueKey {
                                account_id,
                                collection,
                                document_id,
                                class: ValueClass::Blob(BlobOp::Link {
                                    hash: blob_id.hash.clone(),
                                    to: BlobLink::Document,
                                }),
                            };
                            self.store()
                                .iterate(
                                    IterateParams::new(key(0), key(u32::MAX)).no_values(),
                                    |key, _| {
                                        ids.insert(
                                            key.deserialize_be_u32(BLOB_HASH_LEN + U32_LEN + 1)?,
                                        );
                                        Ok(true)
                                    },
                                )
                                .await
                                .caused_by(trc::location!())?;
                            readable_only(ids)
                        }
                        FileNodeFilter::ParentId(_)
                        | FileNodeFilter::AncestorId(_)
                        | FileNodeFilter::DescendantId(_)
                        | FileNodeFilter::BlobId(_) => RoaringBitmap::new(),
                        FileNodeFilter::IsExecutable(true) => {
                            readable_only(matching(&cache, |r| r.is_executable()))
                        }
                        FileNodeFilter::IsExecutable(false) => {
                            with_hidden(matching(&cache, |r| !r.is_executable()))
                        }
                        FileNodeFilter::CreatedBefore(date) => {
                            let date = date.timestamp();
                            readable_only(matching(&cache, |r| {
                                r.created_at().is_some_and(|c| c < date)
                            }))
                        }
                        FileNodeFilter::CreatedAfter(date) => {
                            let date = date.timestamp();
                            readable_only(matching(&cache, |r| {
                                r.created_at().is_some_and(|c| c >= date)
                            }))
                        }
                        FileNodeFilter::ModifiedBefore(date) => {
                            let date = date.timestamp();
                            readable_only(matching(&cache, |r| {
                                r.modified_at().is_some_and(|m| m < date)
                            }))
                        }
                        FileNodeFilter::ModifiedAfter(date) => {
                            let date = date.timestamp();
                            readable_only(matching(&cache, |r| {
                                r.modified_at().is_some_and(|m| m >= date)
                            }))
                        }
                        FileNodeFilter::AccessedBefore(date) => {
                            let date = date.timestamp();
                            readable_only(
                                accessed_matching(self, account_id, |accessed| accessed < date)
                                    .await?,
                            )
                        }
                        FileNodeFilter::AccessedAfter(date) => {
                            let date = date.timestamp();
                            readable_only(
                                accessed_matching(self, account_id, |accessed| accessed >= date)
                                    .await?,
                            )
                        }
                        FileNodeFilter::MinSize(size) => readable_only(matching(&cache, |r| {
                            r.size().is_some_and(|s| s as u64 >= size)
                        })),
                        FileNodeFilter::MaxSize(size) => readable_only(matching(&cache, |r| {
                            r.size().is_some_and(|s| (s as u64) < size)
                        })),
                        FileNodeFilter::Name(name) => {
                            matching(&cache, |r| r.container_name() == Some(name.as_str()))
                        }
                        FileNodeFilter::NameMatch(pattern) => name_matching(&cache, &pattern),
                        FileNodeFilter::Type(media_type) => readable_only(matching(&cache, |r| {
                            r.media_type() == Some(media_type.as_str())
                        })),
                        FileNodeFilter::TypeMatch(pattern) => {
                            readable_only(type_matching(&cache, &pattern))
                        }
                        FileNodeFilter::Text(text) => {
                            let pattern = GlobPattern::compile(&text, true);
                            let set = name_matching(&cache, &pattern)
                                | readable_only(type_matching(&cache, &pattern));
                            if fts_enabled {
                                uses_fts = true;
                                filters.push(SearchFilter::Or);
                                filters.extend(readable_text_filter(
                                    SearchFilter::has_text_detect(
                                        FileSearchField::Content,
                                        text,
                                        self.core.email.default_language,
                                    ),
                                    hidden.as_ref().map(|hidden| &mask - hidden),
                                ));
                                filters.extend([SearchFilter::is_in_set(set), SearchFilter::End]);
                                continue;
                            }
                            set
                        }
                        FileNodeFilter::Body(text) if fts_enabled => {
                            uses_fts = true;
                            filters.extend(readable_text_filter(
                                SearchFilter::has_text_detect(
                                    FileSearchField::Content,
                                    text,
                                    self.core.email.default_language,
                                ),
                                hidden.as_ref().map(|hidden| &mask - hidden),
                            ));
                            continue;
                        }
                        FileNodeFilter::Metadata(_) => todo!(),
                        unsupported @ (FileNodeFilter::Body(_) | FileNodeFilter::_T(_)) => {
                            return Err(trc::JmapEvent::UnsupportedFilter
                                .into_err()
                                .details(unsupported.into_string()));
                        }
                    };
                    filters.push(SearchFilter::is_in_set(set));
                }
                Filter::And => filters.push(SearchFilter::And),
                Filter::Or => filters.push(SearchFilter::Or),
                Filter::Not => filters.push(SearchFilter::Not),
                Filter::Close => filters.push(SearchFilter::End),
            }
        }

        let results = if uses_fts {
            self.search_store()
                .filter_account(
                    SearchQuery::new(SearchIndex::File)
                        .with_filters(filters)
                        .with_account_id(account_id)
                        .with_mask(mask),
                )
                .await?
        } else {
            SearchQuery::new(SearchIndex::InMemory)
                .with_filters(filters)
                .with_mask(mask)
                .filter()
                .into_bitmap()
        };

        let mut response = QueryResponseBuilder::new(
            results.len() as usize,
            self.core.jmap.query_max_results,
            cache.get_state(false),
            &request,
        );

        let comparators = request.sort.take().unwrap_or_default();
        let mut collations = Vec::with_capacity(comparators.len());
        for comparator in &comparators {
            if matches!(comparator.property, FileNodeComparator::_T(_)) {
                return Err(trc::JmapEvent::UnsupportedSort
                    .into_err()
                    .details(comparator.property.as_str().to_string()));
            }
            match Collation::parse(comparator.collation.as_deref()) {
                Some(collation) => collations.push(collation),
                None => {
                    return Err(trc::JmapEvent::UnsupportedSort
                        .into_err()
                        .details(comparator.collation.clone().unwrap_or_default()));
                }
            }
        }

        if comparators.is_empty() {
            for document_id in results {
                if !response.add(0, document_id) {
                    break;
                }
            }
        } else {
            let has_tree = comparators
                .iter()
                .any(|comparator| matches!(comparator.property, FileNodeComparator::Tree));
            let mut entries = results
                .iter()
                .filter_map(|document_id| cache.resources.find_any(document_id))
                .map(|resource| SortEntry {
                    readable: hidden
                        .as_ref()
                        .is_none_or(|hidden| !hidden.contains(resource.document_id())),
                    tree: if has_tree {
                        tree_path(&cache, &resource)
                    } else {
                        Vec::new()
                    },
                    resource,
                })
                .collect::<Vec<_>>();
            entries.sort_unstable_by(|a, b| {
                comparators
                    .iter()
                    .zip(collations.iter())
                    .map(|(comparator, collation)| compare(comparator, *collation, a, b))
                    .find(|ordering| *ordering != Ordering::Equal)
                    .unwrap_or_else(|| a.resource.document_id().cmp(&b.resource.document_id()))
            });
            for entry in entries {
                if !response.add(0, entry.resource.document_id()) {
                    break;
                }
            }
        }

        response.build()
    }
}

struct SortEntry<'x> {
    resource: GroupwareResourceRef<'x>,
    readable: bool,
    tree: Vec<&'x str>,
}

impl<'x> SortEntry<'x> {
    fn readable<T>(&self, value: impl FnOnce(&GroupwareResourceRef<'x>) -> Option<T>) -> Option<T> {
        self.readable.then(|| value(&self.resource)).flatten()
    }
}

fn readable_text_filter(
    text: SearchFilter,
    readable: Option<RoaringBitmap>,
) -> impl Iterator<Item = SearchFilter> {
    match readable {
        Some(readable) => vec![
            SearchFilter::And,
            text,
            SearchFilter::is_in_set(readable),
            SearchFilter::End,
        ],
        None => vec![text],
    }
    .into_iter()
}

async fn accessed_matching(
    server: &Server,
    account_id: u32,
    predicate: impl Fn(i64) -> bool + Send + Sync,
) -> trc::Result<RoaringBitmap> {
    let mut ids = RoaringBitmap::new();
    server
        .archives(
            account_id,
            Collection::FileNode,
            Field::ARCHIVE,
            &(),
            |document_id, archive| {
                if predicate(archive.unarchive::<FileNode>()?.accessed.to_native()) {
                    ids.insert(document_id);
                }
                Ok(true)
            },
        )
        .await
        .caused_by(trc::location!())?;
    Ok(ids)
}

fn compare(
    comparator: &Comparator<FileNodeComparator>,
    collation: Collation,
    a: &SortEntry<'_>,
    b: &SortEntry<'_>,
) -> Ordering {
    let (ra, rb) = (&a.resource, &b.resource);
    let ordering = match comparator.property {
        FileNodeComparator::Name => collation.compare(
            ra.container_name().unwrap_or_default(),
            rb.container_name().unwrap_or_default(),
        ),
        FileNodeComparator::Size => a
            .readable(GroupwareResourceRef::size)
            .cmp(&b.readable(GroupwareResourceRef::size)),
        FileNodeComparator::Created => a
            .readable(GroupwareResourceRef::created_at)
            .cmp(&b.readable(GroupwareResourceRef::created_at)),
        FileNodeComparator::Modified => a
            .readable(GroupwareResourceRef::modified_at)
            .cmp(&b.readable(GroupwareResourceRef::modified_at)),
        FileNodeComparator::NodeType => kind_rank(ra).cmp(&kind_rank(rb)),
        FileNodeComparator::Type => (ra.file_kind() != Some(FILE_KIND_DIRECTORY))
            .cmp(&(rb.file_kind() != Some(FILE_KIND_DIRECTORY)))
            .then_with(|| {
                a.readable(GroupwareResourceRef::media_type)
                    .cmp(&b.readable(GroupwareResourceRef::media_type))
            }),
        FileNodeComparator::Tree => {
            return a
                .tree
                .iter()
                .zip(b.tree.iter())
                .map(|(x, y)| collation.compare(x, y).then_with(|| x.cmp(y)))
                .find(|ordering| *ordering != Ordering::Equal)
                .map(|ordering| {
                    if comparator.is_ascending {
                        ordering
                    } else {
                        ordering.reverse()
                    }
                })
                .unwrap_or_else(|| a.tree.len().cmp(&b.tree.len()));
        }
        FileNodeComparator::_T(_) => Ordering::Equal,
    };
    if comparator.is_ascending {
        ordering
    } else {
        ordering.reverse()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Collation {
    Octet,
    AsciiCasemap,
    UnicodeCasemap,
    AsciiNumeric,
}

impl Collation {
    fn parse(collation: Option<&str>) -> Option<Self> {
        match collation {
            None => Some(Collation::UnicodeCasemap),
            Some(collation) => hashify::map!(collation.as_bytes(), Collation,
                "i;octet" => Collation::Octet,
                "i;ascii-casemap" => Collation::AsciiCasemap,
                "i;unicode-casemap" => Collation::UnicodeCasemap,
                "i;ascii-numeric" => Collation::AsciiNumeric,
            )
            .copied(),
        }
    }

    fn compare(self, a: &str, b: &str) -> Ordering {
        match self {
            Collation::Octet => a.cmp(b),
            Collation::AsciiCasemap => a
                .bytes()
                .map(|c| c.to_ascii_lowercase())
                .cmp(b.bytes().map(|c| c.to_ascii_lowercase())),
            Collation::UnicodeCasemap if a.is_ascii() && b.is_ascii() => {
                Collation::AsciiCasemap.compare(a, b)
            }
            Collation::UnicodeCasemap => a
                .chars()
                .flat_map(char::to_lowercase)
                .cmp(b.chars().flat_map(char::to_lowercase)),
            Collation::AsciiNumeric => match (leading_number(a), leading_number(b)) {
                (Some(a), Some(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
        }
    }
}

fn leading_number(value: &str) -> Option<&str> {
    let digits = value
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .filter(|digits| !digits.is_empty())?;
    Some(digits.trim_start_matches('0'))
}

fn kind_rank(resource: &GroupwareResourceRef<'_>) -> u8 {
    match resource.file_kind() {
        Some(FILE_KIND_DIRECTORY) => 0,
        Some(FILE_KIND_FILE) => 2,
        _ => 1,
    }
}

fn tree_path<'x>(
    cache: &'x GroupwareResources,
    resource: &GroupwareResourceRef<'x>,
) -> Vec<&'x str> {
    let mut path = Vec::with_capacity(8);
    let mut current = Some(*resource);
    while let Some(node) = current {
        if path.len() >= MAX_TREE_DEPTH {
            break;
        }
        path.push(node.container_name().unwrap_or_default());
        current = node
            .parent_id()
            .and_then(|parent_id| cache.resources.find_any(parent_id));
    }
    path.reverse();
    path
}

fn all_ids(cache: &GroupwareResources) -> RoaringBitmap {
    cache.resources.iter().map(|r| r.document_id()).collect()
}

fn matching(
    cache: &GroupwareResources,
    predicate: impl Fn(&GroupwareResourceRef<'_>) -> bool,
) -> RoaringBitmap {
    cache
        .resources
        .iter()
        .filter(|r| predicate(r))
        .map(|r| r.document_id())
        .collect()
}

fn name_matching(cache: &GroupwareResources, pattern: &GlobPattern) -> RoaringBitmap {
    matching(cache, |r| {
        r.container_name().is_some_and(|n| pattern.matches(n))
    })
}

fn type_matching(cache: &GroupwareResources, pattern: &GlobPattern) -> RoaringBitmap {
    const UNKNOWN: u8 = 0;
    const MATCHES: u8 = 1;
    const DIFFERS: u8 = 2;

    let mut states = vec![UNKNOWN; MediaTypeId::UNCATALOGUED.raw() as usize];
    let mut ids = RoaringBitmap::new();
    for resource in cache.resources.iter() {
        let Some(flags) = resource.file_flags() else {
            continue;
        };
        let id = flags.media_type_id();
        let is_match = match states.get_mut(id.raw() as usize) {
            Some(state) if flags.kind() == FILE_KIND_FILE || !id.is_none() => {
                if *state == UNKNOWN {
                    *state = if resource
                        .media_type()
                        .is_some_and(|name| pattern.matches(name))
                    {
                        MATCHES
                    } else {
                        DIFFERS
                    };
                }
                *state == MATCHES
            }
            Some(_) => false,
            None => resource
                .media_type()
                .is_some_and(|name| pattern.matches(name)),
        };
        if is_match {
            ids.insert(resource.document_id());
        }
    }
    ids
}

fn descendants(cache: &GroupwareResources, document_id: u32, max_depth: usize) -> RoaringBitmap {
    let Some(root) = cache.container_resource_path_by_id(document_id) else {
        return RoaringBitmap::new();
    };
    let path = root.path();
    let iter: Box<dyn Iterator<Item = u32>> = if max_depth == usize::MAX {
        Box::new(cache.subtree(path).map(|r| r.document_id()))
    } else {
        Box::new(
            cache
                .subtree_with_depth(path, max_depth)
                .map(|r| r.document_id()),
        )
    };
    let mut ids = iter.collect::<RoaringBitmap>();
    ids.remove(document_id);
    ids
}

#[cfg(test)]
mod tests {
    use super::Collation;
    use std::cmp::Ordering;

    #[test]
    fn collations() {
        assert_eq!(Collation::parse(Some("i;unknown")), None);
        assert_eq!(Collation::Octet.compare("B", "a"), Ordering::Less);
        assert_eq!(Collation::AsciiCasemap.compare("B", "a"), Ordering::Greater);
        assert_eq!(
            Collation::UnicodeCasemap.compare("\u{c9}t\u{e9}", "\u{e9}T\u{c9}"),
            Ordering::Equal
        );
        assert_eq!(
            Collation::AsciiNumeric.compare("10", "9"),
            Ordering::Greater
        );
        assert_eq!(Collation::AsciiNumeric.compare("007", "7"), Ordering::Equal);
        assert_eq!(
            Collation::AsciiNumeric.compare("abc", "1"),
            Ordering::Greater
        );
    }
}
