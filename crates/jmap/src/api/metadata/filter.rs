/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::GroupwareResources;
use jmap_proto::{method::query::Filter, request::deserialize::DeserializeArguments};
use store::{
    roaring::RoaringBitmap,
    search::{SearchFilter, SearchQuery},
    write::SearchIndex,
};
use types::metadata::MetadataKinds;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceScope {
    Containers,
    Items,
    All,
}

impl ResourceScope {
    fn includes(self, is_container: bool) -> bool {
        match self {
            ResourceScope::Containers => is_container,
            ResourceScope::Items => !is_container,
            ResourceScope::All => true,
        }
    }
}

pub fn flagged_documents(
    cache: &GroupwareResources,
    scope: ResourceScope,
    readable: Option<&RoaringBitmap>,
) -> RoaringBitmap {
    cache
        .resources
        .iter()
        .filter(|resource| {
            scope.includes(resource.is_container())
                && resource.metadata_kinds().contains(MetadataKinds::JMAP)
                && readable.is_none_or(|readable| readable.contains(resource.document_id()))
        })
        .map(|resource| resource.document_id())
        .collect()
}

pub fn filter_containers<F>(
    filters: &[Filter<F>],
    leaves: Vec<RoaringBitmap>,
    readable: RoaringBitmap,
) -> RoaringBitmap
where
    F: for<'de> DeserializeArguments<'de> + Default,
{
    if filters.is_empty() {
        return readable;
    }
    let mut leaves = leaves.into_iter();
    let filters = filters
        .iter()
        .map(|filter| match filter {
            Filter::Property(_) => SearchFilter::is_in_set(leaves.next().unwrap_or_default()),
            Filter::And => SearchFilter::And,
            Filter::Or => SearchFilter::Or,
            Filter::Not => SearchFilter::Not,
            Filter::Close => SearchFilter::End,
        })
        .collect();
    SearchQuery::new(SearchIndex::InMemory)
        .with_filters(filters)
        .with_mask(readable)
        .filter()
        .into_bitmap()
}
