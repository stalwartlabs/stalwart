/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{MetadataContainers, MetadataPatches};
use jmap_proto::{
    object::metadata::{MetadataProperty, MetadataRoot},
    request::MaybeInvalid,
};
use jmap_tools::{Element, Value};
use store::roaring::RoaringBitmap;
use types::{id::Id, metadata::MetadataKinds};
use utils::map::vec_map::VecMap;

#[derive(Debug, Default)]
pub struct MetadataPreload {
    pub(super) shared: RoaringBitmap,
    pub(super) private: RoaringBitmap,
}

#[derive(Debug, Default)]
pub struct PreloadedContainers {
    pub shared: MetadataContainers,
    pub private: MetadataContainers,
}

impl MetadataPreload {
    pub(super) fn from_updates<P, E>(
        updates: Option<&VecMap<MaybeInvalid<Id>, Value<'_, P, E>>>,
        stored: impl Fn(u32) -> Option<MetadataKinds>,
    ) -> Self
    where
        P: MetadataProperty,
        E: Element<Property = P>,
    {
        let mut preload = MetadataPreload::default();
        for (id, object) in updates.into_iter().flat_map(VecMap::iter) {
            if let MaybeInvalid::Value(id) = id
                && let Some(kinds) = stored(id.document_id())
                && let Some(object) = object.as_object()
            {
                for root in object
                    .keys()
                    .filter_map(|key| key.as_property().and_then(MetadataProperty::metadata_root))
                {
                    preload.add_root(id.document_id(), root, kinds);
                }
            }
        }
        preload
    }

    pub fn insert(&mut self, document_id: u32, patches: &MetadataPatches, stored: MetadataKinds) {
        if patches.has_shared() {
            self.add_root(document_id, MetadataRoot::Shared, stored);
        }
        if patches.has_private() {
            self.add_root(document_id, MetadataRoot::Private, stored);
        }
    }

    pub fn insert_source(&mut self, document_id: u32, stored: MetadataKinds) {
        self.add_root(document_id, MetadataRoot::Shared, stored);
        self.add_root(document_id, MetadataRoot::Private, stored);
    }

    fn add_root(&mut self, document_id: u32, root: MetadataRoot, stored: MetadataKinds) {
        match root {
            MetadataRoot::Shared if !stored.is_empty() => {
                self.shared.insert(document_id);
            }
            MetadataRoot::Private => {
                self.private.insert(document_id);
            }
            MetadataRoot::Shared => {}
        }
    }

    pub fn is_empty(&self) -> bool {
        self.shared.is_empty() && self.private.is_empty()
    }
}
