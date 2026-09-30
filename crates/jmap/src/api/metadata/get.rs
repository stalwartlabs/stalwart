/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MetadataSupport;
use common::Server;
use jmap_proto::object::metadata::{MetadataProperty, MetadataRoot, MetadataSelection, Selection};
use jmap_tools::{Element, Key, Map, Value};
use std::mem;
use store::roaring::RoaringBitmap;
use types::{
    collection::Collection,
    metadata::{MetadataKinds, MetadataView, Namespace},
};

#[derive(Debug, Default)]
pub struct MetadataDocuments {
    shared: RoaringBitmap,
    requested: RoaringBitmap,
    pub(super) repeated: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataGet {
    collection: Collection,
    pub(super) shared: Selection,
    pub(super) private: Selection,
}

type Outputs<P, E> = Vec<(u32, Value<'static, P, E>)>;

#[derive(Debug)]
pub struct MetadataValues<P: MetadataProperty, E: Element<Property = P>> {
    shared: Option<Outputs<P, E>>,
    private: Option<Outputs<P, E>>,
    repeated: Vec<u32>,
}

impl MetadataDocuments {
    pub fn insert(&mut self, document_id: u32, kinds: MetadataKinds) {
        if !self.requested.insert(document_id) {
            self.repeated.push(document_id);
        }
        if kinds.contains(MetadataKinds::JMAP) {
            self.shared.insert(document_id);
        }
    }

    pub fn shared(&self) -> &RoaringBitmap {
        &self.shared
    }

    pub fn requested(&self) -> &RoaringBitmap {
        &self.requested
    }
}

impl MetadataGet {
    pub fn new(support: Option<&MetadataSupport>, selection: MetadataSelection) -> Option<Self> {
        let support = support?;
        let get = MetadataGet {
            collection: support.object_type().collection(),
            shared: storable(selection.shared),
            private: if support.supports_private() {
                storable(selection.private)
            } else {
                Selection::None
            },
        };
        (!get.shared.is_none() || !get.private.is_none()).then_some(get)
    }

    pub fn wants_shared(&self) -> bool {
        !self.shared.is_none()
    }

    pub fn wants_private(&self) -> bool {
        !self.private.is_none()
    }

    pub async fn load<P, E>(
        &self,
        server: &Server,
        account_id: u32,
        private_viewer: Option<u32>,
        documents: &MetadataDocuments,
    ) -> trc::Result<MetadataValues<P, E>>
    where
        P: MetadataProperty + Send + Sync,
        E: Element<Property = P> + Send + Sync,
    {
        let shared = if self.wants_shared() {
            let mut outputs = Vec::new();
            if !documents.shared.is_empty() {
                server
                    .metadata_containers(
                        account_id,
                        self.collection,
                        &documents.shared,
                        |document_id, view, _| {
                            push_output(&self.shared, document_id, &view, &mut outputs);
                            Ok(true)
                        },
                    )
                    .await?;
            }
            Some(outputs)
        } else {
            None
        };

        let private = match private_viewer {
            Some(viewer_id) if self.wants_private() && !documents.requested.is_empty() => {
                let mut outputs = Vec::new();
                server
                    .private_metadata_containers(
                        account_id,
                        viewer_id,
                        self.collection,
                        &documents.requested,
                        |document_id, view, _| {
                            push_output(&self.private, document_id, &view, &mut outputs);
                            Ok(true)
                        },
                    )
                    .await?;
                Some(outputs)
            }
            _ => self.wants_private().then(Vec::new),
        };

        Ok(MetadataValues::new(
            shared,
            private,
            documents.repeated.clone(),
        ))
    }
}

fn storable(mut selection: Selection) -> Selection {
    if let Selection::Namespaces(names) = &mut selection {
        names.retain(|name| Namespace::parse(name).is_ok());
    }
    selection
}

pub(super) fn push_output<P, E>(
    selection: &Selection,
    document_id: u32,
    view: &MetadataView<'_>,
    outputs: &mut Outputs<P, E>,
) where
    P: MetadataProperty,
    E: Element<Property = P>,
{
    let mut output = Map::new();
    for (namespace, value) in view.jmap() {
        if selection.contains(namespace.name())
            && let Some(value) = value.to_value::<P, E>()
        {
            let key = match namespace {
                Namespace::Registered(namespace) => Key::Borrowed(namespace.name),
                Namespace::Vendor(name) => Key::Owned(name.to_string()),
            };
            output.insert_unchecked(key, value.into_owned());
        }
    }
    if !output.is_empty() {
        outputs.push((document_id, Value::Object(output)));
    }
}

impl<P, E> MetadataValues<P, E>
where
    P: MetadataProperty,
    E: Element<Property = P>,
{
    pub(super) fn new(
        shared: Option<Outputs<P, E>>,
        private: Option<Outputs<P, E>>,
        mut repeated: Vec<u32>,
    ) -> Self {
        repeated.sort_unstable();
        repeated.dedup();
        MetadataValues {
            shared: shared.map(sorted),
            private: private.map(sorted),
            repeated,
        }
    }

    pub fn insert_into(&mut self, document_id: u32, object: &mut Map<'_, P, E>) {
        let is_repeated = self.repeated.binary_search(&document_id).is_ok();
        for (root, outputs) in [
            (MetadataRoot::Shared, self.shared.as_mut()),
            (MetadataRoot::Private, self.private.as_mut()),
        ] {
            if let Some(outputs) = outputs {
                object.insert_unchecked(
                    P::from_metadata_root(root),
                    take_output(outputs, document_id, is_repeated),
                );
            }
        }
    }
}

fn sorted<T>(mut outputs: Vec<(u32, T)>) -> Vec<(u32, T)> {
    if !outputs.is_sorted_by_key(|(document_id, _)| *document_id) {
        outputs.sort_unstable_by_key(|(document_id, _)| *document_id);
    }
    outputs
}

fn take_output<P, E>(
    outputs: &mut [(u32, Value<'static, P, E>)],
    document_id: u32,
    is_repeated: bool,
) -> Value<'static, P, E>
where
    P: MetadataProperty,
    E: Element<Property = P>,
{
    let output = outputs
        .binary_search_by_key(&document_id, |(document_id, _)| *document_id)
        .ok()
        .and_then(|position| outputs.get_mut(position))
        .map(|(_, output)| output);
    match output {
        Some(output) if is_repeated => output.clone(),
        Some(output) => mem::replace(output, Value::Object(Map::new())),
        None => Value::Object(Map::new()),
    }
}
