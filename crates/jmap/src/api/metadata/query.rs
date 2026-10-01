/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::MetadataSupport;
use common::Server;
use jmap_proto::object::metadata::{MetadataCondition, MetadataFilter, MetadataRoot};
use memchr::memmem::Finder;
use store::roaring::RoaringBitmap;
use types::{
    collation::unicode_casemap,
    collection::Collection,
    metadata::{MetadataKinds, MetadataView, Namespace, RegisteredNamespace},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateCandidates {
    pub viewer_id: u32,
    pub containers: u32,
}

#[derive(Debug)]
pub struct MetadataQuery {
    collection: Collection,
    max_scan: usize,
    leaves: Vec<QueryLeaf>,
}

#[derive(Debug)]
struct QueryLeaf {
    root: MetadataRoot,
    target: Option<LeafTarget>,
    condition: LeafCondition,
}

#[derive(Debug)]
struct LeafTarget {
    namespace: LeafNamespace,
    key: Option<Box<str>>,
}

#[derive(Debug)]
enum LeafNamespace {
    Registered(&'static RegisteredNamespace),
    Vendor(Box<str>),
}

#[derive(Debug)]
enum LeafCondition {
    Exists,
    Contains(Box<Finder<'static>>),
    Equals(Box<str>),
}

impl MetadataQuery {
    pub fn new<'x>(
        support: Option<&MetadataSupport>,
        filters: impl IntoIterator<Item = &'x MetadataFilter>,
    ) -> trc::Result<Self> {
        let mut filters = filters.into_iter().peekable();
        let Some(support) = support else {
            return match filters.peek() {
                Some(filter) => Err(unsupported_filter(filter.as_str())),
                None => Ok(MetadataQuery {
                    collection: Collection::None,
                    max_scan: 0,
                    leaves: Vec::new(),
                }),
            };
        };

        let mut scratch = String::new();
        let leaves = filters
            .map(|filter| QueryLeaf::new(support, filter, &mut scratch))
            .collect::<trc::Result<Vec<_>>>()?;

        Ok(MetadataQuery {
            collection: support.object_type().collection(),
            max_scan: support.query_max_scan,
            leaves,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn has_shared(&self) -> bool {
        self.searches(MetadataRoot::Shared)
    }

    pub fn has_private(&self) -> bool {
        self.searches(MetadataRoot::Private)
    }

    pub async fn evaluate(
        &self,
        server: &Server,
        account_id: u32,
        shared: &RoaringBitmap,
        private: Option<PrivateCandidates>,
    ) -> trc::Result<Vec<RoaringBitmap>> {
        self.check_scan_limit(MetadataRoot::Shared, shared.len())?;
        if let Some(private) = private {
            self.check_scan_limit(MetadataRoot::Private, u64::from(private.containers))?;
        }

        let mut results = vec![RoaringBitmap::new(); self.leaves.len()];
        let mut scratch = String::new();
        if self.has_shared() && !shared.is_empty() {
            server
                .metadata_containers(
                    account_id,
                    self.collection,
                    shared,
                    |document_id, view, _| {
                        self.evaluate_container(
                            MetadataRoot::Shared,
                            document_id,
                            &view,
                            &mut results,
                            &mut scratch,
                        );
                        Ok(true)
                    },
                )
                .await?;
        }
        if let Some(private) = private
            && self.has_private()
        {
            let mut scanned = 0u64;
            server
                .all_private_metadata_containers(
                    account_id,
                    private.viewer_id,
                    self.collection,
                    |document_id, view, _| {
                        scanned += 1;
                        self.check_scan_limit(MetadataRoot::Private, scanned)?;
                        self.evaluate_container(
                            MetadataRoot::Private,
                            document_id,
                            &view,
                            &mut results,
                            &mut scratch,
                        );
                        Ok(true)
                    },
                )
                .await?;
        }

        Ok(results)
    }

    pub(super) fn evaluate_container(
        &self,
        root: MetadataRoot,
        document_id: u32,
        view: &MetadataView<'_>,
        results: &mut [RoaringBitmap],
        scratch: &mut String,
    ) {
        if view.kinds().contains(MetadataKinds::JMAP) {
            for (leaf, result) in self.leaves.iter().zip(results.iter_mut()) {
                if leaf.root == root && leaf.matches(view, scratch) {
                    result.insert(document_id);
                }
            }
        }
    }

    fn searches(&self, root: MetadataRoot) -> bool {
        self.leaves
            .iter()
            .any(|leaf| leaf.root == root && leaf.target.is_some())
    }

    pub(super) fn check_scan_limit(&self, root: MetadataRoot, candidates: u64) -> trc::Result<()> {
        if candidates > self.max_scan as u64
            && let Some(leaf) = self.leaves.iter().find(|leaf| {
                leaf.root == root
                    && leaf.target.is_some()
                    && !matches!(leaf.condition, LeafCondition::Exists)
            })
        {
            Err(trc::JmapEvent::UnsupportedFilter
                .into_err()
                .details(format!(
                    "{} is limited to {} candidates.",
                    leaf.name(),
                    self.max_scan
                )))
        } else {
            Ok(())
        }
    }
}

impl QueryLeaf {
    fn new(
        support: &MetadataSupport,
        filter: &MetadataFilter,
        scratch: &mut String,
    ) -> trc::Result<Self> {
        if filter.root() == MetadataRoot::Private && !support.supports_private() {
            return Err(unsupported_filter(filter.as_str()));
        }
        let (root, path, condition) = match filter {
            MetadataFilter::Condition {
                root,
                path,
                condition,
            } => (*root, path, condition),
            MetadataFilter::Invalid { name, reason, .. } => {
                return Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details(format!("Invalid {name} condition: {reason}")));
            }
        };

        let target = Namespace::parse(&path.namespace)
            .ok()
            .filter(|namespace| support.is_supported(namespace, root))
            .map(|namespace| LeafTarget {
                namespace: match namespace {
                    Namespace::Registered(namespace) => LeafNamespace::Registered(namespace),
                    Namespace::Vendor(name) => LeafNamespace::Vendor(name.into()),
                },
                key: path.key.clone(),
            });
        let condition = match condition {
            MetadataCondition::Exists => LeafCondition::Exists,
            MetadataCondition::TextContains(text) => {
                scratch.clear();
                unicode_casemap(text, scratch);
                LeafCondition::Contains(Box::new(Finder::new(scratch.as_bytes()).into_owned()))
            }
            MetadataCondition::TextEquals(text) => LeafCondition::Equals(text.as_str().into()),
        };

        Ok(QueryLeaf {
            root,
            target,
            condition,
        })
    }

    fn matches(&self, view: &MetadataView<'_>, scratch: &mut String) -> bool {
        let Some(target) = &self.target else {
            return false;
        };
        let Some(namespace) = view.jmap_namespace(&target.namespace.as_namespace()) else {
            return false;
        };
        let Some(key) = &target.key else {
            return matches!(self.condition, LeafCondition::Exists) && !namespace.is_empty_object();
        };
        let Some(value) = namespace.get(key) else {
            return false;
        };

        match &self.condition {
            LeafCondition::Exists => true,
            LeafCondition::Contains(needle) => value.as_str().is_some_and(|text| {
                scratch.clear();
                unicode_casemap(text, scratch);
                needle.find(scratch.as_bytes()).is_some()
            }),
            LeafCondition::Equals(expected) => value.as_str() == Some(&**expected),
        }
    }

    fn name(&self) -> &'static str {
        match (self.root, &self.condition) {
            (MetadataRoot::Shared, LeafCondition::Exists) => "metadataExists",
            (MetadataRoot::Shared, LeafCondition::Contains(_)) => "metadataTextContains",
            (MetadataRoot::Shared, LeafCondition::Equals(_)) => "metadataTextEquals",
            (MetadataRoot::Private, LeafCondition::Exists) => "privateMetadataExists",
            (MetadataRoot::Private, LeafCondition::Contains(_)) => "privateMetadataTextContains",
            (MetadataRoot::Private, LeafCondition::Equals(_)) => "privateMetadataTextEquals",
        }
    }
}

impl LeafNamespace {
    fn as_namespace(&self) -> Namespace<'_> {
        match self {
            LeafNamespace::Registered(namespace) => Namespace::Registered(namespace),
            LeafNamespace::Vendor(name) => Namespace::Vendor(name),
        }
    }
}

fn unsupported_filter(name: &'static str) -> trc::Error {
    trc::JmapEvent::UnsupportedFilter.into_err().details(name)
}
