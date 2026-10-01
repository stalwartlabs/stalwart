/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod apply;
mod copy;
mod filter;
mod get;
mod object;
mod patch;
mod preload;
mod prepared;
mod query;
mod reject;
mod validate;
mod violation;
mod write;
mod writer;

#[cfg(test)]
mod tests;

pub use common::storage::metadata::MetadataContainers;
pub use filter::{ResourceScope, filter_containers, flagged_documents};
pub use get::{MetadataDocuments, MetadataGet, MetadataValues};
pub use object::ObjectMetadata;
pub use patch::{MetadataPatches, is_empty_update};
pub use preload::{MetadataPreload, PreloadedContainers};
pub use prepared::PreparedMetadata;
pub use query::{MetadataQuery, PrivateCandidates};
pub use reject::reject_uncommitted;
pub use validate::{MetadataAccess, ValidatedPatches};
pub use write::MetadataUpdate;
pub use writer::{MetadataTarget, MetadataWriter, NewMetadata};

use common::{
    auth::AccessToken, config::metadata::MetadataConfig, storage::metadata::MetadataViewer,
};
use jmap_proto::{
    method::get::GetRequest,
    object::{
        JmapObject,
        metadata::{MetadataProperty, MetadataRoot, MetadataSelection},
    },
    request::capability::{Capability, CapabilityIds},
};
use registry::schema::enums::Permission;
use types::{
    collection::Collection,
    metadata::{MetadataLimits, MetadataScope, Namespace},
    type_state::DataType,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetadataType {
    Email,
    Mailbox,
    SieveScript,
    Calendar,
    CalendarEvent,
    AddressBook,
    ContactCard,
    FileNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetadataSupport {
    object: MetadataType,
    vendor_namespaces: bool,
    private: bool,
    writable: bool,
    limits: MetadataLimits,
    query_max_scan: usize,
}

impl MetadataType {
    pub fn data_type(self) -> DataType {
        match self {
            MetadataType::Email => DataType::Email,
            MetadataType::Mailbox => DataType::Mailbox,
            MetadataType::SieveScript => DataType::SieveScript,
            MetadataType::Calendar => DataType::Calendar,
            MetadataType::CalendarEvent => DataType::CalendarEvent,
            MetadataType::AddressBook => DataType::AddressBook,
            MetadataType::ContactCard => DataType::ContactCard,
            MetadataType::FileNode => DataType::FileNode,
        }
    }

    pub fn collection(self) -> Collection {
        match self {
            MetadataType::Email => Collection::Email,
            MetadataType::Mailbox => Collection::Mailbox,
            MetadataType::SieveScript => Collection::SieveScript,
            MetadataType::Calendar => Collection::Calendar,
            MetadataType::CalendarEvent => Collection::CalendarEvent,
            MetadataType::AddressBook => Collection::AddressBook,
            MetadataType::ContactCard => Collection::ContactCard,
            MetadataType::FileNode => Collection::FileNode,
        }
    }
}

impl MetadataSupport {
    pub fn new(
        config: &MetadataConfig,
        access_token: &AccessToken,
        object: MetadataType,
        viewer: Option<MetadataViewer>,
    ) -> Option<Self> {
        (config.data_types.contains(object.data_type())
            && access_token.has_permission(Permission::JmapMetadataGet))
        .then(|| MetadataSupport {
            object,
            vendor_namespaces: config.vendor_namespaces,
            private: viewer.is_some(),
            writable: access_token.has_permission(Permission::JmapMetadataSet),
            limits: config.limits(),
            query_max_scan: config.query_max_scan,
        })
    }

    pub fn object_type(&self) -> MetadataType {
        self.object
    }

    pub fn supports_private(&self) -> bool {
        self.private
    }

    pub fn is_supported(&self, namespace: &Namespace<'_>, root: MetadataRoot) -> bool {
        match namespace {
            Namespace::Registered(namespace) => {
                namespace.is_writable()
                    && namespace.supports(self.object.data_type(), metadata_scope(root))
            }
            Namespace::Vendor(_) => self.vendor_namespaces,
        }
    }
}

fn uses_metadata(using: CapabilityIds) -> bool {
    using.contains(Capability::Metadata)
}

pub fn select_properties<T>(
    request: &mut GetRequest<T>,
    defaults: &[T::Property],
    using: CapabilityIds,
) -> trc::Result<(Vec<T::Property>, MetadataSelection)>
where
    T: JmapObject,
    T::Property: MetadataProperty,
{
    if request.properties.is_none() {
        let selection = if uses_metadata(using) {
            MetadataSelection::all()
        } else {
            MetadataSelection::default()
        };
        Ok((request.unwrap_properties(defaults), selection))
    } else {
        let mut properties = request.unwrap_properties(defaults);
        MetadataSelection::extract(&mut properties).map(|selection| (properties, selection))
    }
}

fn metadata_scope(root: MetadataRoot) -> MetadataScope {
    match root {
        MetadataRoot::Shared => MetadataScope::Shared,
        MetadataRoot::Private => MetadataScope::Private,
    }
}
