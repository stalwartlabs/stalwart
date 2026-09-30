/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::PropFindItem;
use crate::common::dead::{ContainerRequest, DeadContainers};
use common::{DavResourcePath, Server, auth::AccessToken, storage::dav::DISPLAY_NAME_PROPERTY};
use dav_proto::schema::{
    property::{DavProperty, WebDavProperty},
    request::DavPropertyValue,
};
use groupware::calendar::privacy::EventPrivacy;
use store::write::metadata::MetadataBuf;
use types::{collection::Collection, metadata::MetadataKinds};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DeadPresence {
    properties: bool,
    display_name: bool,
    is_private: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DeadDemand {
    pub properties: bool,
    pub display_name: bool,
}

impl DeadPresence {
    pub fn from_resource(resource: &DavResourcePath<'_>) -> Self {
        let resource = resource.resource;
        match resource.file_flags() {
            Some(flags) => {
                let presence = flags.presence();
                DeadPresence {
                    properties: presence.has_dead_properties(),
                    display_name: presence.has_dav_display_name(),
                    is_private: false,
                }
            }
            None => DeadPresence {
                properties: resource.metadata_kinds().intersects(MetadataKinds::DAV),
                display_name: false,
                is_private: resource
                    .event_flags()
                    .is_some_and(|flags| !EventPrivacy::from_flags(flags).is_public()),
            },
        }
    }

    pub fn is_hidden_from(&self, access_token: &AccessToken, account_id: u32) -> bool {
        self.is_private && !access_token.is_member(account_id)
    }
}

impl DeadDemand {
    pub fn new(
        properties: &[DavProperty],
        is_allprop: bool,
        is_propname: bool,
        collection: Collection,
    ) -> Self {
        let is_file = collection == Collection::FileNode;
        DeadDemand {
            properties: is_allprop
                || is_propname
                || properties
                    .iter()
                    .any(|property| matches!(property, DavProperty::Dead(_))),
            display_name: is_file
                && (is_allprop
                    || properties.iter().any(|property| {
                        matches!(property, DavProperty::WebDav(WebDavProperty::DisplayName))
                    })),
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.properties && !self.display_name
    }

    fn wants(&self, item: &PropFindItem) -> bool {
        (self.properties && item.dead.properties && !item.is_discover_only)
            || (self.display_name && item.dead.display_name)
    }

    pub async fn load(
        &self,
        server: &Server,
        access_token: &AccessToken,
        items: &[PropFindItem],
        collection_of: impl Fn(&PropFindItem) -> Collection,
    ) -> trc::Result<DeadContainers> {
        if self.is_empty() {
            return Ok(DeadContainers::default());
        }
        let mut request = ContainerRequest::default();
        for item in items {
            if self.wants(item) && !item.dead.is_hidden_from(access_token, item.account_id) {
                request.insert(item.account_id, collection_of(item), item.document_id);
            }
        }
        if request.is_empty() {
            Ok(DeadContainers::default())
        } else {
            request.load(server).await
        }
    }
}

pub(crate) fn dead_properties(
    container: &MetadataBuf,
    collection: Collection,
) -> impl Iterator<Item = DavPropertyValue> + '_ {
    let skip_display_name = collection == Collection::FileNode;
    container
        .view()
        .dav()
        .filter(move |(name, _)| !(skip_display_name && *name == DISPLAY_NAME_PROPERTY))
        .map(|(name, value)| {
            DavPropertyValue::new(DavProperty::Dead(name.into_owned()), value.to_encoded())
        })
}

pub(crate) fn dead_property_names(
    container: &MetadataBuf,
    collection: Collection,
) -> impl Iterator<Item = DavPropertyValue> + '_ {
    let skip_display_name = collection == Collection::FileNode;
    container
        .view()
        .dav()
        .filter(move |(name, _)| !(skip_display_name && *name == DISPLAY_NAME_PROPERTY))
        .map(|(name, _)| DavPropertyValue::empty(DavProperty::Dead(name.into_owned())))
}
