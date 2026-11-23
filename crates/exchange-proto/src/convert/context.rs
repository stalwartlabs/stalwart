/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use crate::{
    common::Guid,
    ids::{ReplGuid, essdn::OrgDn},
};

pub trait AddressResolver {
    fn resolve(&self, smtp: &str) -> Option<ResolvedAddress<'_>>;
    fn resolve_dn(&self, essdn: &str) -> Option<ResolvedAddress<'_>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAddress<'r> {
    pub display_name: Cow<'r, str>,
    pub smtp: Cow<'r, str>,
    pub essdn: Cow<'r, str>,
    pub object_type: u32,
    pub display_type: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoDirectory;

impl AddressResolver for NoDirectory {
    fn resolve(&self, _smtp: &str) -> Option<ResolvedAddress<'_>> {
        None
    }

    fn resolve_dn(&self, _essdn: &str) -> Option<ResolvedAddress<'_>> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct ConvertOptions<'o> {
    pub org_dn: &'o OrgDn,
    pub store: Option<StoreIds>,
    pub body_preference: BodyPreference,
    pub tnef: TnefPolicy,
    pub max_decoded: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreIds {
    pub store_guid: Guid,
    pub replguid: ReplGuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPreference {
    Html,
    Text,
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TnefPolicy {
    Ignore,
    Decode,
}
