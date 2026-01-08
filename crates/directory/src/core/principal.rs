/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    ArchivedPrincipal, ArchivedPrincipalData, FALLBACK_ADMIN_ID, Permission, PermissionGrant,
    Principal, PrincipalData, ROLE_ADMIN, Type,
    backend::internal::{PrincipalField, PrincipalSet, PrincipalUpdate, PrincipalValue},
};
use ahash::AHashSet;
use nlp::tokenizers::word::WordTokenizer;
use serde::{
    Deserializer, Serializer,
    de::{self, IgnoredAny, Visitor},
    ser::SerializeMap,
};
use serde_json::Value;
use std::{cmp::Ordering, collections::hash_map::Entry, fmt, str::FromStr};
use store::{
    U32_LEN, U64_LEN,
    backend::MAX_TOKEN_LENGTH,
    write::{BatchBuilder, DirectoryClass},
};

impl Principal {
    pub fn new(id: u32, typ: Type) -> Self {
        Self {
            id,
            typ,
            name: "".into(),
            data: Default::default(),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn typ(&self) -> Type {
        self.typ
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn quota(&self) -> Option<u64> {
        self.data.iter().find_map(|d| {
            if let PrincipalData::DiskQuota(quota) = d {
                if *quota > 0 { Some(*quota) } else { None }
            } else {
                None
            }
        })
    }

    pub fn directory_quota(&self, typ: &Type) -> Option<u32> {
        self.data.iter().find_map(|d| {
            if let PrincipalData::DirectoryQuota { quota, typ: qtyp } = d
                && qtyp == typ
            {
                Some(*quota)
            } else {
                None
            }
        })
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    #[cfg(feature = "enterprise")]
    pub fn tenant(&self) -> Option<u32> {
        self.data.iter().find_map(|item| {
            if let PrincipalData::Tenant(tenant) = item {
                Some(*tenant)
            } else {
                None
            }
        })
    }
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    pub fn tenant(&self) -> Option<u32> {
        None
    }

    pub fn description(&self) -> Option<&str> {
        self.data.iter().find_map(|item| {
            if let PrincipalData::Description(description) = item {
                if !description.is_empty() {
                    Some(description.as_str())
                } else {
                    None
                }
            } else {
                None
            }
        })
    }

    pub fn secret(&self) -> Option<&str> {
        if let Some(PrincipalData::Password(password)) = self.data.first() {
            Some(password.as_str())
        } else if let Some(PrincipalData::Password(password)) = self.data.get(1) {
            Some(password.as_str())
        } else {
            None
        }
    }

    pub fn primary_email(&self) -> Option<&str> {
        self.data.iter().find_map(|item| {
            if let PrincipalData::PrimaryEmail(email) = item {
                Some(email.as_str())
            } else {
                None
            }
        })
    }

    pub fn email_addresses(&self) -> impl Iterator<Item = &str> {
        let mut found_email = false;
        self.data
            .iter()
            .take_while(move |item| {
                if matches!(
                    item,
                    PrincipalData::PrimaryEmail(_) | PrincipalData::EmailAlias(_)
                ) {
                    found_email = true;
                    true
                } else {
                    !found_email
                }
            })
            .filter_map(|item| {
                if let PrincipalData::PrimaryEmail(email) | PrincipalData::EmailAlias(email) = item
                {
                    Some(email.as_str())
                } else {
                    None
                }
            })
    }

    pub fn into_primary_email(self) -> Option<String> {
        self.data.into_iter().find_map(|item| {
            if let PrincipalData::PrimaryEmail(email) = item {
                Some(email)
            } else {
                None
            }
        })
    }

    pub fn into_email_addresses(self) -> impl Iterator<Item = String> {
        self.data.into_iter().filter_map(|item| {
            if let PrincipalData::PrimaryEmail(email) | PrincipalData::EmailAlias(email) = item {
                Some(email)
            } else {
                None
            }
        })
    }

    pub fn member_of(&self) -> impl Iterator<Item = u32> {
        self.data.iter().filter_map(|item| {
            if let PrincipalData::MemberOf(item) = item {
                Some(*item)
            } else {
                None
            }
        })
    }

    pub fn roles(&self) -> impl Iterator<Item = u32> {
        self.data.iter().filter_map(|item| {
            if let PrincipalData::Role(item) = item {
                Some(*item)
            } else {
                None
            }
        })
    }

    pub fn permissions(&self) -> impl Iterator<Item = PermissionGrant> {
        self.data.iter().filter_map(|item| {
            if let PrincipalData::Permission {
                permission_id,
                grant,
            } = item
            {
                Permission::from_id(*permission_id).map(|permission| PermissionGrant {
                    permission,
                    grant: *grant,
                })
            } else {
                None
            }
        })
    }

    pub fn urls(&self) -> impl Iterator<Item = &String> {
        self.data.iter().filter_map(|item| {
            if let PrincipalData::Url(item) = item {
                Some(item)
            } else {
                None
            }
        })
    }

    pub fn lists(&self) -> impl Iterator<Item = &u32> {
        self.data.iter().filter_map(|item| {
            if let PrincipalData::List(item) = item {
                Some(item)
            } else {
                None
            }
        })
    }

    pub fn picture(&self) -> Option<&String> {
        self.data.iter().find_map(|item| {
            if let PrincipalData::Picture(picture) = item {
                picture.into()
            } else {
                None
            }
        })
    }

    pub fn picture_mut(&mut self) -> Option<&mut String> {
        self.data.iter_mut().find_map(|item| {
            if let PrincipalData::Picture(picture) = item {
                picture.into()
            } else {
                None
            }
        })
    }

    pub fn add_permission(&mut self, permission: Permission, grant: bool) {
        let permission = permission.id();
        if let Some(permissions) = self.data.iter_mut().find_map(|item| {
            if let PrincipalData::Permission {
                permission_id,
                grant,
            } = item
            {
                if *permission_id == permission {
                    Some(grant)
                } else {
                    None
                }
            } else {
                None
            }
        }) {
            *permissions = grant;
        } else {
            self.data.push(PrincipalData::Permission {
                permission_id: permission,
                grant,
            });
        }
    }

    pub fn add_permissions(&mut self, iter: impl Iterator<Item = PermissionGrant>) {
        for grant in iter {
            self.add_permission(grant.permission, grant.grant);
        }
    }

    pub fn remove_permission(&mut self, permission: Permission, grant: bool) {
        let permission = permission.id();
        self.data.retain(|data| {
            if let PrincipalData::Permission {
                permission_id: p,
                grant: g,
            } = data
            {
                *p != permission || *g != grant
            } else {
                true
            }
        });
    }

    pub fn remove_permissions(&mut self, grant: bool) {
        self.data.retain(|data| {
            if let PrincipalData::Permission { grant: g, .. } = data {
                *g != grant
            } else {
                true
            }
        });
    }

    pub fn update_external(&mut self, external: Principal) -> Vec<PrincipalUpdate> {
        let mut updates = Vec::new();
        let mut external_data = AHashSet::with_capacity(external.data.len());
        let mut has_role = false;
        let mut has_member_of = false;
        let mut has_quota = false;
        let mut has_otp_auth = false;
        let mut has_app_password = false;

        for item in external.data {
            match item {
                PrincipalData::DiskQuota(_) => {
                    has_quota = true;
                    external_data.insert(item);
                }
                PrincipalData::MemberOf(_) => {
                    has_member_of = true;
                    external_data.insert(item);
                }
                PrincipalData::Role(_) => {
                    has_role = true;
                    external_data.insert(item);
                }
                PrincipalData::OtpAuth(_) => {
                    has_otp_auth = true;
                    external_data.insert(item);
                }
                PrincipalData::AppPassword(_) => {
                    has_app_password = true;
                    external_data.insert(item);
                }
                PrincipalData::Password(_)
                | PrincipalData::Description(_)
                | PrincipalData::PrimaryEmail(_)
                | PrincipalData::EmailAlias(_) => {
                    external_data.insert(item);
                }
                _ => {}
            }
        }

        let mut old_data = Vec::new();
        let data_len = self.data.len();

        for item in std::mem::replace(&mut self.data, Vec::with_capacity(data_len)) {
            match item {
                PrincipalData::Password(_)
                | PrincipalData::AppPassword(_)
                | PrincipalData::OtpAuth(_)
                | PrincipalData::Description(_)
                | PrincipalData::PrimaryEmail(_)
                | PrincipalData::EmailAlias(_)
                | PrincipalData::DiskQuota(_)
                | PrincipalData::MemberOf(_)
                | PrincipalData::Role(_) => {
                    if external_data.remove(&item)
                        || match item {
                            PrincipalData::EmailAlias(_) => true,
                            PrincipalData::AppPassword(_) => !has_app_password,
                            PrincipalData::OtpAuth(_) => !has_otp_auth,
                            PrincipalData::Role(_) => !has_role,
                            PrincipalData::MemberOf(_) => !has_member_of,
                            PrincipalData::DiskQuota(_) => !has_quota,
                            _ => false,
                        }
                    {
                        self.data.push(item);
                    } else if matches!(
                        item,
                        PrincipalData::Password(_)
                            | PrincipalData::AppPassword(_)
                            | PrincipalData::OtpAuth(_)
                            | PrincipalData::PrimaryEmail(_)
                            | PrincipalData::EmailAlias(_)
                    ) {
                        old_data.push(item);
                    }
                }
                _ => {
                    self.data.push(item);
                }
            }
        }

        // Add new data
        let mut has_password = false;
        let mut has_email = false;
        for item in external_data {
            match &item {
                PrincipalData::Description(value) => {
                    updates.push(PrincipalUpdate::set(
                        PrincipalField::Description,
                        PrincipalValue::String(value.to_string()),
                    ));
                }
                PrincipalData::DiskQuota(value) => {
                    updates.push(PrincipalUpdate::set(
                        PrincipalField::Quota,
                        PrincipalValue::Integer(*value),
                    ));
                }
                PrincipalData::Password(value)
                | PrincipalData::AppPassword(value)
                | PrincipalData::OtpAuth(value) => {
                    let item = PrincipalUpdate::add_item(
                        PrincipalField::Secrets,
                        PrincipalValue::String(value.to_string()),
                    );
                    if !has_password && !updates.is_empty() {
                        updates.insert(0, item);
                    } else {
                        updates.push(item);
                    }
                    has_password = true;
                }
                PrincipalData::PrimaryEmail(value) => {
                    let item = PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String(value.to_string()),
                    );
                    if !has_email && !updates.is_empty() {
                        updates.insert(0, item);
                    } else {
                        updates.push(item);
                    }
                    has_email = true;
                }
                PrincipalData::EmailAlias(value) => {
                    updates.push(PrincipalUpdate::add_item(
                        PrincipalField::Emails,
                        PrincipalValue::String(value.to_string()),
                    ));
                }
                _ => (),
            }
            self.data.push(item);
        }

        // Remove old data
        for item in old_data {
            match item {
                PrincipalData::Password(value)
                | PrincipalData::AppPassword(value)
                | PrincipalData::OtpAuth(value) => {
                    updates.push(PrincipalUpdate::remove_item(
                        PrincipalField::Secrets,
                        PrincipalValue::String(value),
                    ));
                }
                PrincipalData::PrimaryEmail(value) | PrincipalData::EmailAlias(value) => {
                    updates.push(PrincipalUpdate::remove_item(
                        PrincipalField::Emails,
                        PrincipalValue::String(value),
                    ));
                }
                _ => (),
            }
        }

        self.sort();

        updates
    }

    pub fn object_size(&self) -> usize {
        self.name.len()
            + self
                .data
                .iter()
                .map(|item| item.object_size())
                .sum::<usize>()
    }

    pub fn fallback_admin(fallback_pass: impl Into<String>) -> Self {
        Principal {
            id: FALLBACK_ADMIN_ID,
            typ: Type::Individual,
            name: "Fallback Administrator".into(),
            data: vec![
                PrincipalData::Role(ROLE_ADMIN),
                PrincipalData::Password(fallback_pass.into()),
            ],
        }
    }

    pub fn sort(&mut self) {
        self.data.sort_unstable();
    }
}

impl PrincipalData {
    fn rank(&self) -> u8 {
        match self {
            PrincipalData::OtpAuth(_) => 0,
            PrincipalData::Password(_) => 1,
            PrincipalData::AppPassword(_) => 2,
            PrincipalData::PrimaryEmail(_) => 3,
            PrincipalData::EmailAlias(_) => 4,
            _ => 5,
        }
    }

    fn rank_string(&self) -> Option<&str> {
        match self {
            PrincipalData::OtpAuth(s)
            | PrincipalData::Password(s)
            | PrincipalData::AppPassword(s)
            | PrincipalData::PrimaryEmail(s)
            | PrincipalData::EmailAlias(s) => Some(s),
            _ => None,
        }
    }
}

impl PartialOrd for PrincipalData {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrincipalData {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.rank().cmp(&other.rank()) {
            Ordering::Equal => match (self.rank_string(), other.rank_string()) {
                (Some(a), Some(b)) => a.cmp(b),
                _ => Ordering::Equal,
            },
            other => other,
        }
    }
}

impl PrincipalData {
    pub fn object_size(&self) -> usize {
        match self {
            PrincipalData::Password(v)
            | PrincipalData::AppPassword(v)
            | PrincipalData::OtpAuth(v)
            | PrincipalData::Description(v)
            | PrincipalData::PrimaryEmail(v)
            | PrincipalData::EmailAlias(v)
            | PrincipalData::Picture(v)
            | PrincipalData::ExternalMember(v)
            | PrincipalData::Url(v)
            | PrincipalData::Locale(v) => v.len(),
            PrincipalData::DiskQuota(_) => U64_LEN,
            PrincipalData::Permission { .. } => U32_LEN + 1,
            PrincipalData::DirectoryQuota { .. } | PrincipalData::ObjectQuota { .. } => U64_LEN + 1,
            PrincipalData::Tenant(_)
            | PrincipalData::MemberOf(_)
            | PrincipalData::Role(_)
            | PrincipalData::List(_) => U32_LEN,
        }
    }
}

impl PrincipalSet {
    pub fn new(id: u32, typ: Type) -> Self {
        Self {
            id,
            typ,
            ..Default::default()
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn typ(&self) -> Type {
        self.typ
    }

    pub fn name(&self) -> &str {
        self.get_str(PrincipalField::Name).unwrap_or_default()
    }

    pub fn has_name(&self) -> bool {
        self.fields.contains_key(&PrincipalField::Name)
    }

    pub fn quota(&self) -> u64 {
        self.get_int(PrincipalField::Quota).unwrap_or_default()
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL
    #[cfg(feature = "enterprise")]
    pub fn tenant(&self) -> Option<u32> {
        self.get_int(PrincipalField::Tenant).map(|v| v as u32)
    }
    // SPDX-SnippetEnd

    #[cfg(not(feature = "enterprise"))]
    pub fn tenant(&self) -> Option<u32> {
        None
    }

    pub fn description(&self) -> Option<&str> {
        self.get_str(PrincipalField::Description)
    }

    pub fn get_str(&self, key: PrincipalField) -> Option<&str> {
        self.fields.get(&key).and_then(|v| v.as_str())
    }

    pub fn get_int(&self, key: PrincipalField) -> Option<u64> {
        self.fields.get(&key).and_then(|v| v.as_int())
    }

    pub fn get_str_array(&self, key: PrincipalField) -> Option<&[String]> {
        self.fields.get(&key).and_then(|v| match v {
            PrincipalValue::StringList(v) => Some(v.as_slice()),
            PrincipalValue::String(v) => Some(std::slice::from_ref(v)),
            PrincipalValue::Integer(_) | PrincipalValue::IntegerList(_) => None,
        })
    }

    pub fn get_int_array(&self, key: PrincipalField) -> Option<&[u64]> {
        self.fields.get(&key).and_then(|v| match v {
            PrincipalValue::IntegerList(v) => Some(v.as_slice()),
            PrincipalValue::Integer(v) => Some(std::slice::from_ref(v)),
            PrincipalValue::String(_) | PrincipalValue::StringList(_) => None,
        })
    }

    pub fn take(&mut self, key: PrincipalField) -> Option<PrincipalValue> {
        self.fields.remove(&key)
    }

    pub fn take_str(&mut self, key: PrincipalField) -> Option<String> {
        self.take(key).and_then(|v| match v {
            PrincipalValue::String(s) => Some(s),
            PrincipalValue::StringList(l) => l.into_iter().next(),
            PrincipalValue::Integer(i) => Some(i.to_string()),
            PrincipalValue::IntegerList(l) => l.into_iter().next().map(|i| i.to_string()),
        })
    }

    pub fn take_int(&mut self, key: PrincipalField) -> Option<u64> {
        self.take(key).and_then(|v| match v {
            PrincipalValue::Integer(i) => Some(i),
            PrincipalValue::IntegerList(l) => l.into_iter().next(),
            PrincipalValue::String(s) => s.parse().ok(),
            PrincipalValue::StringList(l) => l.into_iter().next().and_then(|s| s.parse().ok()),
        })
    }

    pub fn take_str_array(&mut self, key: PrincipalField) -> Option<Vec<String>> {
        self.take(key).map(|v| v.into_str_array())
    }

    pub fn take_int_array(&mut self, key: PrincipalField) -> Option<Vec<u64>> {
        self.take(key).map(|v| v.into_int_array())
    }

    pub fn iter_str(
        &self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = &String> + Sync + Send + '_> {
        self.fields
            .get(&key)
            .map(|v| v.iter_str())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn iter_mut_str(
        &mut self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = &mut String> + Sync + Send + '_> {
        self.fields
            .get_mut(&key)
            .map(|v| v.iter_mut_str())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn iter_int(
        &self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = u64> + Sync + Send + '_> {
        self.fields
            .get(&key)
            .map(|v| v.iter_int())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn iter_mut_int(
        &mut self,
        key: PrincipalField,
    ) -> Box<dyn Iterator<Item = &mut u64> + Sync + Send + '_> {
        self.fields
            .get_mut(&key)
            .map(|v| v.iter_mut_int())
            .unwrap_or_else(|| Box::new(std::iter::empty()))
    }

    pub fn append_int(&mut self, key: PrincipalField, value: impl Into<u64>) -> &mut Self {
        let value = value.into();
        match self.fields.entry(key) {
            Entry::Occupied(v) => {
                let v = v.into_mut();

                match v {
                    PrincipalValue::IntegerList(v) => {
                        if !v.contains(&value) {
                            v.push(value);
                        }
                    }
                    PrincipalValue::Integer(i) => {
                        if value != *i {
                            *v = PrincipalValue::IntegerList(vec![*i, value]);
                        }
                    }
                    PrincipalValue::String(s) => {
                        *v =
                            PrincipalValue::IntegerList(vec![s.parse().unwrap_or_default(), value]);
                    }
                    PrincipalValue::StringList(l) => {
                        *v = PrincipalValue::IntegerList(
                            l.iter()
                                .map(|s| s.parse().unwrap_or_default())
                                .chain(std::iter::once(value))
                                .collect(),
                        );
                    }
                }
            }
            Entry::Vacant(v) => {
                v.insert(PrincipalValue::IntegerList(vec![value]));
            }
        }

        self
    }

    pub fn append_str(&mut self, key: PrincipalField, value: impl Into<String>) -> &mut Self {
        let value = value.into();
        match self.fields.entry(key) {
            Entry::Occupied(v) => {
                let v = v.into_mut();

                match v {
                    PrincipalValue::StringList(v) => {
                        if !v.contains(&value) {
                            v.push(value);
                        }
                    }
                    PrincipalValue::String(s) => {
                        if s != &value {
                            *v = PrincipalValue::StringList(vec![std::mem::take(s), value]);
                        }
                    }
                    PrincipalValue::Integer(i) => {
                        *v = PrincipalValue::StringList(vec![i.to_string(), value]);
                    }
                    PrincipalValue::IntegerList(l) => {
                        *v = PrincipalValue::StringList(
                            l.iter()
                                .map(|i| i.to_string())
                                .chain(std::iter::once(value))
                                .collect(),
                        );
                    }
                }
            }
            Entry::Vacant(v) => {
                v.insert(PrincipalValue::StringList(vec![value]));
            }
        }
        self
    }

    pub fn prepend_str(&mut self, key: PrincipalField, value: impl Into<String>) -> &mut Self {
        let value = value.into();
        match self.fields.entry(key) {
            Entry::Occupied(v) => {
                let v = v.into_mut();

                match v {
                    PrincipalValue::StringList(v) => {
                        if !v.contains(&value) {
                            v.insert(0, value);
                        }
                    }
                    PrincipalValue::String(s) => {
                        if s != &value {
                            *v = PrincipalValue::StringList(vec![value, std::mem::take(s)]);
                        }
                    }
                    PrincipalValue::Integer(i) => {
                        *v = PrincipalValue::StringList(vec![value, i.to_string()]);
                    }
                    PrincipalValue::IntegerList(l) => {
                        *v = PrincipalValue::StringList(
                            std::iter::once(value)
                                .chain(l.iter().map(|i| i.to_string()))
                                .collect(),
                        );
                    }
                }
            }
            Entry::Vacant(v) => {
                v.insert(PrincipalValue::StringList(vec![value]));
            }
        }
        self
    }

    pub fn set(&mut self, key: PrincipalField, value: impl Into<PrincipalValue>) -> &mut Self {
        self.fields.insert(key, value.into());
        self
    }

    pub fn with_field(mut self, key: PrincipalField, value: impl Into<PrincipalValue>) -> Self {
        self.set(key, value);
        self
    }

    pub fn with_opt_field(
        mut self,
        key: PrincipalField,
        value: Option<impl Into<PrincipalValue>>,
    ) -> Self {
        if let Some(value) = value {
            self.set(key, value);
        }
        self
    }

    pub fn has_field(&self, key: PrincipalField) -> bool {
        self.fields.contains_key(&key)
    }

    pub fn has_str_value(&self, key: PrincipalField, value: &str) -> bool {
        self.fields.get(&key).is_some_and(|v| match v {
            PrincipalValue::String(v) => v == value,
            PrincipalValue::StringList(l) => l.iter().any(|v| v == value),
            PrincipalValue::Integer(_) | PrincipalValue::IntegerList(_) => false,
        })
    }

    pub fn has_int_value(&self, key: PrincipalField, value: u64) -> bool {
        self.fields.get(&key).is_some_and(|v| match v {
            PrincipalValue::Integer(v) => *v == value,
            PrincipalValue::IntegerList(l) => l.contains(&value),
            PrincipalValue::String(_) | PrincipalValue::StringList(_) => false,
        })
    }

    pub fn find_str(&self, value: &str) -> bool {
        self.fields.values().any(|v| v.find_str(value))
    }

    pub fn field_len(&self, key: PrincipalField) -> usize {
        self.fields.get(&key).map_or(0, |v| match v {
            PrincipalValue::String(_) => 1,
            PrincipalValue::StringList(l) => l.len(),
            PrincipalValue::Integer(_) => 1,
            PrincipalValue::IntegerList(l) => l.len(),
        })
    }

    pub fn remove(&mut self, key: PrincipalField) -> Option<PrincipalValue> {
        self.fields.remove(&key)
    }

    pub fn retain_str<F>(&mut self, key: PrincipalField, mut f: F)
    where
        F: FnMut(&String) -> bool,
    {
        if let Some(value) = self.fields.get_mut(&key) {
            match value {
                PrincipalValue::String(s) => {
                    if !f(s) {
                        self.fields.remove(&key);
                    }
                }
                PrincipalValue::StringList(l) => {
                    l.retain(f);
                    if l.is_empty() {
                        self.fields.remove(&key);
                    }
                }
                _ => {}
            }
        }
    }

    pub fn retain_int<F>(&mut self, key: PrincipalField, mut f: F)
    where
        F: FnMut(&u64) -> bool,
    {
        if let Some(value) = self.fields.get_mut(&key) {
            match value {
                PrincipalValue::Integer(i) => {
                    if !f(i) {
                        self.fields.remove(&key);
                    }
                }
                PrincipalValue::IntegerList(l) => {
                    l.retain(f);
                    if l.is_empty() {
                        self.fields.remove(&key);
                    }
                }
                _ => {}
            }
        }
    }
}

impl PrincipalValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PrincipalValue::String(v) => Some(v.as_str()),
            PrincipalValue::StringList(v) => v.first().map(|s| s.as_str()),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<u64> {
        match self {
            PrincipalValue::Integer(v) => Some(*v),
            PrincipalValue::IntegerList(v) => v.first().copied(),
            _ => None,
        }
    }

    pub fn iter_str(&self) -> Box<dyn Iterator<Item = &String> + Sync + Send + '_> {
        match self {
            PrincipalValue::String(v) => Box::new(std::iter::once(v)),
            PrincipalValue::StringList(v) => Box::new(v.iter()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn iter_mut_str(&mut self) -> Box<dyn Iterator<Item = &mut String> + Sync + Send + '_> {
        match self {
            PrincipalValue::String(v) => Box::new(std::iter::once(v)),
            PrincipalValue::StringList(v) => Box::new(v.iter_mut()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn iter_int(&self) -> Box<dyn Iterator<Item = u64> + Sync + Send + '_> {
        match self {
            PrincipalValue::Integer(v) => Box::new(std::iter::once(*v)),
            PrincipalValue::IntegerList(v) => Box::new(v.iter().copied()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn iter_mut_int(&mut self) -> Box<dyn Iterator<Item = &mut u64> + Sync + Send + '_> {
        match self {
            PrincipalValue::Integer(v) => Box::new(std::iter::once(v)),
            PrincipalValue::IntegerList(v) => Box::new(v.iter_mut()),
            _ => Box::new(std::iter::empty()),
        }
    }

    pub fn into_array(self) -> Self {
        match self {
            PrincipalValue::String(v) => PrincipalValue::StringList(vec![v]),
            PrincipalValue::Integer(v) => PrincipalValue::IntegerList(vec![v]),
            v => v,
        }
    }

    pub fn into_str_array(self) -> Vec<String> {
        match self {
            PrincipalValue::StringList(v) => v,
            PrincipalValue::String(v) => vec![v],
            PrincipalValue::Integer(v) => vec![v.to_string()],
            PrincipalValue::IntegerList(v) => v.into_iter().map(|v| v.to_string()).collect(),
        }
    }

    pub fn into_int_array(self) -> Vec<u64> {
        match self {
            PrincipalValue::IntegerList(v) => v,
            PrincipalValue::Integer(v) => vec![v],
            PrincipalValue::String(v) => vec![v.parse().unwrap_or_default()],
            PrincipalValue::StringList(v) => v
                .into_iter()
                .map(|v| v.parse().unwrap_or_default())
                .collect(),
        }
    }

    pub fn serialized_size(&self) -> usize {
        match self {
            PrincipalValue::String(s) => s.len() + 2,
            PrincipalValue::StringList(s) => s.iter().map(|s| s.len() + 2).sum(),
            PrincipalValue::Integer(_) => U64_LEN,
            PrincipalValue::IntegerList(l) => l.len() * U64_LEN,
        }
    }

    pub fn find_str(&self, value: &str) -> bool {
        match self {
            PrincipalValue::String(s) => s.to_lowercase().contains(value),
            PrincipalValue::StringList(l) => l.iter().any(|s| s.to_lowercase().contains(value)),
            _ => false,
        }
    }
}

impl From<u64> for PrincipalValue {
    fn from(v: u64) -> Self {
        Self::Integer(v)
    }
}

impl From<String> for PrincipalValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for PrincipalValue {
    fn from(v: &str) -> Self {
        Self::String(v.into())
    }
}

impl From<Vec<String>> for PrincipalValue {
    fn from(v: Vec<String>) -> Self {
        Self::StringList(v)
    }
}

impl From<Vec<u64>> for PrincipalValue {
    fn from(v: Vec<u64>) -> Self {
        Self::IntegerList(v)
    }
}

impl From<u32> for PrincipalValue {
    fn from(v: u32) -> Self {
        Self::Integer(v as u64)
    }
}

impl From<Vec<u32>> for PrincipalValue {
    fn from(v: Vec<u32>) -> Self {
        Self::IntegerList(v.into_iter().map(|v| v as u64).collect())
    }
}

pub(crate) fn build_search_index(
    batch: &mut BatchBuilder,
    principal_id: u32,
    current: Option<&ArchivedPrincipal>,
    new: Option<&Principal>,
) {
    let mut current_words = AHashSet::new();
    let mut new_words = AHashSet::new();

    if let Some(current) = current {
        for word in [Some(current.name.as_str())]
            .into_iter()
            .chain(current.data.iter().map(|s| match s {
                ArchivedPrincipalData::Description(v)
                | ArchivedPrincipalData::PrimaryEmail(v)
                | ArchivedPrincipalData::EmailAlias(v) => Some(v.as_str()),
                _ => None,
            }))
            .flatten()
        {
            current_words.extend(WordTokenizer::new(word, MAX_TOKEN_LENGTH).map(|t| t.word));
        }
    }

    if let Some(new) = new {
        for word in [Some(new.name.as_str())]
            .into_iter()
            .chain(new.data.iter().map(|s| match s {
                PrincipalData::Description(v)
                | PrincipalData::PrimaryEmail(v)
                | PrincipalData::EmailAlias(v) => Some(v.as_str()),
                _ => None,
            }))
            .flatten()
        {
            new_words.extend(WordTokenizer::new(word, MAX_TOKEN_LENGTH).map(|t| t.word));
        }
    }

    for word in new_words.difference(&current_words) {
        batch.set(
            DirectoryClass::Index {
                word: word.as_bytes().to_vec(),
                principal_id,
            },
            vec![],
        );
    }

    for word in current_words.difference(&new_words) {
        batch.clear(DirectoryClass::Index {
            word: word.as_bytes().to_vec(),
            principal_id,
        });
    }
}

impl Type {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::Group => "group",
            Self::Resource => "resource",
            Self::Location => "location",
            Self::Other => "other",
            Self::List => "list",
            Self::Tenant => "tenant",
            Self::Role => "role",
            Self::Domain => "domain",
            Self::ApiKey => "apiKey",
            Self::OauthClient => "oauthClient",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Individual => "Individual",
            Self::Group => "Group",
            Self::Resource => "Resource",
            Self::Location => "Location",
            Self::Tenant => "Tenant",
            Self::List => "List",
            Self::Other => "Other",
            Self::Role => "Role",
            Self::Domain => "Domain",
            Self::ApiKey => "API Key",
            Self::OauthClient => "OAuth Client",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "individual" => Some(Type::Individual),
            "group" => Some(Type::Group),
            "resource" => Some(Type::Resource),
            "location" => Some(Type::Location),
            "list" => Some(Type::List),
            "tenant" => Some(Type::Tenant),
            "superuser" => Some(Type::Individual), // legacy
            "role" => Some(Type::Role),
            "domain" => Some(Type::Domain),
            "apiKey" => Some(Type::ApiKey),
            "oauthClient" => Some(Type::OauthClient),
            _ => None,
        }
    }

    pub const MAX_ID: usize = 11;

    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Type::Individual,
            1 => Type::Group,
            2 => Type::Resource,
            3 => Type::Location,
            4 => Type::Other, // legacy
            5 => Type::List,
            6 => Type::Other,
            7 => Type::Domain,
            8 => Type::Tenant,
            9 => Type::Role,
            10 => Type::ApiKey,
            11 => Type::OauthClient,
            _ => Type::Other,
        }
    }
}

impl FromStr for Type {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Type::parse(s).ok_or(())
    }
}

impl serde::Serialize for PrincipalSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("type", &self.typ.as_str())?;

        for (key, value) in &self.fields {
            match value {
                PrincipalValue::String(v) => map.serialize_entry(key.as_str(), v)?,
                PrincipalValue::StringList(v) => map.serialize_entry(key.as_str(), v)?,
                PrincipalValue::Integer(v) => map.serialize_entry(key.as_str(), v)?,
                PrincipalValue::IntegerList(v) => map.serialize_entry(key.as_str(), v)?,
            };
        }

        map.end()
    }
}

const MAX_STRING_LEN: usize = 512;

impl<'de> serde::Deserialize<'de> for PrincipalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PrincipalValueVisitor;

        impl<'de> Visitor<'de> for PrincipalValueVisitor {
            type Value = PrincipalValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an optional values or a sequence of values")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PrincipalValue::String("".into()))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(PrincipalValue::Integer(value))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(PrincipalValue::String(value))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(PrincipalValue::String(value.into()))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let mut vec_u64 = Vec::new();
                let mut vec_string = Vec::new();

                while let Some(value) = seq.next_element::<StringOrU64>()? {
                    match value {
                        StringOrU64::String(s) => {
                            if s.len() <= MAX_STRING_LEN {
                                vec_string.push(s);
                            } else {
                                return Err(serde::de::Error::custom("string too long"));
                            }
                        }
                        StringOrU64::U64(u) => vec_u64.push(u),
                    }
                }

                match (vec_u64.is_empty(), vec_string.is_empty()) {
                    (true, false) => Ok(PrincipalValue::StringList(vec_string)),
                    (false, true) => Ok(PrincipalValue::IntegerList(vec_u64)),
                    (true, true) => Ok(PrincipalValue::StringList(vec_string)),
                    _ => Err(serde::de::Error::custom("invalid principal value")),
                }
            }
        }

        deserializer.deserialize_any(PrincipalValueVisitor)
    }
}

impl<'de> serde::Deserialize<'de> for PrincipalSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PrincipalVisitor;

        // Deserialize the principal
        impl<'de> Visitor<'de> for PrincipalVisitor {
            type Value = PrincipalSet;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid principal")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: de::MapAccess<'de>,
            {
                let mut principal = PrincipalSet::default();

                while let Some(key) = map.next_key::<&str>()? {
                    if key == "id" {
                        // Ignored
                        map.next_value::<IgnoredAny>()?;
                        continue;
                    }

                    let key = PrincipalField::try_parse(key).ok_or_else(|| {
                        serde::de::Error::custom(format!("invalid principal field: {}", key))
                    })?;

                    let value = match key {
                        PrincipalField::Name => {
                            PrincipalValue::String(map.next_value::<String>().and_then(|v| {
                                if v.len() <= MAX_STRING_LEN {
                                    Ok(v)
                                } else {
                                    Err(serde::de::Error::custom("string too long"))
                                }
                            })?)
                        }
                        PrincipalField::Description
                        | PrincipalField::Tenant
                        | PrincipalField::Picture
                        | PrincipalField::Locale => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                if v.len() <= MAX_STRING_LEN {
                                    PrincipalValue::String(v)
                                } else {
                                    return Err(serde::de::Error::custom("string too long"));
                                }
                            } else {
                                continue;
                            }
                        }
                        PrincipalField::Type => {
                            principal.typ = Type::parse(map.next_value()?).ok_or_else(|| {
                                serde::de::Error::custom("invalid principal type")
                            })?;
                            continue;
                        }
                        PrincipalField::Quota => map.next_value::<PrincipalValue>()?,
                        PrincipalField::Secrets
                        | PrincipalField::Emails
                        | PrincipalField::MemberOf
                        | PrincipalField::Members
                        | PrincipalField::Roles
                        | PrincipalField::Lists
                        | PrincipalField::EnabledPermissions
                        | PrincipalField::DisabledPermissions
                        | PrincipalField::Urls
                        | PrincipalField::ExternalMembers => match map.next_value::<Value>()? {
                            Value::String(v) => {
                                if v.len() <= MAX_STRING_LEN {
                                    PrincipalValue::StringList(vec![v])
                                } else {
                                    return Err(serde::de::Error::custom("string too long"));
                                }
                            }
                            Value::Array(v) => {
                                if !v.is_empty() {
                                    PrincipalValue::StringList(
                                        v.into_iter()
                                            .filter_map(|item| {
                                                if let Value::String(s) = item {
                                                    if s.len() <= MAX_STRING_LEN {
                                                        Some(s)
                                                    } else {
                                                        None
                                                    }
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect(),
                                    )
                                } else {
                                    continue;
                                }
                            }
                            _ => continue,
                        },
                        PrincipalField::UsedQuota => {
                            // consume and ignore
                            map.next_value::<IgnoredAny>()?;
                            continue;
                        }
                    };

                    principal.fields.insert(key, value);
                }

                Ok(principal)
            }
        }

        deserializer.deserialize_map(PrincipalVisitor)
    }
}

#[derive(Debug)]
enum StringOrU64 {
    String(String),
    U64(u64),
}

impl<'de> serde::Deserialize<'de> for StringOrU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StringOrU64Visitor;

        impl Visitor<'_> for StringOrU64Visitor {
            type Value = StringOrU64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or u64")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() <= MAX_STRING_LEN {
                    Ok(StringOrU64::String(value.to_string()))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() <= MAX_STRING_LEN {
                    Ok(StringOrU64::String(v))
                } else {
                    Err(serde::de::Error::custom("string too long"))
                }
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StringOrU64::U64(value))
            }
        }

        deserializer.deserialize_any(StringOrU64Visitor)
    }
}

impl Permission {
    pub fn all() -> impl Iterator<Item = Permission> {
        (0..Permission::COUNT as u32).filter_map(Permission::from_id)
    }

    pub const fn is_user_permission(&self) -> bool {
        matches!(
            self,
            Permission::Authenticate
                | Permission::AuthenticateOauth
                | Permission::EmailSend
                | Permission::EmailReceive
                | Permission::ManageEncryption
                | Permission::ManagePasswords
                | Permission::JmapEmailGet
                | Permission::JmapMailboxGet
                | Permission::JmapThreadGet
                | Permission::JmapIdentityGet
                | Permission::JmapEmailSubmissionGet
                | Permission::JmapPushSubscriptionGet
                | Permission::JmapSieveScriptGet
                | Permission::JmapVacationResponseGet
                | Permission::JmapQuotaGet
                | Permission::JmapBlobGet
                | Permission::JmapEmailSet
                | Permission::JmapMailboxSet
                | Permission::JmapIdentitySet
                | Permission::JmapEmailSubmissionSet
                | Permission::JmapPushSubscriptionSet
                | Permission::JmapSieveScriptSet
                | Permission::JmapVacationResponseSet
                | Permission::JmapEmailChanges
                | Permission::JmapMailboxChanges
                | Permission::JmapThreadChanges
                | Permission::JmapIdentityChanges
                | Permission::JmapEmailSubmissionChanges
                | Permission::JmapQuotaChanges
                | Permission::JmapEmailCopy
                | Permission::JmapBlobCopy
                | Permission::JmapEmailImport
                | Permission::JmapEmailParse
                | Permission::JmapEmailQueryChanges
                | Permission::JmapMailboxQueryChanges
                | Permission::JmapEmailSubmissionQueryChanges
                | Permission::JmapSieveScriptQueryChanges
                | Permission::JmapQuotaQueryChanges
                | Permission::JmapEmailQuery
                | Permission::JmapMailboxQuery
                | Permission::JmapEmailSubmissionQuery
                | Permission::JmapSieveScriptQuery
                | Permission::JmapQuotaQuery
                | Permission::JmapSearchSnippet
                | Permission::JmapSieveScriptValidate
                | Permission::JmapBlobLookup
                | Permission::JmapBlobUpload
                | Permission::JmapEcho
                | Permission::ImapAuthenticate
                | Permission::ImapAclGet
                | Permission::ImapAclSet
                | Permission::ImapMyRights
                | Permission::ImapListRights
                | Permission::ImapAppend
                | Permission::ImapCapability
                | Permission::ImapId
                | Permission::ImapCopy
                | Permission::ImapMove
                | Permission::ImapCreate
                | Permission::ImapDelete
                | Permission::ImapEnable
                | Permission::ImapExpunge
                | Permission::ImapFetch
                | Permission::ImapIdle
                | Permission::ImapList
                | Permission::ImapLsub
                | Permission::ImapNamespace
                | Permission::ImapRename
                | Permission::ImapSearch
                | Permission::ImapSort
                | Permission::ImapSelect
                | Permission::ImapExamine
                | Permission::ImapStatus
                | Permission::ImapStore
                | Permission::ImapSubscribe
                | Permission::ImapThread
                | Permission::Pop3Authenticate
                | Permission::Pop3List
                | Permission::Pop3Uidl
                | Permission::Pop3Stat
                | Permission::Pop3Retr
                | Permission::Pop3Dele
                | Permission::SieveAuthenticate
                | Permission::SieveListScripts
                | Permission::SieveSetActive
                | Permission::SieveGetScript
                | Permission::SievePutScript
                | Permission::SieveDeleteScript
                | Permission::SieveRenameScript
                | Permission::SieveCheckScript
                | Permission::SieveHaveSpace
                | Permission::DavSyncCollection
                | Permission::DavExpandProperty
                | Permission::DavPrincipalAcl
                | Permission::DavPrincipalList
                | Permission::DavPrincipalSearch
                | Permission::DavPrincipalMatch
                | Permission::DavPrincipalSearchPropSet
                | Permission::DavFilePropFind
                | Permission::DavFilePropPatch
                | Permission::DavFileGet
                | Permission::DavFileMkCol
                | Permission::DavFileDelete
                | Permission::DavFilePut
                | Permission::DavFileCopy
                | Permission::DavFileMove
                | Permission::DavFileLock
                | Permission::DavFileAcl
                | Permission::DavCardPropFind
                | Permission::DavCardPropPatch
                | Permission::DavCardGet
                | Permission::DavCardMkCol
                | Permission::DavCardDelete
                | Permission::DavCardPut
                | Permission::DavCardCopy
                | Permission::DavCardMove
                | Permission::DavCardLock
                | Permission::DavCardAcl
                | Permission::DavCardQuery
                | Permission::DavCardMultiGet
                | Permission::DavCalPropFind
                | Permission::DavCalPropPatch
                | Permission::DavCalGet
                | Permission::DavCalMkCol
                | Permission::DavCalDelete
                | Permission::DavCalPut
                | Permission::DavCalCopy
                | Permission::DavCalMove
                | Permission::DavCalLock
                | Permission::DavCalAcl
                | Permission::DavCalQuery
                | Permission::DavCalMultiGet
                | Permission::DavCalFreeBusyQuery
                | Permission::CalendarAlarms
                | Permission::CalendarSchedulingSend
                | Permission::CalendarSchedulingReceive
                | Permission::JmapAddressBookGet
                | Permission::JmapAddressBookSet
                | Permission::JmapAddressBookChanges
                | Permission::JmapContactCardGet
                | Permission::JmapContactCardChanges
                | Permission::JmapContactCardQuery
                | Permission::JmapContactCardQueryChanges
                | Permission::JmapContactCardSet
                | Permission::JmapContactCardCopy
                | Permission::JmapContactCardParse
                | Permission::JmapFileNodeGet
                | Permission::JmapFileNodeSet
                | Permission::JmapFileNodeChanges
                | Permission::JmapFileNodeQuery
                | Permission::JmapFileNodeQueryChanges
                | Permission::JmapPrincipalGetAvailability
                | Permission::JmapPrincipalChanges
                | Permission::JmapPrincipalQuery
                | Permission::JmapPrincipalGet
                | Permission::JmapPrincipalQueryChanges
                | Permission::JmapShareNotificationGet
                | Permission::JmapShareNotificationSet
                | Permission::JmapShareNotificationChanges
                | Permission::JmapShareNotificationQuery
                | Permission::JmapShareNotificationQueryChanges
                | Permission::JmapCalendarGet
                | Permission::JmapCalendarSet
                | Permission::JmapCalendarChanges
                | Permission::JmapCalendarEventGet
                | Permission::JmapCalendarEventSet
                | Permission::JmapCalendarEventChanges
                | Permission::JmapCalendarEventQuery
                | Permission::JmapCalendarEventQueryChanges
                | Permission::JmapCalendarEventCopy
                | Permission::JmapCalendarEventParse
                | Permission::JmapCalendarEventNotificationGet
                | Permission::JmapCalendarEventNotificationSet
                | Permission::JmapCalendarEventNotificationChanges
                | Permission::JmapCalendarEventNotificationQuery
                | Permission::JmapCalendarEventNotificationQueryChanges
                | Permission::JmapParticipantIdentityGet
                | Permission::JmapParticipantIdentitySet
                | Permission::JmapParticipantIdentityChanges
        )
    }

    #[cfg(not(feature = "enterprise"))]
    pub const fn is_tenant_admin_permission(&self) -> bool {
        false
    }

    // SPDX-SnippetBegin
    // SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
    // SPDX-License-Identifier: LicenseRef-SEL

    #[cfg(feature = "enterprise")]
    pub const fn is_tenant_admin_permission(&self) -> bool {
        matches!(
            self,
            Permission::MessageQueueList
                | Permission::MessageQueueGet
                | Permission::MessageQueueUpdate
                | Permission::MessageQueueDelete
                | Permission::OutgoingReportList
                | Permission::OutgoingReportGet
                | Permission::OutgoingReportDelete
                | Permission::IncomingReportList
                | Permission::IncomingReportGet
                | Permission::IncomingReportDelete
                | Permission::IndividualList
                | Permission::IndividualGet
                | Permission::IndividualUpdate
                | Permission::IndividualDelete
                | Permission::IndividualCreate
                | Permission::GroupList
                | Permission::GroupGet
                | Permission::GroupUpdate
                | Permission::GroupDelete
                | Permission::GroupCreate
                | Permission::DomainList
                | Permission::DomainGet
                | Permission::DomainCreate
                | Permission::DomainUpdate
                | Permission::DomainDelete
                | Permission::MailingListList
                | Permission::MailingListGet
                | Permission::MailingListCreate
                | Permission::MailingListUpdate
                | Permission::MailingListDelete
                | Permission::RoleList
                | Permission::RoleGet
                | Permission::RoleCreate
                | Permission::RoleUpdate
                | Permission::RoleDelete
                | Permission::PrincipalList
                | Permission::PrincipalGet
                | Permission::PrincipalCreate
                | Permission::PrincipalUpdate
                | Permission::PrincipalDelete
                | Permission::Undelete
                | Permission::DkimSignatureCreate
                | Permission::DkimSignatureGet
                | Permission::ApiKeyList
                | Permission::ApiKeyGet
                | Permission::ApiKeyCreate
                | Permission::ApiKeyUpdate
                | Permission::ApiKeyDelete
                | Permission::SpamFilterTrain
                | Permission::SpamFilterTest
        ) || self.is_user_permission()
    }

    // SPDX-SnippetEnd
}
