/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub mod get;
pub mod patch;
pub mod set;

use crate::{context::ScimContext, error::Result, query::MAX_RESULTS};
use registry::{
    schema::{
        enums::AccountType,
        prelude::{ObjectType, Property},
        structs::GroupAccount,
    },
    types::EnumImpl,
};
use scim_proto::{
    ResourceType,
    attributes::AttributeSelection,
    etag::weak_etag,
    message::error::Error,
    schema::{
        Meta,
        group::{GROUP_SCHEMA, Group, MEMBER_TYPE_USER, Member},
    },
};
use serde_json::Value;
use store::registry::RegistryQuery;
use trc::AddContext;
use types::id::Id;

impl ScimContext<'_> {
    pub async fn group_member_ids(&self, group_id: Id) -> Result<Vec<Id>> {
        self.server
            .registry()
            .query::<Vec<Id>>(
                RegistryQuery::new(ObjectType::Account)
                    .with_tenant(self.tenant_id())
                    .equal(Property::Type, AccountType::User.to_id())
                    .equal(Property::MemberGroupIds, group_id.id()),
            )
            .await
            .caused_by(trc::location!())
            .map_err(Into::into)
    }

    pub async fn group_to_scim(
        &self,
        id: Id,
        revision: u64,
        account: &GroupAccount,
        member_ids: &[Id],
        selection: &AttributeSelection<'_>,
    ) -> Result<Value> {
        let members = if selection.excludes(&GROUP_SCHEMA, "members") {
            None
        } else if member_ids.len() > MAX_RESULTS {
            return Err(Error::too_many(format!(
                "This Group has more than {MAX_RESULTS} members, request it with \
                 '?excludedAttributes=members' and read the membership from the User resources."
            ))
            .into());
        } else if member_ids.is_empty() {
            Some(Vec::new())
        } else {
            let mut members = Vec::with_capacity(member_ids.len());
            for member_id in member_ids {
                let display =
                    self.server
                        .try_account(member_id.document_id())
                        .await?
                        .map(|member| {
                            member
                                .description
                                .as_deref()
                                .unwrap_or_else(|| member.name.as_ref())
                                .to_string()
                        });

                members.push(Member {
                    value: Some(member_id.to_string().into()),
                    ref_: Some(self.location(ResourceType::User, *member_id).into()),
                    display: display.map(Into::into),
                    r#type: Some(MEMBER_TYPE_USER.into()),
                });
            }
            Some(members)
        };

        let group = Group {
            id: Some(id.to_string().into()),
            external_id: account.external_id.as_deref().map(Into::into),
            display_name: Some(display_name(account).into()),
            members,
            meta: Some(
                Meta::new(ResourceType::Group)
                    .with_created(account.created_at.to_string())
                    .with_location(self.location(ResourceType::Group, id))
                    .with_version(weak_etag(version(revision, member_ids))),
            ),
        };

        let mut value = serde_json::to_value(&group).unwrap_or(Value::Null);
        selection.apply(&GROUP_SCHEMA, &mut value);

        Ok(value)
    }
}

pub fn display_name(account: &GroupAccount) -> &str {
    account
        .description
        .as_deref()
        .unwrap_or(account.name.as_str())
}

pub fn version(revision: u64, member_ids: &[Id]) -> u64 {
    let mut ids = member_ids.iter().map(Id::id).collect::<Vec<_>>();
    ids.sort_unstable();

    let mut buffer = Vec::with_capacity((ids.len() + 1) * std::mem::size_of::<u64>());
    buffer.extend_from_slice(&revision.to_be_bytes());
    for id in ids {
        buffer.extend_from_slice(&id.to_be_bytes());
    }

    xxhash_rust::xxh3::xxh3_64(&buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_covers_the_membership() {
        let revision = 0x1234_5678;
        let empty = version(revision, &[]);
        let one = version(revision, &[Id::new(1)]);
        let two = version(revision, &[Id::new(1), Id::new(2)]);

        assert_ne!(empty, one);
        assert_ne!(one, two);
        assert_ne!(version(revision + 1, &[Id::new(1)]), one);
    }

    #[test]
    fn the_version_is_independent_of_the_member_order() {
        let members = [Id::new(7), Id::new(3), Id::new(9)];
        let reversed = [Id::new(9), Id::new(3), Id::new(7)];

        assert_eq!(version(1, &members), version(1, &reversed));
    }
}
