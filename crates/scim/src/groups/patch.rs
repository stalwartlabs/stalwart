/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::ScimConditional,
    context::{ScimContext, group_account, parse_id},
    error::Result,
    groups,
    request::respond_with_etag,
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::StatusCode;
use registry::schema::{enums::Permission, prelude::Object, structs::GroupAccount};
use scim_proto::{
    etag::weak_etag,
    filter::EqualityTerm,
    message::{
        error::Error,
        patch::{PatchOp, PatchOperation, PatchRequest},
        search::SearchRequest,
    },
    schema::{
        Mutability,
        group::{GROUP_SCHEMA, MEMBER_TYPE_USER, Member, TOLERATED_GROUP_ATTRIBUTES},
    },
};
use serde::Deserialize;
use serde_json::Value;
use types::id::Id;

impl ScimContext<'_> {
    pub async fn group_patch(
        &self,
        req: &HttpRequest,
        id: Id,
        body: &[u8],
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let patch = PatchRequest::parse(body)?;
        let old_object = self.account(id).await?;
        let current_members = self.group_member_ids(id).await?;

        group_account(&old_object)?;
        req.scim_assert_if_match(&weak_etag(groups::version(
            old_object.revision,
            &current_members,
        )))?;

        let (updated, member_ids) = self
            .group_apply_patch(id, &patch, &old_object, current_members)
            .await?;
        let object = updated.as_ref().unwrap_or(&old_object);
        let resource = self.group_render(id, object, &member_ids, request).await?;

        respond_with_etag(
            StatusCode::OK,
            &resource,
            weak_etag(groups::version(object.revision, &member_ids)),
        )
    }

    pub async fn group_apply_patch(
        &self,
        id: Id,
        patch: &PatchRequest<'_>,
        old_object: &Object,
        current_members: Vec<Id>,
    ) -> Result<(Option<Object>, Vec<Id>)> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let mut account = group_account(old_object)?.clone();
        let mut members = current_members.clone();

        for operation in &patch.operations {
            self.apply_group_operation(id, &mut account, &mut members, operation)
                .await?;
        }

        let member_ids = self.set_members(id, &members, &current_members).await?;
        let object = match self.group_write(id, account, old_object).await {
            Ok(object) => object,
            Err(error) => {
                self.set_members(id, &current_members, &member_ids)
                    .await
                    .ok();

                return Err(error);
            }
        };

        Ok((object, member_ids))
    }

    async fn apply_group_operation(
        &self,
        id: Id,
        account: &mut GroupAccount,
        members: &mut Vec<Id>,
        operation: &PatchOperation<'_>,
    ) -> Result<()> {
        let path = &operation.path;
        if TOLERATED_GROUP_ATTRIBUTES
            .iter()
            .any(|name| path.attr.eq_ignore_ascii_case(name))
        {
            return Ok(());
        }

        let attribute = GROUP_SCHEMA.resolve_patch_path(path)?;

        if attribute.mutability == Mutability::ReadOnly {
            return Err(Error::mutability(format!(
                "The attribute '{path}' is read-only and cannot be modified."
            ))
            .into());
        }

        let is_remove = operation.op == PatchOp::Remove;
        let attr = path.attr.as_ref();

        if path.filter.is_some() && !attr.eq_ignore_ascii_case("members") {
            return Err(Error::invalid_path(format!(
                "Value filters are not supported on the attribute '{path}'."
            ))
            .into());
        }

        if attr.eq_ignore_ascii_case("displayName") {
            if is_remove {
                return Err(Error::invalid_value(
                    "The 'displayName' attribute is required and cannot be removed.",
                )
                .into());
            }

            let display_name = value_as_str(operation)?;
            if !groups::display_name(account).eq_ignore_ascii_case(display_name) {
                self.assert_display_name_available(display_name, Some(id))
                    .await?;
            }
            account.description = Some(display_name.to_string());

            Ok(())
        } else if attr.eq_ignore_ascii_case("externalId") {
            account.external_id = if is_remove {
                None
            } else {
                Some(value_as_str(operation)?.to_string())
            };
            Ok(())
        } else if attr.eq_ignore_ascii_case("members") {
            if path.filter.is_none() && path.sub_attr.is_some() {
                return Err(Error::invalid_path(format!(
                    "The path '{path}' must select an element with a value filter."
                ))
                .into());
            }

            self.patch_members(members, operation).await
        } else {
            Err(Error::invalid_path(format!(
                "The attribute '{path}' cannot be modified through this endpoint."
            ))
            .into())
        }
    }

    async fn patch_members(
        &self,
        members: &mut Vec<Id>,
        operation: &PatchOperation<'_>,
    ) -> Result<()> {
        if let Some(filter) = &operation.path.filter {
            let terms = filter.clone().into_equality_terms()?;
            let mut matched = Vec::new();
            for member in members.iter() {
                if matches(&terms, *member)? {
                    matched.push(*member);
                }
            }

            if matched.is_empty() {
                return Err(Error::no_target(
                    "The value filter did not match any 'members' element.",
                )
                .into());
            } else if operation.op != PatchOp::Remove {
                return Err(Error::invalid_path(
                    "Only 'remove' operations may target an existing 'members' element.",
                )
                .into());
            }

            members.retain(|member| !matched.contains(member));

            return Ok(());
        }

        match operation.op {
            PatchOp::Remove => {
                let requested = self
                    .resolve_members(&deserialize_members(operation)?)
                    .await?;
                if requested.is_empty() {
                    members.clear();
                } else {
                    members.retain(|member| !requested.contains(member));
                }
            }
            PatchOp::Replace => {
                *members = self
                    .resolve_members(&deserialize_members(operation)?)
                    .await?;
            }
            PatchOp::Add => {
                for member in self
                    .resolve_members(&deserialize_members(operation)?)
                    .await?
                {
                    if !members.contains(&member) {
                        members.push(member);
                    }
                }
            }
        }

        Ok(())
    }
}

fn matches(terms: &[EqualityTerm<'_>], member: Id) -> Result<bool> {
    for term in terms {
        let attr = term.path.attr.as_ref();
        let matches = if attr.eq_ignore_ascii_case("value") {
            term.value.as_str().and_then(|value| parse_id(value).ok()) == Some(member)
        } else if attr.eq_ignore_ascii_case("type") {
            term.value
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(MEMBER_TYPE_USER))
        } else if attr.eq_ignore_ascii_case("display") || attr.eq_ignore_ascii_case("$ref") {
            false
        } else {
            return Err(Error::invalid_filter(format!(
                "Unknown sub-attribute '{}' in the 'members' value filter.",
                term.path
            ))
            .into());
        };

        if !matches {
            return Ok(false);
        }
    }

    Ok(true)
}

fn deserialize_members<'x>(operation: &'x PatchOperation<'x>) -> Result<Vec<Member<'x>>> {
    match operation.value.as_ref() {
        Some(Value::Array(_)) => deserialize::<Vec<Member<'x>>>(operation),
        Some(_) => deserialize::<Member<'x>>(operation).map(|member| vec![member]),
        None => Ok(Vec::new()),
    }
}

fn deserialize<'x, T: Deserialize<'x>>(operation: &'x PatchOperation<'x>) -> Result<T> {
    let value = operation
        .value
        .as_ref()
        .ok_or_else(|| Error::invalid_syntax("Missing 'value' attribute."))?;

    T::deserialize(value).map_err(|err| {
        Error::invalid_syntax(format!(
            "Invalid value for the attribute '{}': {err}",
            operation.path
        ))
        .into()
    })
}

fn value_as_str<'x>(operation: &'x PatchOperation<'x>) -> Result<&'x str> {
    operation.value_as_str().ok_or_else(|| {
        Error::invalid_value(format!(
            "The attribute '{}' requires a string value.",
            operation.path
        ))
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scim_proto::filter::Filter;

    fn parse_terms(filter: &str) -> Vec<EqualityTerm<'static>> {
        Filter::parse(filter)
            .unwrap()
            .into_owned()
            .into_equality_terms()
            .unwrap()
    }

    #[test]
    fn member_filters_select_by_identifier() {
        let member = Id::new(42);
        let terms = parse_terms(&format!(r#"value eq "{member}""#));

        assert!(matches(&terms, member).unwrap());
        assert!(!matches(&terms, Id::new(43)).unwrap());
    }

    #[test]
    fn member_filters_accept_the_user_type() {
        let member = Id::new(42);

        assert!(matches(&parse_terms(r#"type eq "User""#), member).unwrap());
        assert!(matches(&parse_terms(r#"type eq "user""#), member).unwrap());
        assert!(!matches(&parse_terms(r#"type eq "Group""#), member).unwrap());
    }

    #[test]
    fn unsupported_sub_attributes_never_match() {
        assert!(!matches(&parse_terms(r#"display eq "Babs""#), Id::new(42)).unwrap());
        assert!(matches(&parse_terms(r#"nosuch eq "x""#), Id::new(42)).is_err());
    }

    #[test]
    fn a_malformed_identifier_never_matches() {
        assert!(!matches(&parse_terms(r#"value eq "!!!""#), Id::new(42)).unwrap());
    }
}
