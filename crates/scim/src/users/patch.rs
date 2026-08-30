/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    auth::ScimConditional,
    context::{ScimContext, user_account},
    error::Result,
    request::respond_with_etag,
    users,
};
use http_proto::{HttpRequest, HttpResponse};
use hyper::StatusCode;
use registry::schema::{enums::Permission, prelude::Object, structs::UserAccount};
use scim_proto::{
    etag::weak_etag,
    filter::EqualityTerm,
    message::{
        error::Error,
        patch::{PatchOp, PatchOperation, PatchRequest},
        search::SearchRequest,
    },
    path::PatchPath,
    schema::{
        Mutability,
        user::{
            Email, Name, TOLERATED_NAME_ATTRIBUTES, TOLERATED_USER_ATTRIBUTES,
            TOLERATED_USER_SCHEMAS, USER_SCHEMA,
        },
    },
};
use serde::Deserialize;
use serde_json::Value;
use types::id::Id;

impl ScimContext<'_> {
    pub async fn user_patch(
        &self,
        req: &HttpRequest,
        id: Id,
        body: &[u8],
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let patch = PatchRequest::parse(body)?;
        let old_object = self.account(id).await?;

        user_account(&old_object)?;
        req.scim_assert_if_match(&weak_etag(old_object.revision))?;

        let updated = self.user_apply_patch(id, &patch, &old_object).await?;
        let object = updated.as_ref().unwrap_or(&old_object);
        let resource = self.user_render(id, object, request).await?;

        respond_with_etag(StatusCode::OK, &resource, weak_etag(object.revision))
    }

    pub async fn user_apply_patch(
        &self,
        id: Id,
        patch: &PatchRequest<'_>,
        old_object: &Object,
    ) -> Result<Option<Object>> {
        self.assert_permission(Permission::SysAccountUpdate)?;

        let mut account = user_account(old_object)?.clone();

        for operation in &patch.operations {
            self.apply_user_operation(id, &mut account, operation)
                .await?;
        }

        self.user_write(id, account, old_object).await
    }

    async fn apply_user_operation(
        &self,
        id: Id,
        account: &mut UserAccount,
        operation: &PatchOperation<'_>,
    ) -> Result<()> {
        let path = &operation.path;
        if is_tolerated_path(path) {
            return Ok(());
        }

        let attribute = USER_SCHEMA.resolve_patch_path(path)?;

        if attribute.mutability == Mutability::ReadOnly {
            return Err(Error::mutability(format!(
                "The attribute '{path}' is read-only and cannot be modified."
            ))
            .into());
        }

        let is_remove = operation.op == PatchOp::Remove;
        let attr = path.attr.as_ref();

        if path.filter.is_some() && !attr.eq_ignore_ascii_case("emails") {
            return Err(Error::invalid_path(format!(
                "Value filters are not supported on the attribute '{path}'."
            ))
            .into());
        }

        if attr.eq_ignore_ascii_case("userName") {
            if is_remove {
                return Err(
                    Error::invalid_value("The 'userName' attribute cannot be removed.").into(),
                );
            }
            self.set_user_name(account, as_str(operation)?).await
        } else if attr.eq_ignore_ascii_case("externalId") {
            account.external_id = if is_remove {
                None
            } else {
                Some(as_str(operation)?.to_string())
            };
            Ok(())
        } else if attr.eq_ignore_ascii_case("displayName") {
            account.description = if is_remove {
                None
            } else {
                Some(as_str(operation)?.to_string())
            };
            Ok(())
        } else if attr.eq_ignore_ascii_case("name") {
            match path.sub_attr.as_deref() {
                Some(_) => {
                    account.description = if is_remove {
                        None
                    } else {
                        Some(as_str(operation)?.to_string())
                    };
                }
                None if is_remove => account.description = None,
                None => {
                    let name = deserialize::<Name<'_>>(operation)?;
                    match (operation.op, name.composed()) {
                        (_, Some(composed)) => account.description = Some(composed),
                        (PatchOp::Replace, None) => account.description = None,
                        (_, None) => {}
                    }
                }
            }
            Ok(())
        } else if attr.eq_ignore_ascii_case("active") {
            if is_remove {
                return Err(
                    Error::invalid_value("The 'active' attribute cannot be removed.").into(),
                );
            }

            let active = operation.value.as_ref().and_then(as_bool).ok_or_else(|| {
                Error::invalid_value("The 'active' attribute requires a boolean.")
            })?;

            if !active {
                self.assert_not_service_principal(id)?;
            }

            users::set_active(&mut account.permissions, active);
            Ok(())
        } else if attr.eq_ignore_ascii_case("locale")
            || attr.eq_ignore_ascii_case("preferredLanguage")
        {
            if is_remove {
                account.locale = users::DEFAULT_LOCALE;
                Ok(())
            } else {
                users::set_locale(account, as_str(operation)?)
            }
        } else if attr.eq_ignore_ascii_case("timezone") {
            if is_remove {
                account.time_zone = None;
                Ok(())
            } else {
                users::set_time_zone(account, Some(as_str(operation)?))
            }
        } else if attr.eq_ignore_ascii_case("emails") {
            if path.filter.is_none() && path.sub_attr.is_some() {
                return Err(Error::invalid_path(format!(
                    "The path '{path}' must select an element with a value filter."
                ))
                .into());
            }

            self.patch_emails(account, operation).await
        } else {
            Err(Error::invalid_path(format!(
                "The attribute '{path}' cannot be modified through this endpoint."
            ))
            .into())
        }
    }

    async fn patch_emails(
        &self,
        account: &mut UserAccount,
        operation: &PatchOperation<'_>,
    ) -> Result<()> {
        let primary = self.email_address(&account.name, account.domain_id).await?;

        let Some(filter) = &operation.path.filter else {
            return match operation.op {
                PatchOp::Remove => {
                    account.aliases = Default::default();
                    Ok(())
                }
                PatchOp::Replace => {
                    let emails = deserialize_emails(operation)?;
                    self.set_emails(account, &emails).await
                }
                PatchOp::Add => {
                    let emails = deserialize_emails(operation)?;
                    let mut merged = Vec::with_capacity(account.aliases.len() + emails.len());
                    for alias in account.aliases.values() {
                        merged.push(Email {
                            value: Some(
                                self.email_address(&alias.name, alias.domain_id)
                                    .await?
                                    .into(),
                            ),
                            ..Default::default()
                        });
                    }
                    merged.extend(emails);

                    self.set_emails(account, &merged).await
                }
            };
        };

        let terms = filter.clone().into_equality_terms()?;
        let mut matched = Vec::new();

        if matches(&terms, &primary, true)? {
            matched.push(None);
        }
        for (index, alias) in account.aliases.values().enumerate() {
            let address = self.email_address(&alias.name, alias.domain_id).await?;
            if matches(&terms, &address, false)? {
                matched.push(Some(index));
            }
        }

        match matched.len() {
            0 => {
                Err(Error::no_target("The value filter did not match any 'emails' element.").into())
            }
            1 => {
                let Some(index) = matched[0] else {
                    if operation.op == PatchOp::Remove {
                        return Err(Error::invalid_value(
                            "The primary email address is derived from 'userName' and cannot be \
                             removed.",
                        )
                        .into());
                    }

                    return self.set_user_name(account, as_str(operation)?).await;
                };

                if operation.op == PatchOp::Remove {
                    account.aliases = std::mem::take(&mut account.aliases)
                        .into_iter()
                        .enumerate()
                        .filter_map(|(position, alias)| (position != index).then_some(alias))
                        .collect();
                } else {
                    let (local_part, domain) =
                        self.resolve_address(as_str(operation)?, "emails").await?;

                    if domain.id_tenant.map(Id::from) != account.member_tenant_id {
                        return Err(Error::invalid_value(
                            "The address belongs to a domain in a different tenant.",
                        )
                        .into());
                    }

                    if let Some(alias) = account.aliases.values_mut().nth(index) {
                        alias.name = local_part;
                        alias.domain_id = Id::from(domain.id);
                    }
                }

                Ok(())
            }
            _ => Err(Error::invalid_filter(
                "The value filter matched more than one 'emails' element.",
            )
            .into()),
        }
    }
}

fn is_tolerated_path(path: &PatchPath<'_>) -> bool {
    if path.schema.as_deref().is_some_and(|schema| {
        TOLERATED_USER_SCHEMAS
            .iter()
            .any(|urn| schema.eq_ignore_ascii_case(urn))
    }) {
        return true;
    }

    let attr = path.attr.as_ref();
    if TOLERATED_USER_ATTRIBUTES
        .iter()
        .any(|name| attr.eq_ignore_ascii_case(name))
    {
        return true;
    }

    attr.eq_ignore_ascii_case("name")
        && path.sub_attr.as_deref().is_some_and(|sub_attr| {
            ["givenName", "familyName"]
                .iter()
                .any(|name| sub_attr.eq_ignore_ascii_case(name))
                || TOLERATED_NAME_ATTRIBUTES
                    .iter()
                    .any(|name| sub_attr.eq_ignore_ascii_case(name))
        })
}

fn matches(terms: &[EqualityTerm<'_>], address: &str, is_primary: bool) -> Result<bool> {
    for term in terms {
        let attr = term.path.attr.as_ref();
        let matches = if attr.eq_ignore_ascii_case("value") {
            term.value
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(address))
        } else if attr.eq_ignore_ascii_case("type") {
            term.value
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(users::EMAIL_TYPE_WORK))
        } else if attr.eq_ignore_ascii_case("primary") {
            term.value.as_bool() == Some(is_primary)
        } else if attr.eq_ignore_ascii_case("display") {
            false
        } else {
            return Err(Error::invalid_filter(format!(
                "Unknown sub-attribute '{}' in the 'emails' value filter.",
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

fn deserialize_emails<'x>(operation: &'x PatchOperation<'x>) -> Result<Vec<Email<'x>>> {
    match operation.value.as_ref() {
        Some(Value::Array(_)) => deserialize::<Vec<Email<'x>>>(operation),
        Some(_) => deserialize::<Email<'x>>(operation).map(|email| vec![email]),
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

fn as_str<'x>(operation: &'x PatchOperation<'x>) -> Result<&'x str> {
    operation.value_as_str().ok_or_else(|| {
        Error::invalid_value(format!(
            "The attribute '{}' requires a string value.",
            operation.path
        ))
        .into()
    })
}

fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.as_str() {
            value if value.eq_ignore_ascii_case("true") => Some(true),
            value if value.eq_ignore_ascii_case("false") => Some(false),
            _ => None,
        },
        _ => None,
    }
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
    fn value_filters_select_the_matching_address() {
        let terms = parse_terms(r#"value eq "babs@example.com""#);

        assert!(matches(&terms, "babs@example.com", false).unwrap());
        assert!(matches(&terms, "BABS@EXAMPLE.COM", false).unwrap());
        assert!(!matches(&terms, "other@example.com", false).unwrap());
    }

    #[test]
    fn every_address_is_of_type_work() {
        let terms = parse_terms(r#"type eq "work""#);

        assert!(matches(&terms, "a@example.com", true).unwrap());
        assert!(matches(&terms, "b@example.com", false).unwrap());

        assert!(!matches(&parse_terms(r#"type eq "home""#), "a@example.com", false).unwrap());
    }

    #[test]
    fn the_primary_flag_distinguishes_the_derived_address() {
        let terms = parse_terms("primary eq true");

        assert!(matches(&terms, "a@example.com", true).unwrap());
        assert!(!matches(&terms, "b@example.com", false).unwrap());
    }

    #[test]
    fn conjunctions_must_all_match() {
        let terms = parse_terms(r#"type eq "work" and value eq "a@example.com""#);

        assert!(matches(&terms, "a@example.com", false).unwrap());
        assert!(!matches(&terms, "b@example.com", false).unwrap());
    }

    #[test]
    fn unknown_sub_attributes_are_rejected() {
        let terms = parse_terms(r#"nosuch eq "x""#);

        assert!(matches(&terms, "a@example.com", false).is_err());
    }

    #[test]
    fn booleans_and_strings_are_read_as_active_values() {
        assert_eq!(as_bool(&Value::Bool(true)), Some(true));
        assert_eq!(as_bool(&Value::String("False".into())), Some(false));
        assert_eq!(as_bool(&Value::String("TRUE".into())), Some(true));
        assert_eq!(as_bool(&Value::String("yes".into())), None);
        assert_eq!(as_bool(&Value::Null), None);
    }
}
