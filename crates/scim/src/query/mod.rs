/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

pub mod cursor;

use crate::{
    context::{ScimContext, group_account, parse_id, user_account},
    error::{Result, scim_response},
};
use common::auth::EmailCache;
use http_proto::HttpResponse;
use hyper::StatusCode;
use registry::{
    schema::{
        enums::{AccountType, Permission},
        prelude::{Object, ObjectType, Property},
    },
    types::EnumImpl,
};
use scim_proto::{
    ResourceType,
    attributes::AttributeSelection,
    filter::{AttrPath, CompValue, EqualityTerm},
    message::{error::Error, list::ListResponse, search::SearchRequest},
};
use serde_json::Value;
use store::{ahash::AHashMap, registry::RegistryQuery};
use trc::AddContext;
use types::id::Id;

pub const MAX_RESULTS: usize = 200;
const NO_ANCHOR: u64 = u64::MAX;
pub const DEFAULT_PAGE_SIZE: usize = 100;

enum PostFilter {
    Active(bool),
    Description(String),
}

struct Plan {
    query: RegistryQuery,
    post: Vec<PostFilter>,
    restrict: Option<Vec<Id>>,
    is_indexed: bool,
    is_empty: bool,
}

impl ScimContext<'_> {
    pub async fn query(
        &self,
        resource_type: ResourceType,
        request: &SearchRequest<'_>,
    ) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountGet)?;

        let selection = request.attribute_selection()?;
        let (ids, mut loaded) = self.matching_ids(resource_type, request).await?;
        let total_results = ids.len();
        let ids = self.sort_ids(resource_type, ids, request).await?;
        let count = request.effective_count(DEFAULT_PAGE_SIZE, MAX_RESULTS);

        let (page, mut response) = if request.is_cursor_paginated() {
            let signature = cursor::signature(resource_type, request);
            let position = match request
                .cursor
                .as_deref()
                .filter(|cursor| !cursor.is_empty())
            {
                Some(cursor) => cursor::decode(cursor, signature, &ids)?,
                None => 0,
            };
            let end = position.saturating_add(count).min(ids.len());
            let page = ids.get(position..end).unwrap_or_default();
            let mut response = ListResponse::new(total_results, Vec::with_capacity(page.len()));

            if end < ids.len() {
                let anchor = end
                    .checked_sub(1)
                    .map_or_else(|| Id::new(NO_ANCHOR), |index| ids[index]);
                response = response.with_next_cursor(cursor::encode(signature, end, anchor));
            }

            (page, response)
        } else {
            let start_index = request.effective_start_index();
            let position = start_index - 1;
            let end = position.saturating_add(count).min(ids.len());
            let page = ids.get(position..end).unwrap_or_default();

            (
                page,
                ListResponse::new(total_results, Vec::with_capacity(page.len()))
                    .with_start_index(start_index),
            )
        };

        for id in page {
            if let Some(resource) = self
                .render(resource_type, *id, loaded.remove(id), &selection)
                .await?
            {
                response.resources.push(resource);
            }
        }
        response.items_per_page = Some(response.resources.len());

        scim_response(StatusCode::OK, &response)
    }

    pub async fn search_all(&self, request: &SearchRequest<'_>) -> Result<HttpResponse> {
        self.assert_permission(Permission::SysAccountGet)?;

        let selection = request.attribute_selection()?;
        let mut page = Vec::new();
        let mut total_results = 0;
        let mut rejected = None;
        let mut accepted = false;
        let start_index = request.effective_start_index();
        let count = request.effective_count(DEFAULT_PAGE_SIZE, MAX_RESULTS);
        let mut position = start_index - 1;

        for resource_type in [ResourceType::User, ResourceType::Group] {
            let (ids, mut loaded) = match self.matching_ids(resource_type, request).await {
                Ok(matches) => matches,
                Err(error) if is_invalid_filter(&error) => {
                    rejected = Some(error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            accepted = true;
            total_results += ids.len();

            if page.len() >= count {
                continue;
            }

            let ids = self.sort_ids(resource_type, ids, request).await?;
            let skipped = position.min(ids.len());
            position -= skipped;

            for id in ids.into_iter().skip(skipped) {
                if page.len() >= count {
                    break;
                }

                if let Some(resource) = self
                    .render(resource_type, id, loaded.remove(&id), &selection)
                    .await?
                {
                    page.push(resource);
                }
            }
        }

        if let Some(error) = rejected.filter(|_| !accepted) {
            return Err(error);
        }

        scim_response(
            StatusCode::OK,
            &ListResponse::new(total_results, page).with_start_index(start_index),
        )
    }

    async fn matching_ids(
        &self,
        resource_type: ResourceType,
        request: &SearchRequest<'_>,
    ) -> Result<(Vec<Id>, AHashMap<Id, Object>)> {
        let account_type = account_type(resource_type).to_id();
        let mut plan = Plan {
            query: RegistryQuery::new(ObjectType::Account)
                .with_tenant(self.tenant_id())
                .equal(Property::Type, account_type),
            post: Vec::new(),
            restrict: None,
            is_indexed: false,
            is_empty: false,
        };

        if let Some(filter) = request.parse_filter()? {
            for term in filter.into_equality_terms()? {
                self.resolve_term(resource_type, &term, &mut plan).await?;
            }
        }

        let mut loaded = AHashMap::new();
        let mut ids = match &plan.restrict {
            _ if plan.is_empty => Vec::new(),
            Some(restrict) if !plan.is_indexed => {
                let mut ids = Vec::with_capacity(restrict.len());

                for id in restrict {
                    if let Some(object) = self.try_account(*id).await?
                        && is_resource_type(&object, resource_type)
                    {
                        ids.push(*id);
                        loaded.insert(*id, object);
                    }
                }

                ids
            }
            restrict => {
                let mut ids = self
                    .server
                    .registry()
                    .query::<Vec<Id>>(plan.query)
                    .await
                    .caused_by(trc::location!())?;

                if let Some(restrict) = restrict {
                    ids.retain(|id| restrict.contains(id));
                }

                ids
            }
        };

        ids = self.retain_provisionable(ids, &mut loaded).await?;

        if !plan.post.is_empty() && !ids.is_empty() {
            if ids.len() > MAX_RESULTS {
                return Err(Error::too_many(format!(
                    "The filter matches more than {MAX_RESULTS} resources before evaluating \
                     non-indexed attributes, narrow the filter and try again."
                ))
                .into());
            }

            let mut matches = Vec::with_capacity(ids.len());
            for id in ids {
                let object = match loaded.remove(&id) {
                    Some(object) => object,
                    None => match self.try_account(id).await? {
                        Some(object) => object,
                        None => continue,
                    },
                };

                if self
                    .post_filter_matches(resource_type, &object, &plan.post)
                    .await?
                {
                    matches.push(id);
                    loaded.insert(id, object);
                }
            }
            ids = matches;
        }

        Ok((ids, loaded))
    }

    async fn retain_provisionable(
        &self,
        ids: Vec<Id>,
        loaded: &mut AHashMap<Id, Object>,
    ) -> Result<Vec<Id>> {
        let mut result = Vec::with_capacity(ids.len());

        for id in ids {
            let is_provisionable = match loaded.get(&id) {
                Some(object) => match crate::context::account_domain_id(object) {
                    Some(domain_id) => self.is_provisionable(domain_id).await?,
                    None => false,
                },
                None => self.is_provisionable_account(id).await?,
            };

            if is_provisionable {
                result.push(id);
            } else {
                loaded.remove(&id);
            }
        }

        Ok(result)
    }

    async fn render(
        &self,
        resource_type: ResourceType,
        id: Id,
        object: Option<Object>,
        selection: &AttributeSelection<'_>,
    ) -> Result<Option<Value>> {
        let object = match object {
            Some(object) => object,
            None => match self.try_account(id).await? {
                Some(object) => object,
                None => return Ok(None),
            },
        };

        match resource_type {
            ResourceType::User => match user_account(&object) {
                Ok(account) => self
                    .user_to_scim(id, object.revision, account, selection)
                    .await
                    .map(Some),
                Err(_) => Ok(None),
            },
            ResourceType::Group => match group_account(&object) {
                Ok(account) => {
                    let member_ids = self.group_member_ids(id).await?;
                    self.group_to_scim(id, object.revision, account, &member_ids, selection)
                        .await
                        .map(Some)
                }
                Err(_) => Ok(None),
            },
        }
    }

    async fn post_filter_matches(
        &self,
        resource_type: ResourceType,
        object: &Object,
        filters: &[PostFilter],
    ) -> Result<bool> {
        for filter in filters {
            let matches = match (filter, resource_type) {
                (PostFilter::Active(expected), ResourceType::User) => match user_account(object) {
                    Ok(account) => self.is_active(account).await? == *expected,
                    Err(_) => false,
                },
                (PostFilter::Active(_), ResourceType::Group) => false,
                (PostFilter::Description(expected), ResourceType::User) => {
                    match user_account(object) {
                        Ok(account) => account
                            .description
                            .as_deref()
                            .is_some_and(|description| description.eq_ignore_ascii_case(expected)),
                        Err(_) => false,
                    }
                }
                (PostFilter::Description(expected), ResourceType::Group) => {
                    match group_account(object) {
                        Ok(account) => {
                            crate::groups::display_name(account).eq_ignore_ascii_case(expected)
                        }
                        Err(_) => false,
                    }
                }
            };

            if !matches {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn sort_ids(
        &self,
        resource_type: ResourceType,
        mut ids: Vec<Id>,
        request: &SearchRequest<'_>,
    ) -> Result<Vec<Id>> {
        let ascending = !request.sort_order.unwrap_or_default().is_descending();
        let property = match request.sort_by.as_deref() {
            None | Some("") => None,
            Some(sort_by) if sort_by.eq_ignore_ascii_case("id") => None,
            Some(sort_by)
                if resource_type == ResourceType::User
                    && sort_by.eq_ignore_ascii_case("userName") =>
            {
                Some(Property::Name)
            }
            Some(sort_by) => {
                return Err(Error::invalid_value(format!(
                    "Sorting by attribute '{sort_by}' is not supported."
                ))
                .into());
            }
        };

        match property {
            Some(property) => self
                .server
                .registry()
                .sort_by_index(ObjectType::Account, property, Some(ids), ascending)
                .await
                .caused_by(trc::location!())
                .map_err(Into::into),
            None => {
                if ascending {
                    ids.sort_unstable();
                } else {
                    ids.sort_unstable_by(|a, b| b.cmp(a));
                }
                Ok(ids)
            }
        }
    }

    async fn resolve_term(
        &self,
        resource_type: ResourceType,
        term: &EqualityTerm<'_>,
        plan: &mut Plan,
    ) -> Result<()> {
        resource_type.schema().resolve_filter_path(&term.path)?;

        let path = &term.path;
        let value = &term.value;

        if path.matches("id", None) {
            let id = as_id(path, value)?;
            plan.restrict_to(vec![id]);
        } else if path.matches("externalId", None) {
            plan.is_indexed = true;
            plan.query.push_equal_pk(
                Property::ExternalId,
                as_str(path, value)?.to_string(),
                false,
            );
        } else if resource_type == ResourceType::User && path.matches("userName", None) {
            match self.lookup_address(as_str(path, value)?).await? {
                Some((local_part, domain_id)) => {
                    plan.is_indexed = true;
                    plan.query.push_equal_pk(Property::Name, local_part, false);
                    plan.query
                        .push_equal_pk(Property::DomainId, domain_id.id(), false);
                }
                None => plan.is_empty = true,
            }
        } else if resource_type == ResourceType::User
            && (path.matches("emails", None) || path.matches("emails", Some("value")))
        {
            match self.lookup_recipient(as_str(path, value)?).await? {
                Some(id) => plan.restrict_to(vec![id]),
                None => plan.is_empty = true,
            }
        } else if resource_type == ResourceType::User && path.matches("active", None) {
            plan.post
                .push(PostFilter::Active(value.as_bool().ok_or_else(|| {
                    Error::invalid_filter("The 'active' attribute requires a boolean value.")
                })?));
        } else if path.matches("displayName", None)
            || (resource_type == ResourceType::User && path.matches("name", Some("formatted")))
        {
            let value = as_str(path, value)?;
            if value
                .split(|ch: char| !ch.is_alphanumeric())
                .any(|word| word.len() > 1)
            {
                plan.is_indexed = true;
                plan.query.push_text(Property::Text, value);
            }
            plan.post.push(PostFilter::Description(value.to_string()));
        } else if resource_type == ResourceType::User
            && (path.matches("groups", None) || path.matches("groups", Some("value")))
        {
            plan.is_indexed = true;
            plan.query
                .push_equal_pk(Property::MemberGroupIds, as_id(path, value)?.id(), false);
        } else if resource_type == ResourceType::Group
            && (path.matches("members", None) || path.matches("members", Some("value")))
        {
            let member_id = as_id(path, value)?;
            let group_ids = match self.try_account(member_id).await? {
                Some(object) => user_account(&object)
                    .map(|account| account.member_group_ids.iter().copied().collect::<Vec<_>>())
                    .unwrap_or_default(),
                None => Vec::new(),
            };

            if group_ids.is_empty() {
                plan.is_empty = true;
            } else {
                plan.restrict_to(group_ids);
            }
        } else {
            return Err(Error::invalid_filter(format!(
                "The attribute '{path}' is not supported in filters."
            ))
            .into());
        }

        Ok(())
    }

    pub async fn lookup_address(&self, address: &str) -> Result<Option<(String, Id)>> {
        let Some((local_part, domain_name)) = address.rsplit_once('@') else {
            return Ok(None);
        };

        match self
            .server
            .domain(domain_name)
            .await
            .caused_by(trc::location!())?
        {
            Some(domain)
                if self
                    .tenant_id()
                    .is_none_or(|tenant_id| domain.id_tenant == Some(tenant_id)) =>
            {
                Ok(Some((local_part.to_lowercase(), Id::from(domain.id))))
            }
            _ => Ok(None),
        }
    }

    pub async fn lookup_recipient(&self, address: &str) -> Result<Option<Id>> {
        let Some((local_part, domain_id)) = self.lookup_address(address).await? else {
            return Ok(None);
        };

        Ok(
            match self
                .server
                .rcpt_id_from_parts(&local_part, domain_id.document_id())
                .await
                .caused_by(trc::location!())?
            {
                Some(EmailCache::Account(id) | EmailCache::DisabledAccountAddress(id)) => {
                    Some(Id::from(id))
                }
                _ => None,
            },
        )
    }
}

impl Plan {
    fn restrict_to(&mut self, ids: Vec<Id>) {
        match &mut self.restrict {
            Some(restrict) => restrict.retain(|id| ids.contains(id)),
            None => self.restrict = Some(ids),
        }

        if self.restrict.as_ref().is_some_and(Vec::is_empty) {
            self.is_empty = true;
        }
    }
}

fn as_str<'x>(path: &AttrPath<'_>, value: &'x CompValue<'x>) -> Result<&'x str> {
    value.as_str().ok_or_else(|| {
        Error::invalid_filter(format!("The attribute '{path}' requires a string value.")).into()
    })
}

fn as_id(path: &AttrPath<'_>, value: &CompValue<'_>) -> Result<Id> {
    parse_id(as_str(path, value)?).map_err(|_| {
        Error::invalid_filter(format!(
            "The attribute '{path}' requires a resource identifier."
        ))
        .into()
    })
}

fn is_resource_type(object: &Object, resource_type: ResourceType) -> bool {
    match resource_type {
        ResourceType::User => user_account(object).is_ok(),
        ResourceType::Group => group_account(object).is_ok(),
    }
}

fn is_invalid_filter(error: &crate::error::Error) -> bool {
    matches!(
        error,
        crate::error::Error::Scim(error)
            if error.scim_type == Some(scim_proto::message::error::ScimType::InvalidFilter)
    )
}

pub fn account_type(resource_type: ResourceType) -> AccountType {
    match resource_type {
        ResourceType::User => AccountType::User,
        ResourceType::Group => AccountType::Group,
    }
}
