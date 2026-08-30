/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::{
    context::{ScimContext, parse_id},
    error::{Error as ScimResponseError, Result, scim_response},
    groups,
};
use http_proto::HttpResponse;
use hyper::StatusCode;
use scim_proto::{
    ResourceType,
    etag::weak_etag,
    message::{
        bulk::{
            BulkMethod, BulkOperation, BulkOperationResponse, BulkRequest, BulkResponse,
            resolve_bulk_id_refs,
        },
        error::Error,
        patch::PatchRequest,
    },
    schema::{group::Group, spc::ServiceProviderConfig, user::User},
};
use serde::Deserialize;
use serde_json::Value;
use store::ahash::AHashMap;
use types::id::Id;

impl ScimContext<'_> {
    pub async fn bulk(&self, body: &[u8]) -> Result<HttpResponse> {
        let request = BulkRequest::parse(body, ServiceProviderConfig::DEFAULT.bulk.max_operations)?;
        let order = request.processing_order()?;
        let fail_on_errors = request.fail_on_errors.unwrap_or(usize::MAX);
        let mut operations = request.operations.unwrap_or_default();
        let mut resolved = AHashMap::with_capacity(operations.len());
        let mut responses = Vec::with_capacity(operations.len());
        let mut errors = 0;

        for index in order {
            let operation = &mut operations[index];
            let bulk_id = operation.bulk_id.as_deref().map(str::to_string);

            if let Some(data) = operation.data.as_mut()
                && let Err(error) = resolve_bulk_id_refs(data, &|reference| {
                    resolved.get(reference).map(|id: &Id| id.to_string())
                })
            {
                responses.push(failed(self, operation, bulk_id, error));
                errors += 1;

                if errors >= fail_on_errors {
                    break;
                }
                continue;
            }

            match self.bulk_operation(operation).await {
                Ok((id, status, version)) => {
                    let method = operation.method().unwrap_or(BulkMethod::Post);
                    let resource_type = operation
                        .resource_path()
                        .map(|(resource_type, _)| resource_type)
                        .unwrap_or(ResourceType::User);
                    let mut response = BulkOperationResponse::new(method, status);

                    if let Some(bulk_id) = bulk_id {
                        resolved.insert(bulk_id.clone(), id);
                        response = response.with_bulk_id(bulk_id);
                    }
                    if let Some(version) = version {
                        response = response.with_version(version);
                    }

                    responses.push(response.with_location(self.location(resource_type, id)));
                }
                Err(error) => {
                    let error = match error {
                        ScimResponseError::Scim(error) | ScimResponseError::Allow(error, _) => {
                            error
                        }
                        ScimResponseError::Internal(error) => {
                            let scim = crate::error::IntoScimError::into_scim_error(&error);
                            trc::error!(error.span_id(self.session_id));
                            scim
                        }
                    };

                    responses.push(failed(self, operation, bulk_id, error));
                    errors += 1;

                    if errors >= fail_on_errors {
                        break;
                    }
                }
            }
        }

        scim_response(StatusCode::OK, &BulkResponse::new(responses))
    }

    async fn bulk_operation(
        &self,
        operation: &BulkOperation<'_>,
    ) -> Result<(Id, u16, Option<String>)> {
        let method = operation.method()?;
        let (resource_type, path_id) = operation.resource_path()?;
        let data = operation.data.as_ref();

        match (method, path_id) {
            (BulkMethod::Post, _) => match resource_type {
                ResourceType::User => {
                    let user = parse::<User<'_>>(data)?;
                    let (id, object) = self.user_insert(&user).await?;

                    Ok((id, 201, Some(weak_etag(object.revision))))
                }
                ResourceType::Group => {
                    let group = parse::<Group<'_>>(data)?;
                    let (id, object, member_ids) = self.group_insert(&group).await?;

                    Ok((
                        id,
                        201,
                        Some(weak_etag(groups::version(object.revision, &member_ids))),
                    ))
                }
            },
            (method, Some(path_id)) => {
                let id = parse_id(path_id)?;
                let object = self.account(id).await?;
                let members = match resource_type {
                    ResourceType::User => Vec::new(),
                    ResourceType::Group => self.group_member_ids(id).await?,
                };
                let version = match resource_type {
                    ResourceType::User => weak_etag(object.revision),
                    ResourceType::Group => weak_etag(groups::version(object.revision, &members)),
                };

                if let Some(expected) = operation.version.as_deref()
                    && !scim_proto::etag::matches(expected, &version)
                {
                    return Err(Error::precondition_failed()
                        .with_detail("The resource has been modified since it was last retrieved.")
                        .into());
                }

                match (method, resource_type) {
                    (BulkMethod::Put, ResourceType::User) => {
                        let user = parse::<User<'_>>(data)?;
                        let updated = self.user_update(id, &user, &object).await?;

                        Ok((
                            id,
                            200,
                            Some(weak_etag(updated.as_ref().unwrap_or(&object).revision)),
                        ))
                    }
                    (BulkMethod::Patch, ResourceType::User) => {
                        let patch = parse_patch(data)?;
                        let updated = self.user_apply_patch(id, &patch, &object).await?;

                        Ok((
                            id,
                            200,
                            Some(weak_etag(updated.as_ref().unwrap_or(&object).revision)),
                        ))
                    }
                    (BulkMethod::Delete, ResourceType::User) => {
                        self.user_delete(id, &object).await?;

                        Ok((id, 204, None))
                    }
                    (BulkMethod::Put, ResourceType::Group) => {
                        let group = parse::<Group<'_>>(data)?;
                        let (updated, member_ids) =
                            self.group_update(id, &group, &object, members).await?;
                        let revision = updated.as_ref().unwrap_or(&object).revision;

                        Ok((
                            id,
                            200,
                            Some(weak_etag(groups::version(revision, &member_ids))),
                        ))
                    }
                    (BulkMethod::Patch, ResourceType::Group) => {
                        let patch = parse_patch(data)?;
                        let (updated, member_ids) =
                            self.group_apply_patch(id, &patch, &object, members).await?;
                        let revision = updated.as_ref().unwrap_or(&object).revision;

                        Ok((
                            id,
                            200,
                            Some(weak_etag(groups::version(revision, &member_ids))),
                        ))
                    }
                    (BulkMethod::Delete, ResourceType::Group) => {
                        self.group_delete(id, &object).await?;

                        Ok((id, 204, None))
                    }
                    (BulkMethod::Post, _) => unreachable!(),
                }
            }
            (method, None) => Err(Error::invalid_value(format!(
                "A '{}' operation must target a specific resource.",
                method.as_str()
            ))
            .into()),
        }
    }
}

fn failed<'x>(
    ctx: &ScimContext<'_>,
    operation: &BulkOperation<'_>,
    bulk_id: Option<String>,
    error: Error,
) -> BulkOperationResponse<'x> {
    let method = operation.method().unwrap_or(BulkMethod::Post);
    let mut response = BulkOperationResponse::new(method, error.status).with_error(error);

    if let Some(bulk_id) = bulk_id {
        response = response.with_bulk_id(bulk_id);
    }

    if method != BulkMethod::Post
        && let Ok((resource_type, Some(path_id))) = operation.resource_path()
        && let Ok(id) = parse_id(path_id)
    {
        response = response.with_location(ctx.location(resource_type, id));
    }

    response
}

fn parse<'x, T: Deserialize<'x>>(data: Option<&'x Value>) -> Result<T> {
    let data = data.ok_or_else(|| Error::invalid_syntax("Missing 'data' attribute."))?;

    T::deserialize(data).map_err(|err| Error::invalid_syntax(err.to_string()).into())
}

fn parse_patch(data: Option<&Value>) -> Result<PatchRequest<'static>> {
    let data = data.ok_or_else(|| Error::invalid_syntax("Missing 'data' attribute."))?;
    let body = serde_json::to_vec(data).map_err(|err| Error::invalid_syntax(err.to_string()))?;

    PatchRequest::parse(&body)
        .map(|patch| PatchRequest {
            operations: patch
                .operations
                .into_iter()
                .map(|operation| scim_proto::message::patch::PatchOperation {
                    op: operation.op,
                    path: operation.path.into_owned(),
                    value: operation.value,
                })
                .collect(),
        })
        .map_err(Into::into)
}
