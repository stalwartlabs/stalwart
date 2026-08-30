/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 */

use crate::error::{Result, scim_response};
use common::Server;
use http_proto::HttpResponse;
use hyper::StatusCode;
use scim_proto::{
    BASE_PATH, ResourceType,
    message::{error::Error, list::ListResponse},
    schema::{
        Schema,
        group::GROUP_SCHEMA,
        spc::{GROUP_RESOURCE_TYPE, ResourceTypeDef, ServiceProviderConfig, USER_RESOURCE_TYPE},
        user::USER_SCHEMA,
    },
};

pub trait ScimDiscovery: Sync + Send {
    fn scim_service_provider_config(&self) -> Result<HttpResponse>;
    fn scim_resource_types(&self, name: Option<&str>) -> Result<HttpResponse>;
    fn scim_schemas(&self, id: Option<&str>) -> Result<HttpResponse>;
    fn scim_endpoint(&self, path: &str) -> String;
}

impl ScimDiscovery for Server {
    fn scim_service_provider_config(&self) -> Result<HttpResponse> {
        let location = self.scim_endpoint("/ServiceProviderConfig");

        scim_response(
            StatusCode::OK,
            &ServiceProviderConfig::DEFAULT.with_location(&location),
        )
    }

    fn scim_resource_types(&self, name: Option<&str>) -> Result<HttpResponse> {
        match name {
            Some(name) => {
                let resource_type = match name {
                    "User" => ResourceType::User,
                    "Group" => ResourceType::Group,
                    _ => return Err(Error::not_found().into()),
                };
                let location = self.resource_type_location(resource_type);

                scim_response(
                    StatusCode::OK,
                    &ResourceTypeDef::new(resource_type).with_location(&location),
                )
            }
            None => {
                let user_location = self.resource_type_location(ResourceType::User);
                let group_location = self.resource_type_location(ResourceType::Group);

                scim_response(
                    StatusCode::OK,
                    &ListResponse::new(
                        2,
                        vec![
                            USER_RESOURCE_TYPE.with_location(&user_location),
                            GROUP_RESOURCE_TYPE.with_location(&group_location),
                        ],
                    )
                    .with_start_index(1),
                )
            }
        }
    }

    fn scim_schemas(&self, id: Option<&str>) -> Result<HttpResponse> {
        match id {
            Some(id) => {
                let schema = [&USER_SCHEMA, &GROUP_SCHEMA]
                    .into_iter()
                    .find(|schema| schema.id.eq_ignore_ascii_case(id))
                    .ok_or_else(Error::not_found)?;
                let location = self.schema_location(schema);

                scim_response(StatusCode::OK, &schema.resource(Some(&location)))
            }
            None => {
                let user_location = self.schema_location(&USER_SCHEMA);
                let group_location = self.schema_location(&GROUP_SCHEMA);

                scim_response(
                    StatusCode::OK,
                    &ListResponse::new(
                        2,
                        vec![
                            USER_SCHEMA.resource(Some(&user_location)),
                            GROUP_SCHEMA.resource(Some(&group_location)),
                        ],
                    )
                    .with_start_index(1),
                )
            }
        }
    }

    fn scim_endpoint(&self, path: &str) -> String {
        let base_url = &self.core.network.http.url_https;
        let mut location = String::with_capacity(base_url.len() + BASE_PATH.len() + path.len());
        location.push_str(base_url);
        location.push_str(BASE_PATH);
        location.push_str(path);
        location
    }
}

trait ScimDiscoveryLocations {
    fn resource_type_location(&self, resource_type: ResourceType) -> String;
    fn schema_location(&self, schema: &Schema) -> String;
}

impl ScimDiscoveryLocations for Server {
    fn resource_type_location(&self, resource_type: ResourceType) -> String {
        let mut path = String::with_capacity(20);
        path.push_str("/ResourceTypes/");
        path.push_str(resource_type.as_str());
        self.scim_endpoint(&path)
    }

    fn schema_location(&self, schema: &Schema) -> String {
        let mut path = String::with_capacity(schema.id.len() + 9);
        path.push_str("/Schemas/");
        path.push_str(schema.id);
        self.scim_endpoint(&path)
    }
}
