/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::{Server, auth::AccessToken};
use email::sieve::rules::managed::{ManagedSieveScript, SaveError};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::vacation_response::{self, VacationResponseProperty, VacationResponseValue},
    references::resolve::ResolveCreatedReference,
    request::IntoValid,
    types::state::State,
};
use jmap_tools::{Key, Value};
use std::future::Future;
use types::{collection::SyncCollection, id::Id};

pub trait VacationResponseSet: Sync + Send {
    fn vacation_response_set(
        &self,
        request: SetRequest<'_, vacation_response::VacationResponse>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<vacation_response::VacationResponse>>> + Send;
}

impl VacationResponseSet for Server {
    async fn vacation_response_set(
        &self,
        mut request: SetRequest<'_, vacation_response::VacationResponse>,
        access_token: &AccessToken,
    ) -> trc::Result<SetResponse<vacation_response::VacationResponse>> {
        let account_id = request.account_id.document_id();
        let mut response = SetResponse::from_request(&request, self.core.jmap.set_max_objects)?
            .with_state(
                self.assert_state(
                    account_id,
                    SyncCollection::SieveScript,
                    &request.if_in_state,
                )
                .await?,
            );

        for id in request.unwrap_destroy().into_valid() {
            response.not_destroyed.append(id, SetError::singleton());
        }

        // Process set or update requests
        let create_id = None;
        let mut changes = None;
        match (request.create, request.update) {
            (Some(create), Some(update)) if !create.is_empty() && !update.is_empty() => {
                return Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details("Creating and updating on the same request is not allowed."));
            }
            (Some(create), _) if !create.is_empty() => {
                for (id, _obj) in create {
                    response.not_created.append(id, SetError::singleton());
                }
            }
            (_, Some(update)) if !update.is_empty() => {
                for (id, obj) in update.into_valid() {
                    if id.is_singleton() {
                        changes = Some(obj);
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::new(SetErrorType::NotFound).with_description("ID not found."),
                        );
                    }
                }
            }
            _ => {
                return Ok(response);
            }
        }

        let Some(changes) = changes else {
            return Ok(response);
        };
        let mut state = self.managed_script_load(account_id).await?;
        let mut vacation = state.script.vacation.take().unwrap_or_default();

        for (property, mut value) in changes.into_expanded_object() {
            if let Err(err) = response.resolve_self_references(&mut value, 0, false) {
                return Ok(set_error(response, create_id, err));
            };

            match (&property, value) {
                (Key::Property(VacationResponseProperty::Subject), Value::Str(value))
                    if value.len() < 512 =>
                {
                    vacation.subject = Some(value.into_owned());
                }
                (Key::Property(VacationResponseProperty::HtmlBody), Value::Str(value))
                    if value.len() < 2048 =>
                {
                    vacation.html_body = Some(value.into_owned());
                }
                (Key::Property(VacationResponseProperty::TextBody), Value::Str(value))
                    if value.len() < 2048 =>
                {
                    vacation.text_body = Some(value.into_owned());
                }
                (
                    Key::Property(VacationResponseProperty::FromDate),
                    Value::Element(VacationResponseValue::Date(date)),
                ) => {
                    vacation.from_date = u64::try_from(date.timestamp()).ok();
                }
                (
                    Key::Property(VacationResponseProperty::ToDate),
                    Value::Element(VacationResponseValue::Date(date)),
                ) => {
                    vacation.to_date = u64::try_from(date.timestamp()).ok();
                }
                (Key::Property(VacationResponseProperty::IsEnabled), Value::Bool(value)) => {
                    vacation.is_enabled = value;
                }
                (Key::Property(VacationResponseProperty::IsEnabled), Value::Null) => {
                    vacation.is_enabled = false;
                }
                (Key::Property(VacationResponseProperty::Subject), Value::Null) => {
                    vacation.subject = None;
                }
                (Key::Property(VacationResponseProperty::HtmlBody), Value::Null) => {
                    vacation.html_body = None;
                }
                (Key::Property(VacationResponseProperty::TextBody), Value::Null) => {
                    vacation.text_body = None;
                }
                (Key::Property(VacationResponseProperty::FromDate), Value::Null) => {
                    vacation.from_date = None;
                }
                (Key::Property(VacationResponseProperty::ToDate), Value::Null) => {
                    vacation.to_date = None;
                }
                (Key::Property(VacationResponseProperty::Id), value) => {
                    if !crate::matches_id(&value, Id::singleton()) {
                        return Ok(set_error(
                            response,
                            create_id,
                            SetError::invalid_properties()
                                .with_property(VacationResponseProperty::Id)
                                .with_description("The id property is immutable."),
                        ));
                    }
                }
                _ => {
                    return Ok(set_error(
                        response,
                        create_id,
                        SetError::invalid_properties()
                            .with_property(property.into_owned())
                            .with_description("Field could not be set."),
                    ));
                }
            }
        }

        state.script.set_vacation(vacation);
        match self
            .managed_script_save(access_token, account_id, state)
            .await?
        {
            Ok(change_id) => {
                if let Some(change_id) = change_id {
                    response.new_state = Some(State::Exact(change_id));
                }
                response.updated.append(Id::singleton(), None);
                Ok(response)
            }
            Err(SaveError::Conflict) => Ok(set_error(
                response,
                create_id,
                SetError::forbidden().with_description(
                    "Another process modified the vacation response, please try again.",
                ),
            )),
            Err(SaveError::Invalid(err)) => Ok(set_error(
                response,
                create_id,
                SetError::invalid_properties().with_description(err.to_string()),
            )),
        }
    }
}

fn set_error(
    mut response: SetResponse<vacation_response::VacationResponse>,
    id: Option<String>,
    err: SetError<VacationResponseProperty>,
) -> SetResponse<vacation_response::VacationResponse> {
    if let Some(id) = id {
        response.not_created.append(id, err);
    } else {
        response.not_updated.append(Id::singleton(), err);
    }
    response
}
