/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::get::VacationResponseGet;
use crate::changes::state::StateManager;
use common::{Server, auth::AccessToken, storage::index::ObjectIndexBuilder};
use email::sieve::{
    SieveScript, VacationResponse, delete::SieveScriptDelete, ingest::SieveScriptIngest,
};
use jmap_proto::{
    error::set::{SetError, SetErrorType},
    method::set::{SetRequest, SetResponse},
    object::vacation_response::{self, VacationResponseProperty, VacationResponseValue},
    references::resolve::ResolveCreatedReference,
    request::IntoValid,
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use mail_builder::MessageBuilder;
use mail_parser::decoders::html::html_to_text;
use std::borrow::Cow;
use std::future::Future;
use store::{
    Serialize, SerializeInfallible, ValueKey,
    write::{AlignedBytes, Archive, Archiver, BatchBuilder},
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::PrincipalField,
    id::Id,
};

pub trait VacationResponseSet: Sync + Send {
    fn vacation_response_set(
        &self,
        request: SetRequest<'_, vacation_response::VacationResponse>,
        access_token: &AccessToken,
    ) -> impl Future<Output = trc::Result<SetResponse<vacation_response::VacationResponse>>> + Send;

    fn build_script(&self, obj: &mut SieveScript) -> trc::Result<Vec<u8>>;
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
        let will_destroy = request.unwrap_destroy().into_valid().collect::<Vec<_>>();

        // Process set or update requests
        let mut create_id = None;
        let mut changes = None;
        match (request.create, request.update) {
            (Some(create), Some(update)) if !create.is_empty() && !update.is_empty() => {
                return Err(trc::JmapEvent::InvalidArguments
                    .into_err()
                    .details("Creating and updating on the same request is not allowed."));
            }
            (Some(create), _) if !create.is_empty() => {
                for (id, obj) in create {
                    if will_destroy.contains(&Id::singleton()) {
                        response.not_created.append(
                            id,
                            SetError::new(SetErrorType::WillDestroy)
                                .with_description("ID will be destroyed."),
                        );
                    } else if create_id.is_some() {
                        response.not_created.append(
                            id,
                            SetError::forbidden()
                                .with_description("Only one object can be created."),
                        );
                    } else {
                        create_id = Some(id);
                        changes = Some(obj);
                    }
                }
            }
            (_, Some(update)) if !update.is_empty() => {
                for (id, obj) in update.into_valid() {
                    if id.is_singleton() {
                        if !will_destroy.contains(&id) {
                            changes = Some(obj);
                        } else {
                            response.not_updated.append(
                                id,
                                SetError::new(SetErrorType::WillDestroy)
                                    .with_description("ID will be destroyed."),
                            );
                        }
                    } else {
                        response.not_updated.append(
                            id,
                            SetError::new(SetErrorType::NotFound).with_description("ID not found."),
                        );
                    }
                }
            }
            _ => {
                if will_destroy.is_empty() {
                    return Ok(response);
                }
            }
        }

        // Prepare write batch
        let mut batch = BatchBuilder::new();
        batch
            .with_account_id(account_id)
            .with_collection(Collection::SieveScript);

        // Process changes
        let active_script_id = self.sieve_script_get_active_id(account_id).await?;
        if let Some(changes) = changes {
            // Obtain current script
            let document_id = self.get_vacation_sieve_script_id(account_id).await?;

            let (mut sieve, prev_sieve) = if let Some(document_id) = document_id {
                let prev_sieve = self
                    .store()
                    .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                        account_id,
                        Collection::SieveScript,
                        document_id,
                    ))
                    .await?
                    .ok_or_else(|| {
                        trc::StoreEvent::NotFound
                            .into_err()
                            .caused_by(trc::location!())
                    })?
                    .into_deserialized::<SieveScript>()
                    .caused_by(trc::location!())?;
                let mut sieve = prev_sieve.inner.clone();
                if sieve.vacation_response.is_none() {
                    sieve.vacation_response = VacationResponse::default().into();
                }

                (sieve, Some(prev_sieve))
            } else {
                (
                    SieveScript {
                        name: "vacation".into(),
                        blob_hash: Default::default(),
                        size: 0,
                        vacation_response: VacationResponse::default().into(),
                    },
                    None,
                )
            };

            // Parse properties
            let mut is_active = false;
            let mut build_script = create_id.is_some();
            let vacation = sieve.vacation_response.as_mut().unwrap();

            for (property, mut value) in changes.into_expanded_object() {
                if let Err(err) = response.resolve_self_references(&mut value) {
                    return Ok(set_error(response, create_id, err));
                };

                match (&property, value) {
                    (Key::Property(VacationResponseProperty::Subject), Value::Str(value))
                        if value.len() < 512 =>
                    {
                        build_script = true;
                        vacation.subject = Some(value.into_owned());
                    }
                    (Key::Property(VacationResponseProperty::HtmlBody), Value::Str(value))
                        if value.len() < 2048 =>
                    {
                        build_script = true;
                        vacation.html_body = Some(value.into_owned());
                    }
                    (Key::Property(VacationResponseProperty::TextBody), Value::Str(value))
                        if value.len() < 2048 =>
                    {
                        build_script = true;
                        vacation.text_body = Some(value.into_owned());
                    }
                    (
                        Key::Property(VacationResponseProperty::FromDate),
                        Value::Element(VacationResponseValue::Date(date)),
                    ) => {
                        vacation.from_date = Some(date.timestamp() as u64);
                        build_script = true;
                    }
                    (
                        Key::Property(VacationResponseProperty::ToDate),
                        Value::Element(VacationResponseValue::Date(date)),
                    ) => {
                        vacation.to_date = Some(date.timestamp() as u64);
                        build_script = true;
                    }
                    (Key::Property(VacationResponseProperty::IsEnabled), Value::Bool(value)) => {
                        is_active = value;
                    }
                    (Key::Property(VacationResponseProperty::IsEnabled), Value::Null) => {
                        is_active = false;
                    }
                    (
                        Key::Property(
                            VacationResponseProperty::Subject
                            | VacationResponseProperty::HtmlBody
                            | VacationResponseProperty::TextBody
                            | VacationResponseProperty::ToDate
                            | VacationResponseProperty::FromDate,
                        ),
                        Value::Null,
                    ) => {
                        if create_id.is_none() {
                            build_script = true;
                            match property {
                                Key::Property(VacationResponseProperty::Subject) => {
                                    vacation.subject = None;
                                }
                                Key::Property(VacationResponseProperty::HtmlBody) => {
                                    vacation.html_body = None;
                                }
                                Key::Property(VacationResponseProperty::TextBody) => {
                                    vacation.text_body = None;
                                }
                                Key::Property(VacationResponseProperty::FromDate) => {
                                    vacation.from_date = None;
                                }
                                Key::Property(VacationResponseProperty::ToDate) => {
                                    vacation.to_date = None;
                                }
                                _ => unreachable!(),
                            }
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

            let mut obj = ObjectIndexBuilder::new()
                .with_current_opt(prev_sieve)
                .with_changes(sieve)
                .with_access_token(access_token);

            // Update id
            let document_id = if let Some(document_id) = document_id {
                batch.with_document(document_id);
                document_id
            } else {
                let document_id = self
                    .store()
                    .assign_document_ids(account_id, Collection::SieveScript, 1)
                    .await
                    .caused_by(trc::location!())?;
                batch.with_document(document_id);
                document_id
            };

            // Create sieve script only if there are changes
            if build_script {
                // Upload new blob
                let (blob_hash, blob_hold) = self
                    .put_temporary_blob(
                        account_id,
                        &self.build_script(obj.changes_mut().unwrap())?,
                        60,
                    )
                    .await?;
                obj.changes_mut().unwrap().blob_hash = blob_hash;
                batch.clear(blob_hold);
            };
            batch.custom(obj).caused_by(trc::location!())?;

            // Deactivate other sieve scripts
            let was_active = active_script_id == Some(document_id);
            if is_active {
                if !was_active {
                    batch
                        .with_collection(Collection::Principal)
                        .with_document(0)
                        .set(PrincipalField::ActiveScriptId, document_id.serialize());
                }
            } else if was_active {
                batch
                    .with_collection(Collection::Principal)
                    .with_document(0)
                    .clear(PrincipalField::ActiveScriptId);
            }

            // Write changes
            if !batch.is_empty() {
                response.new_state = Some(
                    self.commit_batch(batch)
                        .await
                        .and_then(|ids| ids.last_change_id(account_id))
                        .caused_by(trc::location!())?
                        .into(),
                );
            }

            // Add result
            if let Some(create_id) = create_id {
                response.created.insert(
                    create_id,
                    Map::with_capacity(1)
                        .with_key_value(VacationResponseProperty::Id, Id::singleton())
                        .into(),
                );
            } else {
                response.updated.append(Id::singleton(), None);
            }
        } else if !will_destroy.is_empty() {
            for id in will_destroy {
                if id.is_singleton()
                    && let Some(document_id) = self.get_vacation_sieve_script_id(account_id).await?
                {
                    self.sieve_script_delete(account_id, document_id, access_token, &mut batch)
                        .await?;
                    if active_script_id == Some(document_id) {
                        batch
                            .with_collection(Collection::Principal)
                            .with_document(0)
                            .clear(PrincipalField::ActiveScriptId);
                    }

                    response.destroyed.push(id);
                    break;
                }

                response.not_destroyed.append(id, SetError::not_found());
            }

            // Write changes
            if !batch.is_empty() {
                response.new_state = Some(
                    self.commit_batch(batch)
                        .await
                        .and_then(|ids| ids.last_change_id(account_id))
                        .caused_by(trc::location!())?
                        .into(),
                );
            }
        }

        Ok(response)
    }

    fn build_script(&self, obj: &mut SieveScript) -> trc::Result<Vec<u8>> {
        // Build Sieve script
        let mut script = Vec::with_capacity(1024);
        script.extend_from_slice(b"require [\"vacation\", \"relational\", \"date\"];\r\n\r\n");
        let mut num_blocks = 0;

        // Add start date
        if let Some(value) = obj.vacation_response.as_ref().and_then(|v| v.from_date) {
            script.extend_from_slice(b"if currentdate :value \"ge\" \"iso8601\" \"");
            script.extend_from_slice(UTCDate::from(value).to_string().as_bytes());
            script.extend_from_slice(b"\" {\r\n");
            num_blocks += 1;
        }

        // Add end date
        if let Some(value) = obj.vacation_response.as_ref().and_then(|v| v.to_date) {
            script.extend_from_slice(b"if currentdate :value \"le\" \"iso8601\" \"");
            script.extend_from_slice(UTCDate::from(value).to_string().as_bytes());
            script.extend_from_slice(b"\" {\r\n");
            num_blocks += 1;
        }

        script.extend_from_slice(b"vacation :mime ");
        if let Some(value) = obj
            .vacation_response
            .as_ref()
            .and_then(|v| v.subject.as_ref())
        {
            script.extend_from_slice(b":subject \"");
            for &ch in value.as_bytes().iter() {
                match ch {
                    b'\\' | b'\"' => {
                        script.push(b'\\');
                    }
                    b'\r' | b'\n' => {
                        continue;
                    }
                    _ => (),
                }
                script.push(ch);
            }
            script.extend_from_slice(b"\" ");
        }

        let mut text_body = if let Some(value) = obj
            .vacation_response
            .as_ref()
            .and_then(|v| v.text_body.as_ref())
        {
            Cow::from(value.as_str()).into()
        } else {
            None
        };
        let html_body = if let Some(value) = obj
            .vacation_response
            .as_ref()
            .and_then(|v| v.html_body.as_ref())
        {
            Cow::from(value.as_str()).into()
        } else {
            None
        };
        match (&html_body, &text_body) {
            (Some(html_body), None) => {
                text_body = Cow::from(html_to_text(html_body.as_ref())).into();
            }
            (None, None) => {
                text_body = Cow::from("I am away.").into();
            }
            _ => (),
        }

        let mut builder = MessageBuilder::new();
        let mut body_len = 0;
        if let Some(html_body) = html_body {
            body_len = html_body.len();
            builder = builder.html_body(html_body);
        }
        if let Some(text_body) = text_body {
            body_len += text_body.len();
            builder = builder.text_body(text_body);
        }
        let mut message_body = Vec::with_capacity(body_len + 128);
        builder.write_body(&mut message_body).ok();

        script.push(b'\"');
        for ch in message_body {
            if [b'\\', b'\"'].contains(&ch) {
                script.push(b'\\');
            }
            script.push(ch);
        }
        script.extend_from_slice(b"\";\r\n");

        // Close blocks
        for _ in 0..num_blocks {
            script.extend_from_slice(b"}\r\n");
        }

        match self.core.sieve.untrusted_compiler.compile(&script) {
            Ok(compiled_script) => {
                // Update blob length
                obj.size = script.len() as u32;

                // Serialize script
                script.extend(
                    Archiver::new(compiled_script)
                        .untrusted()
                        .serialize()
                        .caused_by(trc::location!())?,
                );

                Ok(script)
            }
            Err(err) => Err(trc::StoreEvent::UnexpectedError
                .caused_by(trc::location!())
                .reason(err)
                .details("Vacation Sieve Script failed to compile.")),
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
