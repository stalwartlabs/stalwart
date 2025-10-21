/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    error::set::SetError,
    method::{
        copy::CopyRequest,
        get::GetRequest,
        import::ImportEmailRequest,
        parse::ParseRequest,
        search_snippet::GetSearchSnippetRequest,
        set::{SetRequest, SetResponse},
        upload::{BlobUploadRequest, DataSourceObject},
    },
    object::{AnyId, JmapObject, JmapObjectId},
    references::{Graph, eval::EvalObjectReferences, topological_sort},
    request::{
        CopyRequestMethod, GetRequestMethod, MaybeInvalid, ParseRequestMethod, RequestMethod,
        SetRequestMethod,
        reference::{MaybeIdReference, MaybeResultReference},
    },
    response::Response,
};
use compact_str::format_compact;
use jmap_tools::{Element, Key, Property, Value};
use std::collections::HashMap;
use types::id::Id;

impl Response<'_> {
    pub fn resolve_references(&self, request: &mut RequestMethod) -> trc::Result<()> {
        match request {
            RequestMethod::Get(request) => match request {
                GetRequestMethod::Email(request) => request.resolve_references(self)?,
                GetRequestMethod::Mailbox(request) => request.resolve_references(self)?,
                GetRequestMethod::Thread(request) => request.resolve_references(self)?,
                GetRequestMethod::Identity(request) => request.resolve_references(self)?,
                GetRequestMethod::EmailSubmission(request) => request.resolve_references(self)?,
                GetRequestMethod::PushSubscription(request) => request.resolve_references(self)?,
                GetRequestMethod::Sieve(request) => request.resolve_references(self)?,
                GetRequestMethod::VacationResponse(request) => request.resolve_references(self)?,
                GetRequestMethod::Principal(request) => request.resolve_references(self)?,
                GetRequestMethod::Quota(request) => request.resolve_references(self)?,
                GetRequestMethod::Blob(request) => request.resolve_references(self)?,
                GetRequestMethod::AddressBook(request) => request.resolve_references(self)?,
                GetRequestMethod::ContactCard(request) => request.resolve_references(self)?,
                GetRequestMethod::FileNode(request) => request.resolve_references(self)?,
                GetRequestMethod::ShareNotification(request) => request.resolve_references(self)?,
                GetRequestMethod::Calendar(request) => request.resolve_references(self)?,
                GetRequestMethod::CalendarEvent(request) => request.resolve_references(self)?,
                GetRequestMethod::CalendarEventNotification(request) => {
                    request.resolve_references(self)?
                }
                GetRequestMethod::ParticipantIdentity(request) => {
                    request.resolve_references(self)?
                }
                GetRequestMethod::PrincipalAvailability(_) => (),
            },
            RequestMethod::Set(request) => match request {
                SetRequestMethod::Email(request) => request.resolve_references(self)?,
                SetRequestMethod::Mailbox(request) => request.resolve_references(self)?,
                SetRequestMethod::Identity(request) => request.resolve_references(self)?,
                SetRequestMethod::EmailSubmission(request) => request.resolve_references(self)?,
                SetRequestMethod::PushSubscription(request) => request.resolve_references(self)?,
                SetRequestMethod::Sieve(request) => request.resolve_references(self)?,
                SetRequestMethod::VacationResponse(request) => request.resolve_references(self)?,
                SetRequestMethod::AddressBook(request) => request.resolve_references(self)?,
                SetRequestMethod::ContactCard(request) => request.resolve_references(self)?,
                SetRequestMethod::FileNode(request) => request.resolve_references(self)?,
                SetRequestMethod::ShareNotification(request) => request.resolve_references(self)?,
                SetRequestMethod::Calendar(request) => request.resolve_references(self)?,
                SetRequestMethod::CalendarEvent(request) => request.resolve_references(self)?,
                SetRequestMethod::CalendarEventNotification(request) => {
                    request.resolve_references(self)?
                }
                SetRequestMethod::ParticipantIdentity(request) => {
                    request.resolve_references(self)?
                }
            },
            RequestMethod::Copy(request) => match request {
                CopyRequestMethod::Email(request) => request.resolve_references(self)?,
                CopyRequestMethod::CalendarEvent(request) => request.resolve_references(self)?,
                CopyRequestMethod::ContactCard(request) => request.resolve_references(self)?,
                CopyRequestMethod::Blob(_) => (),
            },
            RequestMethod::ImportEmail(request) => request.resolve_references(self)?,
            RequestMethod::SearchSnippet(request) => request.resolve_references(self)?,
            RequestMethod::UploadBlob(request) => request.resolve_references(self)?,
            RequestMethod::Parse(request) => match request {
                ParseRequestMethod::Email(request) => request.resolve_references(self)?,
                ParseRequestMethod::ContactCard(request) => request.resolve_references(self)?,
                ParseRequestMethod::CalendarEvent(request) => request.resolve_references(self)?,
            },
            _ => {}
        }

        Ok(())
    }
}

pub trait ResolveCreatedReference<P, E>
where
    P: Property,
    E: Element<Property = P> + JmapObjectId,
{
    fn get_created_id(&self, id_ref: &str) -> Option<AnyId>;

    fn resolve_self_references(&self, value: &mut Value<'_, P, E>) -> Result<(), SetError<P>> {
        match value {
            Value::Element(element) => {
                if let Some(id_ref) = element.as_id_ref() {
                    if let Some(id) = self.get_created_id(id_ref) {
                        if !element.try_set_id(id) {
                            return Err(SetError::invalid_properties()
                                .with_description("Id reference points to invalid type."));
                        }
                    } else {
                        return Err(SetError::not_found()
                            .with_description(format!("Id reference {id_ref:?} not found.")));
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.resolve_self_references(item)?;
                }
            }
            _ => {}
        }

        Ok(())
    }
}

pub(crate) trait ResolveReference {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()>;
}

impl<T: JmapObject> ResolveReference for GetRequest<T> {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        // Resolve id references
        match &mut self.ids {
            Some(MaybeResultReference::Reference(reference)) => {
                self.ids = Some(MaybeResultReference::Value(
                    response
                        .eval_result_references(reference)?
                        .into_ids::<T::Id>(reference)
                        .map(|f| f.map(MaybeIdReference::Id))
                        .collect::<Result<_, _>>()?,
                ));
            }
            Some(MaybeResultReference::Value(ids)) => {
                for id in ids {
                    if let MaybeIdReference::Reference(reference) = id {
                        if let Some(resolved_id) = response
                            .created_ids
                            .get(reference)
                            .cloned()
                            .and_then(|v| T::Id::try_from(v).ok())
                        {
                            *id = MaybeIdReference::Id(resolved_id);
                        } else {
                            return Err(trc::JmapEvent::InvalidResultReference.into_err().details(
                                format_compact!(
                                    "Id reference {reference:?} does not exist or is invalid."
                                ),
                            ));
                        }
                    }
                }
            }
            _ => (),
        }

        // Resolve properties references
        if let Some(MaybeResultReference::Reference(reference)) = &self.properties {
            self.properties = Some(MaybeResultReference::Value(
                response
                    .eval_result_references(reference)?
                    .into_properties::<T::Property>(reference)
                    .map(|f| f.map(MaybeInvalid::Value))
                    .collect::<Result<_, _>>()?,
            ));
        }

        Ok(())
    }
}

impl<'x, T: JmapObject> ResolveReference for SetRequest<'x, T> {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        // Resolve create references
        if let Some(create) = &mut self.create {
            let mut graph = HashMap::with_capacity(create.len());
            for (id, obj) in create.iter_mut() {
                obj.eval_object_references(
                    response,
                    &mut Graph::Some {
                        child_id: &*id,
                        graph: &mut graph,
                    },
                    0,
                )?;
            }

            // Perform topological sort
            if !graph.is_empty() {
                self.create = topological_sort(create, graph)?.into();
            }
        }

        // Resolve update references
        if let Some(update) = &mut self.update {
            for obj in update.values_mut() {
                obj.eval_object_references(response, &mut Graph::None, 0)?;
            }
        }

        // Resolve destroy references
        if let Some(MaybeResultReference::Reference(reference)) = &self.destroy {
            self.destroy = Some(MaybeResultReference::Value(
                response
                    .eval_result_references(reference)?
                    .into_ids::<Id>(reference)
                    .map(|f| f.map(MaybeInvalid::Value))
                    .collect::<Result<_, _>>()?,
            ));
        }

        Ok(())
    }
}

impl<'x, T: JmapObject> ResolveReference for CopyRequest<'x, T> {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        // Resolve create references
        for (id, obj) in self.create.iter_mut() {
            obj.eval_object_references(response, &mut Graph::None, 0)?;

            if let MaybeIdReference::Reference(ir) = id {
                *id = MaybeIdReference::Id(response.eval_id_reference(ir)?);
            }
        }

        Ok(())
    }
}

impl<T: JmapObject> ResolveReference for ParseRequest<T> {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        // Resolve blobId references
        for id in self.blob_ids.iter_mut() {
            if let MaybeIdReference::Reference(ir) = id {
                *id = MaybeIdReference::Id(response.eval_blob_id_reference(ir)?);
            }
        }

        Ok(())
    }
}

impl ResolveReference for ImportEmailRequest {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        // Resolve email mailbox references
        for email in self.emails.values_mut() {
            match &mut email.mailbox_ids {
                MaybeResultReference::Reference(reference) => {
                    email.mailbox_ids = MaybeResultReference::Value(
                        response
                            .eval_result_references(reference)?
                            .into_ids::<Id>(reference)
                            .map(|f| f.map(MaybeIdReference::Id))
                            .collect::<Result<_, _>>()?,
                    );
                }
                MaybeResultReference::Value(values) => {
                    for value in values {
                        if let MaybeIdReference::Reference(ir) = value {
                            *value = MaybeIdReference::Id(response.eval_id_reference(ir)?);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl ResolveReference for GetSearchSnippetRequest {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        // Resolve emailIds references
        if let MaybeResultReference::Reference(reference) = &self.email_ids {
            self.email_ids = MaybeResultReference::Value(
                response
                    .eval_result_references(reference)?
                    .into_ids::<Id>(reference)
                    .map(|f| f.map(MaybeInvalid::Value))
                    .collect::<Result<_, _>>()?,
            );
        }

        Ok(())
    }
}

impl ResolveReference for BlobUploadRequest {
    fn resolve_references(&mut self, response: &Response<'_>) -> trc::Result<()> {
        let mut graph = HashMap::with_capacity(self.create.len());
        for (create_id, object) in self.create.iter_mut() {
            for data in &mut object.data {
                if let DataSourceObject::Id { id, .. } = data
                    && let MaybeIdReference::Reference(parent_id) = id
                {
                    match response.created_ids.get(parent_id) {
                        Some(AnyId::BlobId(blob_id)) => {
                            *id = MaybeIdReference::Id(blob_id.clone());
                        }
                        Some(_) => {
                            return Err(trc::JmapEvent::InvalidResultReference.into_err().details(
                                format_compact!(
                                    "Id reference {parent_id:?} points to invalid type."
                                ),
                            ));
                        }
                        None => {
                            graph
                                .entry(create_id.to_string())
                                .or_insert_with(Vec::new)
                                .push(parent_id.to_string());
                        }
                    }
                }
            }
        }

        // Perform topological sort
        if !graph.is_empty() {
            self.create = topological_sort(&mut self.create, graph)?;
        }

        Ok(())
    }
}

impl<T> ResolveCreatedReference<T::Property, T::Element> for SetResponse<T>
where
    T: JmapObject,
{
    fn get_created_id(&self, id_ref: &str) -> Option<AnyId> {
        self.created
            .get(id_ref)
            .and_then(|v| v.as_object())
            .and_then(|v| v.get(&Key::Property(T::ID_PROPERTY)))
            .and_then(|v| v.as_element())
            .and_then(|v| v.as_any_id())
    }
}
