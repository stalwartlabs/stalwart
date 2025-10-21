/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{AnyId, JmapObjectId},
    references::{
        Graph,
        jsptr::{EvalResults, ResponsePtr},
    },
    request::reference::ResultReference,
    response::{ChangesResponseMethod, GetResponseMethod, Response, ResponseMethod},
};
use compact_str::format_compact;
use jmap_tools::{Element, Key, Property, Value};
use types::{blob::BlobId, id::Id};

impl Response<'_> {
    pub(crate) fn eval_result_references(&self, rr: &ResultReference) -> trc::Result<EvalResults> {
        let mut results = EvalResults::default();

        for response in &self.method_responses {
            if response.id == rr.result_of && response.name == rr.name {
                let path = rr.path.iter();
                let success = match &response.method {
                    ResponseMethod::Get(response) => match response {
                        GetResponseMethod::Email(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Mailbox(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Thread(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Identity(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::EmailSubmission(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::PushSubscription(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Sieve(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::VacationResponse(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Principal(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Quota(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Blob(response) => response.eval_jptr(path, &mut results),
                        GetResponseMethod::AddressBook(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::ContactCard(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::FileNode(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::Calendar(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::CalendarEvent(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::CalendarEventNotification(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::ParticipantIdentity(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::ShareNotification(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        GetResponseMethod::PrincipalAvailability(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                    },
                    ResponseMethod::Changes(response) => match response {
                        ChangesResponseMethod::Email(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::Mailbox(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::Thread(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::Identity(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::EmailSubmission(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::Quota(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::AddressBook(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::ContactCard(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::FileNode(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::Calendar(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::CalendarEvent(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::CalendarEventNotification(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                        ChangesResponseMethod::ShareNotification(response) => {
                            response.eval_jptr(path, &mut results)
                        }
                    },
                    ResponseMethod::Query(response) => response.eval_jptr(path, &mut results),
                    ResponseMethod::QueryChanges(response) => {
                        response.eval_jptr(path, &mut results)
                    }
                    _ => false,
                };

                if success {
                    return Ok(results);
                }
            }
        }

        Err(trc::JmapEvent::InvalidResultReference
            .into_err()
            .details(format_compact!(
                "Result reference to {}#{} not found.",
                rr.result_of,
                rr.name
            )))
    }

    pub(crate) fn eval_id_reference(&self, ir: &str) -> trc::Result<Id> {
        if let Some(AnyId::Id(id)) = self.created_ids.get(ir) {
            Ok(*id)
        } else {
            Err(trc::JmapEvent::InvalidResultReference
                .into_err()
                .details(format_compact!("Id reference {ir:?} not found.")))
        }
    }

    pub(crate) fn eval_blob_id_reference(&self, ir: &str) -> trc::Result<BlobId> {
        if let Some(AnyId::BlobId(id)) = self.created_ids.get(ir) {
            Ok(id.clone())
        } else {
            Err(trc::JmapEvent::InvalidResultReference
                .into_err()
                .details(format_compact!("blobId reference {ir:?} not found.")))
        }
    }
}

pub(crate) trait EvalObjectReferences {
    fn eval_object_references(
        &mut self,
        response: &Response<'_>,
        graph: &mut Graph<'_>,
        depth: usize,
    ) -> trc::Result<()>;
}

impl<'x, P, E> EvalObjectReferences for Value<'x, P, E>
where
    P: Property + JmapObjectId,
    E: Element<Property = P> + JmapObjectId,
{
    fn eval_object_references(
        &mut self,
        response: &Response<'_>,
        graph: &mut Graph<'_>,
        depth: usize,
    ) -> trc::Result<()> {
        let Value::Object(obj) = self else {
            return Ok(());
        };

        for (key, value) in obj.as_mut_vec() {
            // Resolve patch with references (e.g. mailboxIds/#idRef)
            if depth == 0
                && let Key::Property(property) = key
                && let Some(id_ref) = property.as_id_ref()
            {
                if let Some(id) = response.created_ids.get(id_ref) {
                    if !property.try_set_id(id.clone()) {
                        return Err(trc::JmapEvent::InvalidResultReference
                            .into_err()
                            .details("Id reference points to invalid type."));
                    }
                } else {
                    return Err(trc::JmapEvent::InvalidResultReference
                        .into_err()
                        .details(format_compact!("Id reference {id_ref:?} not found.")));
                }
            }

            match value {
                Value::Element(element) => {
                    if let Some(id_ref) = element.as_id_ref() {
                        if let Some(id) = response.created_ids.get(id_ref) {
                            if !element.try_set_id(id.clone()) {
                                return Err(trc::JmapEvent::InvalidResultReference
                                    .into_err()
                                    .details("Id reference points to invalid type."));
                            }
                        } else if let Graph::Some { child_id, graph } = graph {
                            graph
                                .entry(child_id.to_string())
                                .or_insert_with(Vec::new)
                                .push(id_ref.to_string());
                        } else {
                            return Err(trc::JmapEvent::InvalidResultReference
                                .into_err()
                                .details(format_compact!("Id reference {id_ref:?} not found.")));
                        }
                    }
                }
                Value::Array(items) if depth == 0 => {
                    // Resolve references in arrays (e.g. emailIds: [#idRef1, #idRef2])
                    for item in items {
                        item.eval_object_references(response, graph, depth + 1)?;
                    }
                }
                Value::Object(items) if depth == 0 => {
                    // Resolve references in JMAP sets (e.g. mailboxIds: { "#idRef1": true, "#idRef2": true })
                    for (key, _) in items.as_mut_vec() {
                        if let Key::Property(property) = key
                            && let Some(id_ref) = property.as_id_ref()
                        {
                            if let Some(id) = response.created_ids.get(id_ref) {
                                if !property.try_set_id(id.clone()) {
                                    return Err(trc::JmapEvent::InvalidResultReference
                                        .into_err()
                                        .details("Id reference points to invalid type."));
                                }
                            } else {
                                return Err(trc::JmapEvent::InvalidResultReference
                                    .into_err()
                                    .details(format_compact!(
                                        "Id reference {id_ref:?} not found."
                                    )));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
