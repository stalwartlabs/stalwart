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
use jmap_tools::{Element, Property, Value};
use types::id::Id;

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
}

pub(crate) trait EvalObjectReferences {
    fn eval_object_references(
        &mut self,
        response: &Response<'_>,
        graph: &mut Graph<'_>,
    ) -> trc::Result<()>;
}

impl<'x, P, E> EvalObjectReferences for Value<'x, P, E>
where
    P: Property,
    E: Element<Property = P> + JmapObjectId + TryFrom<AnyId>,
{
    fn eval_object_references(
        &mut self,
        response: &Response<'_>,
        graph: &mut Graph<'_>,
    ) -> trc::Result<()> {
        let Value::Object(obj) = self else {
            return Ok(());
        };

        for (_, value) in obj.as_mut_vec() {
            match value {
                Value::Element(element) => {
                    if let Some(id_ref) = element.as_id_ref() {
                        if let Some(id) = response.created_ids.get(id_ref) {
                            match E::try_from(id.clone()) {
                                Ok(eid) => {
                                    *element = eid;
                                }
                                Err(_) => {
                                    return Err(trc::JmapEvent::InvalidResultReference
                                        .into_err()
                                        .details(format_compact!(
                                            "Id reference {id_ref:?} points to invalid type."
                                        )));
                                }
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
                Value::Array(items) => {
                    for item in items {
                        item.eval_object_references(response, graph)?;
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
