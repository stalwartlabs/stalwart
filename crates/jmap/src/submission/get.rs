/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::changes::state::StateManager;
use common::Server;
use email::submission::{
    ArchivedAddress, ArchivedEnvelope, ArchivedUndoStatus, Delivered, DeliveryStatus,
    EmailSubmission,
};
use jmap_proto::{
    method::get::{GetRequest, GetResponse},
    object::email_submission::{self, Displayed, EmailSubmissionProperty, EmailSubmissionValue},
    types::date::UTCDate,
};
use jmap_tools::{Key, Map, Value};
use smtp::queue::{ArchivedError, ArchivedErrorDetails, ArchivedStatus, Message, spool::SmtpSpool};
use smtp_proto::ArchivedResponse;
use std::future::Future;
use store::{
    IterateParams, U32_LEN, ValueKey,
    rkyv::option::ArchivedOption,
    write::{
        AlignedBytes, Archive, IndexPropertyClass, ValueClass, key::DeserializeBigEndian, now,
    },
};
use trc::AddContext;
use types::{
    collection::{Collection, SyncCollection},
    field::EmailSubmissionField,
    id::Id,
};
use utils::map::vec_map::VecMap;

pub trait EmailSubmissionGet: Sync + Send {
    fn email_submission_get(
        &self,
        request: GetRequest<email_submission::EmailSubmission>,
    ) -> impl Future<Output = trc::Result<GetResponse<email_submission::EmailSubmission>>> + Send;
}

impl EmailSubmissionGet for Server {
    async fn email_submission_get(
        &self,
        mut request: GetRequest<email_submission::EmailSubmission>,
    ) -> trc::Result<GetResponse<email_submission::EmailSubmission>> {
        let ids = request.unwrap_ids(self.core.jmap.get_max_objects)?;
        let properties = request.unwrap_properties(&[
            EmailSubmissionProperty::Id,
            EmailSubmissionProperty::EmailId,
            EmailSubmissionProperty::IdentityId,
            EmailSubmissionProperty::ThreadId,
            EmailSubmissionProperty::Envelope,
            EmailSubmissionProperty::SendAt,
            EmailSubmissionProperty::UndoStatus,
            EmailSubmissionProperty::DeliveryStatus,
            EmailSubmissionProperty::DsnBlobIds,
            EmailSubmissionProperty::MdnBlobIds,
        ]);
        let account_id = request.account_id.document_id();
        let ids = if let Some(ids) = ids {
            ids
        } else {
            let mut ids = Vec::with_capacity(16);

            self.store()
                .iterate(
                    IterateParams::new(
                        ValueKey {
                            account_id,
                            collection: Collection::CalendarEventNotification.into(),
                            document_id: 0,
                            class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                property: EmailSubmissionField::Metadata.into(),
                                value: now() - (3 * 86400),
                            }),
                        },
                        ValueKey {
                            account_id,
                            collection: Collection::CalendarEventNotification.into(),
                            document_id: 0,
                            class: ValueClass::IndexProperty(IndexPropertyClass::Integer {
                                property: EmailSubmissionField::Metadata.into(),
                                value: u64::MAX,
                            }),
                        },
                    )
                    .ascending()
                    .no_values(),
                    |key, _| {
                        ids.push(Id::from(key.deserialize_be_u32(key.len() - U32_LEN)?));

                        Ok(ids.len() < self.core.jmap.get_max_objects)
                    },
                )
                .await
                .caused_by(trc::location!())?;

            ids
        };
        let mut response = GetResponse {
            account_id: request.account_id.into(),
            state: self
                .get_state(account_id, SyncCollection::EmailSubmission)
                .await?
                .into(),
            list: Vec::with_capacity(ids.len()),
            not_found: vec![],
        };

        for id in ids {
            // Obtain the email_submission object
            let document_id = id.document_id();
            let submission_ = if let Some(submission) = self
                .store()
                .get_value::<Archive<AlignedBytes>>(ValueKey::archive(
                    account_id,
                    Collection::EmailSubmission,
                    document_id,
                ))
                .await?
            {
                submission
            } else {
                response.not_found.push(id);
                continue;
            };
            let submission = submission_
                .unarchive::<EmailSubmission>()
                .caused_by(trc::location!())?;

            // Obtain queueId
            let mut delivery_status = submission
                .delivery_status
                .iter()
                .map(|(k, v)| (k.to_string(), DeliveryStatus::from(v)))
                .collect::<VecMap<_, _>>();
            let mut is_pending = false;
            if let Some(queue_id) = submission.queue_id.as_ref().map(u64::from)
                && let Some(queued_message_) = self
                    .read_message_archive(queue_id)
                    .await
                    .caused_by(trc::location!())?
            {
                let queued_message = queued_message_
                    .unarchive::<Message>()
                    .caused_by(trc::location!())?;
                for rcpt in queued_message.recipients.iter() {
                    *delivery_status.get_mut_or_insert(rcpt.address().to_string()) =
                        DeliveryStatus {
                            smtp_reply: match &rcpt.status {
                                ArchivedStatus::Completed(reply) => {
                                    format_archived_response(&reply.response)
                                }
                                ArchivedStatus::TemporaryFailure(reply)
                                | ArchivedStatus::PermanentFailure(reply) => {
                                    format_archived_error_details(reply)
                                }
                                ArchivedStatus::Scheduled => "250 2.1.5 Queued".to_string(),
                            },
                            delivered: match &rcpt.status {
                                ArchivedStatus::Scheduled | ArchivedStatus::TemporaryFailure(_) => {
                                    Delivered::Queued
                                }
                                ArchivedStatus::Completed(_) => Delivered::Yes,
                                ArchivedStatus::PermanentFailure(_) => Delivered::No,
                            },
                            displayed: false,
                        };
                }
                is_pending = true;
            }

            let mut result = Map::with_capacity(properties.len());
            for property in &properties {
                let value = match property {
                    EmailSubmissionProperty::Id => Value::Element(id.into()),
                    EmailSubmissionProperty::DeliveryStatus => {
                        let mut status = Map::with_capacity(delivery_status.len());

                        for (rcpt, delivery_status) in std::mem::take(&mut delivery_status) {
                            status.insert_unchecked(
                                Key::Owned(rcpt),
                                Map::with_capacity(3)
                                    .with_key_value(
                                        EmailSubmissionProperty::Delivered,
                                        EmailSubmissionValue::Delivered(
                                            match delivery_status.delivered {
                                                Delivered::Queued => {
                                                    email_submission::Delivered::Queued
                                                }
                                                Delivered::Yes => email_submission::Delivered::Yes,
                                                Delivered::No => email_submission::Delivered::No,
                                                Delivered::Unknown => {
                                                    email_submission::Delivered::Unknown
                                                }
                                            },
                                        ),
                                    )
                                    .with_key_value(
                                        EmailSubmissionProperty::SmtpReply,
                                        delivery_status.smtp_reply,
                                    )
                                    .with_key_value(
                                        EmailSubmissionProperty::Displayed,
                                        Value::Element(EmailSubmissionValue::Displayed(
                                            Displayed::Unknown,
                                        )),
                                    ),
                            );
                        }

                        Value::Object(status)
                    }
                    EmailSubmissionProperty::UndoStatus => {
                        Value::Element(EmailSubmissionValue::UndoStatus(if is_pending {
                            email_submission::UndoStatus::Pending
                        } else {
                            match submission.undo_status {
                                ArchivedUndoStatus::Pending => {
                                    email_submission::UndoStatus::Pending
                                }
                                ArchivedUndoStatus::Final => email_submission::UndoStatus::Final,
                                ArchivedUndoStatus::Canceled => {
                                    email_submission::UndoStatus::Canceled
                                }
                            }
                        }))
                    }
                    EmailSubmissionProperty::EmailId => Value::Element(
                        Id::from_parts(
                            u32::from(submission.thread_id),
                            u32::from(submission.email_id),
                        )
                        .into(),
                    ),
                    EmailSubmissionProperty::IdentityId => {
                        Value::Element(Id::from(u32::from(submission.identity_id)).into())
                    }
                    EmailSubmissionProperty::ThreadId => {
                        Value::Element(Id::from(u32::from(submission.thread_id)).into())
                    }
                    EmailSubmissionProperty::Envelope => build_envelope(&submission.envelope),
                    EmailSubmissionProperty::SendAt => Value::Element(EmailSubmissionValue::Date(
                        UTCDate::from_timestamp(u64::from(submission.send_at) as i64),
                    )),
                    EmailSubmissionProperty::MdnBlobIds | EmailSubmissionProperty::DsnBlobIds => {
                        Value::Array(vec![])
                    }
                    _ => Value::Null,
                };

                result.insert_unchecked(property.clone(), value);
            }
            response.list.push(result.into());
        }

        Ok(response)
    }
}

fn build_envelope(
    envelope: &ArchivedEnvelope,
) -> Value<'static, EmailSubmissionProperty, EmailSubmissionValue> {
    Map::with_capacity(2)
        .with_key_value(
            EmailSubmissionProperty::MailFrom,
            build_address(&envelope.mail_from),
        )
        .with_key_value(
            EmailSubmissionProperty::RcptTo,
            Value::Array(envelope.rcpt_to.iter().map(build_address).collect()),
        )
        .into()
}

fn build_address(
    envelope: &ArchivedAddress,
) -> Value<'static, EmailSubmissionProperty, EmailSubmissionValue> {
    Map::with_capacity(2)
        .with_key_value(
            EmailSubmissionProperty::Email,
            Value::Str(envelope.email.to_string().into()),
        )
        .with_key_value(
            EmailSubmissionProperty::Parameters,
            if let ArchivedOption::Some(params) = &envelope.parameters {
                Value::Object(Map::from_iter(
                    params
                        .iter()
                        .map(|(k, v)| (Key::Owned(k.to_string()), v.into())),
                ))
            } else {
                Value::Null
            },
        )
        .into()
}

fn format_archived_response(response: &ArchivedResponse<Box<str>>) -> String {
    format!(
        "Code: {}, Enhanced code: {}.{}.{}, Message: {}",
        response.code,
        response.esc[0],
        response.esc[1],
        response.esc[2],
        response.message.replace('\n', " "),
    )
}

fn format_archived_error_details(response: &ArchivedErrorDetails) -> String {
    match &response.details {
        ArchivedError::UnexpectedResponse(response) => format_archived_response(&response.response),
        ArchivedError::DnsError(details)
        | ArchivedError::Io(details)
        | ArchivedError::ConnectionError(details)
        | ArchivedError::TlsError(details)
        | ArchivedError::DaneError(details)
        | ArchivedError::MtaStsError(details) => details.to_string(),
        ArchivedError::RateLimited => "Rate limited".to_string(),
        ArchivedError::ConcurrencyLimited => "Concurrency limited".to_string(),
    }
}
