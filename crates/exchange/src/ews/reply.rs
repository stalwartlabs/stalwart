/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use exchange_proto::{
    ews::{
        Operation, ResponseShape, Status,
        envelope::EnvelopeWriter,
        responses::{
            ShapeB,
            attachment::AttachmentInfoMessage,
            folder::EmptyMessage,
            item::{ItemInfoMessage, UpdateItemMessage},
            mailtips::GetPasswordExpirationDateBody,
            people::{GetPersonaBody, GetUserPhotoBody},
            reminder::{GetRemindersBody, PerformReminderActionBody},
        },
        types::value::M,
    },
    xml::{XmlWrite, XmlWriter},
};
use http_proto::HttpResponse;
use hyper::StatusCode;

pub(crate) const EWS_CONTENT_TYPE: &str = "text/xml; charset=utf-8";
pub(crate) const RESPONSE_CAPACITY: usize = 4096;
const OOF_MESSAGE: &str = "ResponseMessage";

pub(crate) fn ews_response(body: Vec<u8>) -> HttpResponse {
    HttpResponse::new(StatusCode::OK)
        .with_content_type(EWS_CONTENT_TYPE)
        .with_binary_body(body)
        .with_no_store()
}

pub(crate) fn write_operation_error(
    envelope: EnvelopeWriter<'_>,
    op: Operation,
    status: &Status<'_>,
) {
    match op.shape() {
        ResponseShape::A => {
            let mut messages = envelope.shape_a(op);
            match op {
                Operation::CreateItem
                | Operation::GetItem
                | Operation::MoveItem
                | Operation::CopyItem
                | Operation::ArchiveItem
                | Operation::UpdateItemInRecoverableItems => {
                    messages.empty_message::<ItemInfoMessage>(status)
                }
                Operation::UpdateItem => messages.empty_message::<UpdateItemMessage>(status),
                Operation::GetAttachment | Operation::CreateAttachment => {
                    messages.empty_message::<AttachmentInfoMessage>(status)
                }
                _ => messages.begin_message(status).finish(),
            }
            messages.finish();
        }
        ResponseShape::B if op == Operation::GetUserPhoto => {
            envelope.body(&ShapeB::<GetUserPhotoBody> {
                op,
                status: status.clone(),
                body: None,
            })
        }
        ResponseShape::B if op == Operation::GetPasswordExpirationDate => {
            envelope.body(&ShapeB::<GetPasswordExpirationDateBody> {
                op,
                status: status.clone(),
                body: None,
            })
        }
        ResponseShape::B if op == Operation::GetPersona => {
            envelope.body(&ShapeB::<GetPersonaBody> {
                op,
                status: status.clone(),
                body: None,
            })
        }
        ResponseShape::B if op == Operation::GetReminders => {
            envelope.body(&ShapeB::<GetRemindersBody> {
                op,
                status: status.clone(),
                body: None,
            })
        }
        ResponseShape::B if op == Operation::PerformReminderAction => {
            envelope.body(&ShapeB::<PerformReminderActionBody> {
                op,
                status: status.clone(),
                body: None,
            })
        }
        ResponseShape::B | ResponseShape::D => envelope.body(&ShapeB::<EmptyMessage> {
            op,
            status: status.clone(),
            body: None,
        }),
        ResponseShape::C => envelope.body(&ShapeCError { op, status }),
    }
}

struct ShapeCError<'s, 'x> {
    op: Operation,
    status: &'s Status<'x>,
}

impl XmlWrite for ShapeCError<'_, '_> {
    fn write(&self, w: &mut XmlWriter<'_>) {
        let root = self.op.response_root();
        w.start(M, root);
        if self.op != Operation::GetUserAvailability {
            w.start(M, OOF_MESSAGE)
                .attr("ResponseClass", self.status.class.as_str());
            self.status.write_children(w);
            w.end(M, OOF_MESSAGE);
        }
        w.end(M, root);
    }
}
