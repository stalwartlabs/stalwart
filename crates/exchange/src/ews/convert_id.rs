/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    context::EwsContext,
    reply::{RESPONSE_CAPACITY, ews_response},
};
use exchange_proto::{
    ews::{
        MessageResult, Operation, Status,
        requests::resolve::ConvertId,
        responses::resolve::ConvertIdMessage,
        schema::{IdFormat, ResponseCode},
        types::ids::AlternateId,
    },
    ids::ews::EwsObjectId,
};
use http_proto::HttpResponse;

const ID_MALFORMED: &str = "Id is malformed.";
const UNSUPPORTED_FORMAT: &str = "The requested id conversion is not supported.";
const PUBLIC_FOLDERS: &str = "Public folders are not supported.";

pub(crate) fn convert_id(ctx: &EwsContext, request: &ConvertId<'_>) -> HttpResponse {
    let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
    let mut messages = ctx.envelope(&mut out).shape_a(Operation::ConvertId);
    for source in &request.source_ids {
        messages.message(&convert(source, request.destination_format));
    }
    messages.finish();
    ews_response(out)
}

pub(crate) fn convert<'x>(
    source: &AlternateId<'x>,
    destination: IdFormat,
) -> MessageResult<'static, ConvertIdMessage<'x>> {
    let AlternateId::Mailbox {
        format,
        id,
        mailbox,
        is_archive,
    } = source
    else {
        return MessageResult {
            status: Status::error(ResponseCode::ErrorInvalidRequest, PUBLIC_FOLDERS),
            body: None,
        };
    };
    let status = match (is_ews_format(*format), is_ews_format(destination)) {
        (true, _) if EwsObjectId::decode(id.as_str()).is_none() => {
            Status::error(ResponseCode::ErrorInvalidIdMalformed, ID_MALFORMED)
        }
        (true, true) => Status::SUCCESS,
        _ if *format == destination => Status::SUCCESS,
        _ => Status::error(ResponseCode::ErrorInternalServerError, UNSUPPORTED_FORMAT),
    };
    if status.code != ResponseCode::NoError {
        return MessageResult { status, body: None };
    }
    MessageResult {
        status,
        body: Some(ConvertIdMessage {
            alternate_id: Some(AlternateId::Mailbox {
                format: destination,
                id: id.clone(),
                mailbox: mailbox.clone(),
                is_archive: *is_archive,
            }),
        }),
    }
}

fn is_ews_format(format: IdFormat) -> bool {
    matches!(format, IdFormat::EwsId | IdFormat::EwsLegacyId)
}
