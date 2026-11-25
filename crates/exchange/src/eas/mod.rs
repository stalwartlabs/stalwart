/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod compose;
pub mod context;
pub mod convert;
pub mod device;
pub mod directory;
pub mod find;
pub mod folder_id;
pub mod folder_sync;
pub mod folder_write;
pub mod get_item_estimate;
pub mod groupware_search;
pub mod item_operations;
pub mod mail_search;
pub mod meeting_response;
pub mod move_items;
pub mod oof;
pub mod ping;
pub mod provision;
pub mod resolve_recipients;
pub mod response;
pub mod search;
pub mod settings;
pub mod sync;
pub mod wait;

use crate::eas::{
    compose::{ComposeBody, EasCompose},
    context::EasContext,
    device::{DeviceGate, EasDeviceAccess},
    find::EasFind,
    folder_sync::EasFolderSync,
    folder_write::EasFolderWrite,
    get_item_estimate::EasGetItemEstimate,
    item_operations::EasItemOperations,
    meeting_response::EasMeetingResponse,
    move_items::EasMoveItems,
    ping::EasPingCommand,
    provision::EasProvision,
    resolve_recipients::EasResolveRecipients,
    response::{ContentCoding, EasResponse, options_response},
    search::EasSearch,
    settings::EasSettings,
    sync::EasSync,
};
use common::{Server, auth::AccessToken};
use exchange_proto::eas::{
    commands::{send_mail::ComposeCommand, validate_cert::ValidateCertRequest},
    http::{BodyKind, Command, EasHeaders, HttpError, classify_body, parse_request_line},
    status::{CommonStatus, HttpOutcome, ValidateCertStatus},
    wbxml::{Decoder, WbxmlLimits},
};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{
    Method, StatusCode,
    header::{ACCEPT_ENCODING, CONTENT_TYPE},
};

pub trait EasHandler: Sync + Send {
    fn handle_eas_request(
        &self,
        request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl EasHandler for Server {
    async fn handle_eas_request(
        &self,
        mut request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        match *request.method() {
            Method::OPTIONS => return Ok(options_response()),
            Method::POST => {}
            _ => return Ok(EasResponse::Http(HttpOutcome::BadRequest).into_http(None)),
        }

        let Some(body) = fetch_body(
            &mut request,
            self.core.exchange.max_request_size,
            session.session_id,
        )
        .await
        else {
            return Ok(HttpResponse::new(StatusCode::PAYLOAD_TOO_LARGE));
        };

        let headers = request.headers();
        let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());
        let eas_headers = EasHeaders {
            protocol_version: header("ms-asprotocolversion"),
            policy_key: header("x-ms-policykey"),
            accept_multipart: header("ms-asacceptmultipart"),
            content_type: header(CONTENT_TYPE.as_str()),
        };
        let coding = ContentCoding::negotiate(
            headers
                .get_all(ACCEPT_ENCODING)
                .iter()
                .map(|value| value.as_bytes()),
        );
        let content_type = eas_headers.content_type.map(str::as_bytes);
        let line = match parse_request_line(request.uri().query().unwrap_or_default(), &eas_headers)
        {
            Ok(line) => line,
            Err(HttpError::InvalidDeviceId { command }) if command != Command::GetAttachment => {
                return Ok(EasResponse::status(
                    command,
                    CommonStatus::DEVICE_ID_MISSING_OR_INVALID.into(),
                )
                .into_http(None));
            }
            Err(HttpError::InvalidDeviceType { command }) if command != Command::GetAttachment => {
                return Ok(EasResponse::status(
                    command,
                    CommonStatus::DEVICE_TYPE_MISSING_OR_INVALID.into(),
                )
                .into_http(None));
            }
            Err(HttpError::UnknownCommand) => {
                return Ok(EasResponse::Http(HttpOutcome::NotImplemented).into_http(None));
            }
            Err(_) => return Ok(EasResponse::Http(HttpOutcome::BadRequest).into_http(None)),
        };
        let Some(version) = line.version else {
            return Ok(EasResponse::Http(HttpOutcome::BadRequest).into_http(None));
        };
        let command = line.command;

        let body_kind = classify_body(content_type, body.len());
        let accepted = match body_kind {
            BodyKind::Wbxml | BodyKind::Empty => true,
            BodyKind::Mime => matches!(
                command,
                Command::SendMail | Command::SmartReply | Command::SmartForward
            ),
            BodyKind::Other => false,
        };
        if !accepted {
            return Ok(EasResponse::refused(
                session.session_id,
                access_token.account_id(),
                command,
                CommonStatus::INVALID_CONTENT.into(),
                &eas_headers.content_type,
            )
            .into_http(Some(version)));
        }

        let Some(device_id) = line.device_id.as_str() else {
            return Ok(EasResponse::status(
                command,
                CommonStatus::DEVICE_ID_MISSING_OR_INVALID.into(),
            )
            .into_http(Some(version)));
        };

        let device = match self
            .eas_device(access_token.account_id(), device_id, &line.device_type)
            .await
        {
            Ok(device) => device,
            Err(err) if err.matches(trc::EventType::Limit(trc::LimitEvent::TooManyRequests)) => {
                return Ok(EasResponse::status(
                    command,
                    CommonStatus::MAXIMUM_DEVICES_REACHED.into(),
                )
                .into_http(Some(version)));
            }
            Err(err) => return Err(err),
        };

        let ctx = EasContext::new(access_token, device, version, line.params, session);

        match self.eas_gate(&ctx, command, line.policy_key).await? {
            DeviceGate::Allow => {}
            DeviceGate::Refuse(response) => return Ok(response.into_http(Some(version))),
        }

        let mut decoder = match body_kind {
            BodyKind::Wbxml => match Decoder::new(&body, &WbxmlLimits::DEFAULT) {
                Ok(decoder) => Some(decoder),
                Err(err) => {
                    return Ok(EasResponse::refused(
                        ctx.session.session_id,
                        ctx.account_id,
                        command,
                        CommonStatus::INVALID_WBXML.into(),
                        &err,
                    )
                    .into_http(Some(version)));
                }
            },
            _ => None,
        };

        let response = match command {
            Command::Provision => self.eas_provision(&ctx, decoder.as_mut()).await?,
            Command::Settings => self.eas_settings(&ctx, decoder.as_mut()).await?,
            Command::FolderSync => self.eas_folder_sync(&ctx, decoder.as_mut()).await?,
            Command::FolderCreate => self.eas_folder_create(&ctx, decoder.as_mut()).await?,
            Command::FolderUpdate => self.eas_folder_update(&ctx, decoder.as_mut()).await?,
            Command::FolderDelete => self.eas_folder_delete(&ctx, decoder.as_mut()).await?,
            Command::Sync => self.eas_sync(&ctx, decoder.as_mut()).await?,
            Command::GetItemEstimate => self.eas_get_item_estimate(&ctx, decoder.as_mut()).await?,
            Command::ItemOperations => self.eas_item_operations(&ctx, decoder.as_mut()).await?,
            Command::MoveItems => self.eas_move_items(&ctx, decoder.as_mut()).await?,
            Command::MeetingResponse => self.eas_meeting_response(&ctx, decoder.as_mut()).await?,
            Command::Ping => self.eas_ping(&ctx, decoder.as_mut()).await?,
            Command::GetAttachment => self.eas_get_attachment(&ctx).await?,
            Command::Search => self.eas_search(&ctx, decoder.as_mut()).await?,
            Command::Find => self.eas_find(&ctx, decoder.as_mut()).await?,
            Command::ResolveRecipients => {
                self.eas_resolve_recipients(&ctx, decoder.as_mut()).await?
            }
            Command::ValidateCert => EasResponse::status(
                Command::ValidateCert,
                match decoder.as_mut() {
                    None => CommonStatus::INVALID_XML.into(),
                    Some(decoder) => match ValidateCertRequest::parse(decoder, ctx.version) {
                        Ok(request)
                            if request.certificates.is_empty()
                                && request.certificate_chain.is_empty() =>
                        {
                            ValidateCertStatus::SUCCESS.into()
                        }
                        Ok(_) => CommonStatus::COMMAND_NOT_SUPPORTED.into(),
                        Err(err) => err.status(Command::ValidateCert),
                    },
                },
            ),
            Command::SendMail => {
                self.eas_compose(
                    &ctx,
                    compose_body(decoder.as_mut(), body_kind, &body),
                    ComposeCommand::SendMail,
                )
                .await?
            }
            Command::SmartReply => {
                self.eas_compose(
                    &ctx,
                    compose_body(decoder.as_mut(), body_kind, &body),
                    ComposeCommand::SmartReply,
                )
                .await?
            }
            Command::SmartForward => {
                self.eas_compose(
                    &ctx,
                    compose_body(decoder.as_mut(), body_kind, &body),
                    ComposeCommand::SmartForward,
                )
                .await?
            }
        };

        response.into_http_coded(Some(version), coding).await
    }
}

fn compose_body<'a, 'b>(
    decoder: Option<&'b mut Decoder<'a>>,
    kind: BodyKind,
    body: &'a [u8],
) -> ComposeBody<'a, 'b> {
    match (decoder, kind) {
        (Some(decoder), _) => ComposeBody::Wbxml(decoder),
        (None, BodyKind::Mime) => ComposeBody::Mime(body),
        (None, _) => ComposeBody::Missing,
    }
}

pub(crate) const SUPPORTED_VERSIONS: &str = "14.1,16.1";
pub(crate) const IMPLEMENTED_COMMANDS: [Command; 19] = [
    Command::Sync,
    Command::SendMail,
    Command::SmartForward,
    Command::SmartReply,
    Command::GetAttachment,
    Command::FolderSync,
    Command::FolderCreate,
    Command::FolderDelete,
    Command::FolderUpdate,
    Command::GetItemEstimate,
    Command::ItemOperations,
    Command::MoveItems,
    Command::MeetingResponse,
    Command::Ping,
    Command::Provision,
    Command::Settings,
    Command::Search,
    Command::Find,
    Command::ResolveRecipients,
];
