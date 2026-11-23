/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod availability;
pub mod calendar;
pub mod config;
pub mod contact;
pub mod context;
pub mod convert_id;
pub mod delegate;
pub mod directory;
pub mod filter;
pub mod folder;
pub mod groupware;
pub mod impersonation;
pub mod item;
pub mod notify;
pub mod oof;
pub mod people;
pub mod reminder;
pub mod reply;
pub mod rules;
pub mod search;
pub mod service;
pub mod target;
pub mod task;
pub mod timezone;

use availability::get_user_availability;
use common::{Server, auth::AccessToken};
use config::{
    create_user_configuration, delete_user_configuration, get_user_configuration,
    update_user_configuration,
};
use context::{EwsCaller, EwsContext};
use convert_id::convert_id;
use delegate::{add_delegate, get_delegate, remove_delegate, update_delegate};
use directory::{expand_dl, get_room_lists, get_rooms, resolve_names};
use exchange_proto::ews::{
    EwsLimits, EwsRequest, ExchangeVersion, Operation, ParseOutcome, ServerVersionInfo, Status,
    envelope::{EnvelopeWriter, XmlDecl, parse_request},
    schema::response_code::ResponseCode,
    write_fault,
};
use folder::{
    copy::copy_folder,
    get::{find_folder, get_folder},
    sync::sync_folder_hierarchy,
    write::{create_folder, delete_folder, empty_folder, move_folder, update_folder},
};
use http_proto::{HttpRequest, HttpResponse, HttpSessionData, request::fetch_body};
use hyper::{Method, StatusCode, header::ALLOW};
use impersonation::{Impersonation, impersonate};
use item::{
    attach::{create_attachment, delete_attachment},
    attachment::get_attachment,
    bulk::{export_items, upload_items},
    conversation::{find::find_conversation, items::get_conversation_items},
    create::create_item,
    find::find_item,
    get::get_item,
    send::send_item,
    sync::sync_folder_items,
    update::update_item,
    write::{
        Placement, archive_item, delete_item, mark_all_items_as_read, mark_as_junk, move_copy_item,
    },
};
use notify::{get_events, stream::get_streaming_events, subscribe, unsubscribe};
use oof::{get_user_oof_settings, set_user_oof_settings};
use people::{find_people, get_persona};
use registry::schema::enums::EwsVersion;
use reminder::{get_reminders, perform_reminder_action};
use reply::{RESPONSE_CAPACITY, ews_response, write_operation_error};
use rules::{get_inbox_rules, update_inbox_rules};
use search::{end_search_session, execute_search, get_search_suggestions, start_search_session};
use service::{
    add_entity_feedback, get_app_manifests, get_mail_tips, get_password_expiration_date,
    get_service_configuration, get_user_photo, get_user_retention_policy_tags, rbac_role_required,
};
use target::retarget;
use timezone::get_server_time_zones;

const UNSUPPORTED_OPERATION: &str = "The operation is not supported by this server.";

pub(crate) fn server_version(server: &Server) -> ServerVersionInfo {
    ServerVersionInfo::for_version(match server.core.exchange.ews_version {
        EwsVersion::Exchange2010Sp2 => ExchangeVersion::Exchange2010Sp2,
        EwsVersion::Exchange2013 => ExchangeVersion::Exchange2013,
        EwsVersion::Exchange2013Sp1 => ExchangeVersion::Exchange2013Sp1,
        EwsVersion::Exchange2016 => ExchangeVersion::Exchange2016,
    })
}

pub trait EwsHandler: Sync + Send {
    fn handle_ews_request(
        &self,
        request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<HttpResponse>> + Send;
}

impl EwsHandler for Server {
    async fn handle_ews_request(
        &self,
        mut request: HttpRequest,
        access_token: AccessToken,
        session: &HttpSessionData,
    ) -> trc::Result<HttpResponse> {
        if request.method() != Method::POST {
            return Ok(HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED).with_header(ALLOW, "POST"));
        }
        let Some(body) = fetch_body(
            &mut request,
            self.core.exchange.max_request_size,
            session.session_id,
        )
        .await
        else {
            return Err(trc::LimitEvent::SizeRequest.into_err());
        };
        let version = server_version(self);
        let mut out = Vec::with_capacity(RESPONSE_CAPACITY);
        let envelope = match parse_request(&body, &EwsLimits::DEFAULT) {
            Ok(envelope) => envelope,
            Err(err) => {
                return Ok(match err.outcome(&body) {
                    ParseOutcome::Fault(fault) => {
                        write_fault(&mut out, &version, &fault);
                        ews_response(out).with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                    ParseOutcome::MessageError { op, code } => {
                        write_operation_error(
                            EnvelopeWriter::begin(&mut out, &version, XmlDecl::Emit),
                            op,
                            &Status::error(code, err.description()),
                        );
                        ews_response(out)
                    }
                });
            }
        };

        let impersonated = match envelope.header.impersonation.as_ref() {
            Some(target) => {
                match impersonate(self, &access_token, target, session.session_id).await? {
                    Ok(Impersonation::Target(effective)) => Some(effective),
                    Ok(Impersonation::Own) => None,
                    Err(fault) => {
                        write_fault(&mut out, &version, &fault);
                        return Ok(
                            ews_response(out).with_status_code(StatusCode::INTERNAL_SERVER_ERROR)
                        );
                    }
                }
            }
            None => None,
        };
        let principal = access_token.account_id();
        let access_token = impersonated.as_ref().unwrap_or(&access_token);
        let mut ctx = EwsContext::new(version, &envelope.header, access_token);
        retarget(self, &mut ctx, &envelope.request).await?;
        let caller = EwsCaller {
            access_token,
            session,
        };
        match &envelope.request {
            EwsRequest::GetServerTimeZones(request) => Ok(get_server_time_zones(&ctx, request)),
            EwsRequest::ConvertId(request) => Ok(convert_id(&ctx, request)),
            EwsRequest::GetFolder(request) => get_folder(self, &ctx, request).await,
            EwsRequest::FindFolder(request) => find_folder(self, &ctx, request).await,
            EwsRequest::GetItem(request) => get_item(self, &ctx, request).await,
            EwsRequest::ExportItems(request) => export_items(self, &ctx, request).await,
            EwsRequest::UploadItems(request) => upload_items(self, &ctx, caller, request).await,
            EwsRequest::GetAttachment(request) => get_attachment(self, &ctx, request).await,
            EwsRequest::CreateAttachment(request) => {
                create_attachment(self, &ctx, caller, request).await
            }
            EwsRequest::DeleteAttachment(request) => {
                delete_attachment(self, &ctx, caller, request).await
            }
            EwsRequest::FindItem(request) => find_item(self, &ctx, request).await,
            EwsRequest::FindConversation(request) => find_conversation(self, &ctx, request).await,
            EwsRequest::GetConversationItems(request) => {
                get_conversation_items(self, &ctx, request).await
            }
            EwsRequest::SyncFolderHierarchy(request) => {
                sync_folder_hierarchy(self, &ctx, request).await
            }
            EwsRequest::SyncFolderItems(request) => sync_folder_items(self, &ctx, request).await,
            EwsRequest::CreateFolder(request) => create_folder(self, &ctx, caller, request).await,
            EwsRequest::UpdateFolder(request) => update_folder(self, &ctx, caller, request).await,
            EwsRequest::DeleteFolder(request) => delete_folder(self, &ctx, caller, request).await,
            EwsRequest::MoveFolder(request) => move_folder(self, &ctx, caller, request).await,
            EwsRequest::CopyFolder(request) => copy_folder(self, &ctx, caller, request).await,
            EwsRequest::EmptyFolder(request) => empty_folder(self, &ctx, caller, request).await,
            EwsRequest::CreateItem(request) => create_item(self, &ctx, caller, request).await,
            EwsRequest::SendItem(request) => send_item(self, &ctx, caller, request).await,
            EwsRequest::UpdateItem(request) => update_item(self, &ctx, caller, request).await,
            EwsRequest::DeleteItem(request) => delete_item(self, &ctx, caller, request).await,
            EwsRequest::MoveItem(request) => {
                move_copy_item(self, &ctx, caller, request, Placement::Move).await
            }
            EwsRequest::CopyItem(request) => {
                move_copy_item(self, &ctx, caller, request, Placement::Copy).await
            }
            EwsRequest::MarkAsJunk(request) => mark_as_junk(self, &ctx, caller, request).await,
            EwsRequest::ArchiveItem(request) => Ok(archive_item(&ctx, request)),
            EwsRequest::MarkAllItemsAsRead(request) => {
                mark_all_items_as_read(self, &ctx, caller, request).await
            }
            EwsRequest::ResolveNames(request) => resolve_names(self, &ctx, caller, request).await,
            EwsRequest::ExpandDl(request) => expand_dl(self, &ctx, caller, request).await,
            EwsRequest::GetUserAvailability(request) => {
                get_user_availability(
                    self,
                    &ctx,
                    caller,
                    request,
                    envelope.header.time_zone.as_ref(),
                )
                .await
            }
            EwsRequest::GetRooms(request) => get_rooms(self, &ctx, caller, request).await,
            EwsRequest::GetRoomLists => get_room_lists(self, &ctx, caller).await,
            EwsRequest::GetInboxRules(request) => get_inbox_rules(self, &ctx, request).await,
            EwsRequest::UpdateInboxRules(request) => {
                update_inbox_rules(self, &ctx, caller, request).await
            }
            EwsRequest::GetDelegate(request) => get_delegate(self, &ctx, request).await,
            EwsRequest::AddDelegate(request) => add_delegate(self, &ctx, caller, request).await,
            EwsRequest::UpdateDelegate(request) => {
                update_delegate(self, &ctx, caller, request).await
            }
            EwsRequest::RemoveDelegate(request) => {
                remove_delegate(self, &ctx, caller, request).await
            }
            EwsRequest::GetMailTips(request) => Ok(get_mail_tips(self, &ctx, request)),
            EwsRequest::GetPasswordExpirationDate(request) => {
                get_password_expiration_date(self, &ctx, request).await
            }
            EwsRequest::GetServiceConfiguration(request) => {
                get_service_configuration(self, &ctx, request).await
            }
            EwsRequest::GetAppManifests(request) => Ok(get_app_manifests(&ctx, request)),
            EwsRequest::Unsupported(Operation::GetUserRetentionPolicyTags) => {
                Ok(get_user_retention_policy_tags(&ctx))
            }
            EwsRequest::Unsupported(
                Operation::GetSearchableMailboxes | Operation::GetDiscoverySearchConfiguration,
            ) => Ok(rbac_role_required(&ctx)),
            EwsRequest::FindPeople(request) => find_people(self, &ctx, caller, request).await,
            EwsRequest::GetPersona(request) => get_persona(self, &ctx, caller, request).await,
            EwsRequest::AddEntityFeedback => Ok(add_entity_feedback(&ctx)),
            EwsRequest::StartSearchSession(_) => Ok(start_search_session(&ctx)),
            EwsRequest::EndSearchSession(_) => Ok(end_search_session(&ctx)),
            EwsRequest::GetSearchSuggestions(request) => {
                get_search_suggestions(self, &ctx, caller, request).await
            }
            EwsRequest::ExecuteSearch(request) => execute_search(self, &ctx, request).await,
            EwsRequest::GetUserPhoto(_) => Ok(get_user_photo()),
            EwsRequest::GetUserOofSettings(request) => {
                get_user_oof_settings(self, &ctx, request).await
            }
            EwsRequest::SetUserOofSettings(request) => {
                set_user_oof_settings(self, &ctx, caller, request).await
            }
            EwsRequest::GetUserConfiguration(request) => {
                get_user_configuration(self, &ctx, request).await
            }
            EwsRequest::CreateUserConfiguration(request) => {
                create_user_configuration(self, &ctx, caller, request).await
            }
            EwsRequest::UpdateUserConfiguration(request) => {
                update_user_configuration(self, &ctx, caller, request).await
            }
            EwsRequest::DeleteUserConfiguration(request) => {
                delete_user_configuration(self, &ctx, caller, request).await
            }
            EwsRequest::GetReminders(request) => get_reminders(self, &ctx, request).await,
            EwsRequest::PerformReminderAction(request) => {
                perform_reminder_action(self, &ctx, caller, request).await
            }
            EwsRequest::Subscribe(request) => subscribe(self, &ctx, principal, request).await,
            EwsRequest::Unsubscribe(request) => unsubscribe(self, &ctx, principal, request).await,
            EwsRequest::GetEvents(request) => get_events(self, &ctx, principal, request).await,
            EwsRequest::GetStreamingEvents(request) => {
                get_streaming_events(self, &ctx, principal, request).await
            }
            request => {
                write_operation_error(
                    ctx.envelope(&mut out),
                    request.operation(),
                    &Status::error(ResponseCode::ErrorInvalidOperation, UNSUPPORTED_OPERATION),
                );
                Ok(ews_response(out))
            }
        }
    }
}

async fn owns_address(server: &Server, address: &str, account_id: u32) -> trc::Result<bool> {
    Ok(server.account_id_from_email(address, false).await? == Some(account_id))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange/src/ews/tests.rs"]
mod tests;
