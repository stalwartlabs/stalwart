/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, time::Instant};

use crate::{
    api::auth::JmapAuthorization,
    blob::{copy::BlobCopy, get::BlobOperations, upload::BlobUpload},
    changes::{get::ChangesLookup, query::QueryChanges},
    email::{
        copy::JmapEmailCopy, get::EmailGet, import::EmailImport, parse::EmailParse,
        query::EmailQuery, set::EmailSet, snippet::EmailSearchSnippet,
    },
    identity::{get::IdentityGet, set::IdentitySet},
    mailbox::{get::MailboxGet, query::MailboxQuery, set::MailboxSet},
    principal::{get::PrincipalGet, query::PrincipalQuery},
    push::{get::PushSubscriptionFetch, set::PushSubscriptionSet},
    quota::{get::QuotaGet, query::QuotaQuery},
    sieve::{
        get::SieveScriptGet, query::SieveScriptQuery, set::SieveScriptSet,
        validate::SieveScriptValidate,
    },
    submission::{get::EmailSubmissionGet, query::EmailSubmissionQuery, set::EmailSubmissionSet},
    thread::get::ThreadGet,
    vacation::{get::VacationResponseGet, set::VacationResponseSet},
};
use common::{Server, auth::AccessToken};
use http_proto::HttpSessionData;
use jmap_proto::{
    request::{
        Call, CopyRequestMethod, GetRequestMethod, QueryRequestMethod, Request, RequestMethod,
        SetRequestMethod, method::MethodName,
    },
    response::{Response, ResponseMethod, SetResponseMethod},
};
use trc::JmapEvent;
use types::{collection::Collection, id::Id};

use std::future::Future;

pub trait RequestHandler: Sync + Send {
    fn handle_jmap_request<'x>(
        &self,
        request: Request<'x>,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
    ) -> impl Future<Output = Response<'x>> + Send;

    fn handle_method_call<'x>(
        &self,
        method: RequestMethod<'x>,
        method_name: MethodName,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> impl Future<Output = trc::Result<ResponseMethod<'x>>> + Send;
}

impl RequestHandler for Server {
    #![allow(clippy::large_futures)]
    async fn handle_jmap_request<'x>(
        &self,
        request: Request<'x>,
        access_token: Arc<AccessToken>,
        session: &HttpSessionData,
    ) -> Response<'x> {
        let mut response = Response::new(
            access_token.state(),
            request.created_ids.unwrap_or_default(),
            request.method_calls.len(),
        );
        let add_created_ids = !response.created_ids.is_empty();

        for mut call in request.method_calls {
            // Resolve result and id references
            if let Err(error) = response.resolve_references(&mut call.method) {
                let method_error = error.clone();

                trc::error!(error.span_id(session.session_id));

                response.push_response(call.id, MethodName::error(), method_error);
                continue;
            }

            loop {
                let mut next_call = None;

                // Add response
                let method_name = call.name.as_str();
                match self
                    .handle_method_call(
                        call.method,
                        call.name,
                        &access_token,
                        &mut next_call,
                        session,
                    )
                    .await
                {
                    Ok(mut method_response) => {
                        match &mut method_response {
                            ResponseMethod::Set(set_response) => {
                                // Add created ids
                                match set_response {
                                    SetResponseMethod::Email(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Mailbox(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Identity(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::EmailSubmission(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::PushSubscription(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::Sieve(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                    SetResponseMethod::VacationResponse(set_response) => {
                                        set_response.update_created_ids(&mut response);
                                    }
                                }
                            }
                            ResponseMethod::ImportEmail(import_response) => {
                                // Add created ids
                                import_response.update_created_ids(&mut response);
                            }
                            ResponseMethod::UploadBlob(upload_response) => {
                                // Add created blobIds
                                upload_response.update_created_ids(&mut response);
                            }
                            _ => {}
                        }

                        response.push_response(call.id, call.name, method_response);
                    }
                    Err(error) => {
                        let method_error = error.clone();

                        trc::error!(
                            error
                                .span_id(session.session_id)
                                .ctx_unique(trc::Key::AccountId, access_token.primary_id())
                                .caused_by(method_name)
                        );

                        response.push_error(call.id, method_error);
                    }
                }

                // Process next call
                if let Some(next_call) = next_call {
                    call = next_call;
                    call.id
                        .clone_from(&response.method_responses.last().unwrap().id);
                } else {
                    break;
                }
            }
        }

        if !add_created_ids {
            response.created_ids.clear();
        }

        response
    }

    async fn handle_method_call<'x>(
        &self,
        method: RequestMethod<'x>,
        method_name: MethodName,
        access_token: &AccessToken,
        next_call: &mut Option<Call<RequestMethod<'x>>>,
        session: &HttpSessionData,
    ) -> trc::Result<ResponseMethod<'x>> {
        let op_start = Instant::now();

        // Check permissions
        access_token.assert_has_jmap_permission(&method, method_name.obj)?;

        // Handle method
        let response = match method {
            RequestMethod::Get(req) => match req {
                GetRequestMethod::Email(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_get(req, access_token).await?.into()
                }
                GetRequestMethod::Mailbox(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_get(req, access_token).await?.into()
                }
                GetRequestMethod::Thread(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.thread_get(req).await?.into()
                }
                GetRequestMethod::Identity(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.identity_get(req).await?.into()
                }
                GetRequestMethod::EmailSubmission(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.email_submission_get(req).await?.into()
                }
                GetRequestMethod::PushSubscription(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    self.push_subscription_get(req, access_token).await?.into()
                }
                GetRequestMethod::Sieve(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.sieve_script_get(req).await?.into()
                }
                GetRequestMethod::VacationResponse(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.vacation_response_get(req).await?.into()
                }
                GetRequestMethod::Principal(req) => self.principal_get(req).await?.into(),
                GetRequestMethod::Quota(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.quota_get(req, access_token).await?.into()
                }
                GetRequestMethod::Blob(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.blob_get(req, access_token).await?.into()
                }
            },
            RequestMethod::Query(req) => match req {
                QueryRequestMethod::Email(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_query(req, access_token).await?.into()
                }
                QueryRequestMethod::Mailbox(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_query(req, access_token).await?.into()
                }
                QueryRequestMethod::EmailSubmission(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.email_submission_query(req).await?.into()
                }
                QueryRequestMethod::Sieve(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.sieve_script_query(req).await?.into()
                }
                QueryRequestMethod::Principal(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    self.principal_query(req, session).await?.into()
                }
                QueryRequestMethod::Quota(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.quota_query(req, access_token).await?.into()
                }
            },
            RequestMethod::Set(req) => match req {
                SetRequestMethod::Email(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Email)?;

                    self.email_set(req, access_token, session).await?.into()
                }
                SetRequestMethod::Mailbox(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_has_access(req.account_id, Collection::Mailbox)?;

                    self.mailbox_set(req, access_token).await?.into()
                }
                SetRequestMethod::Identity(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.identity_set(req).await?.into()
                }
                SetRequestMethod::EmailSubmission(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.email_submission_set(req, &session.instance, next_call)
                        .await?
                        .into()
                }
                SetRequestMethod::PushSubscription(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    self.push_subscription_set(req, access_token).await?.into()
                }
                SetRequestMethod::Sieve(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.sieve_script_set(req, access_token, session)
                        .await?
                        .into()
                }
                SetRequestMethod::VacationResponse(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.vacation_response_set(req, access_token).await?.into()
                }
            },
            RequestMethod::Changes(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);

                self.changes(req, method_name.obj, access_token)
                    .await?
                    .into_method_response()
            }
            RequestMethod::Copy(req) => match req {
                CopyRequestMethod::Email(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);

                    access_token
                        .assert_has_access(req.account_id, Collection::Email)?
                        .assert_has_access(req.from_account_id, Collection::Email)?;

                    self.email_copy(req, access_token, next_call, session)
                        .await?
                        .into()
                }
                CopyRequestMethod::Blob(mut req) => {
                    set_account_id_if_missing(&mut req.account_id, access_token);
                    access_token.assert_is_member(req.account_id)?;

                    self.blob_copy(req, access_token).await?.into()
                }
            },
            RequestMethod::ImportEmail(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);
                access_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_import(req, access_token, session).await?.into()
            }
            RequestMethod::ParseEmail(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);
                access_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_parse(req, access_token).await?.into()
            }
            RequestMethod::QueryChanges(req) => self.query_changes(req, access_token).await?.into(),
            RequestMethod::SearchSnippet(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);
                access_token.assert_has_access(req.account_id, Collection::Email)?;

                self.email_search_snippet(req, access_token).await?.into()
            }
            RequestMethod::ValidateScript(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);
                access_token.assert_is_member(req.account_id)?;

                self.sieve_script_validate(req, access_token).await?.into()
            }
            RequestMethod::LookupBlob(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);
                access_token.assert_is_member(req.account_id)?;

                self.blob_lookup(req).await?.into()
            }
            RequestMethod::UploadBlob(mut req) => {
                set_account_id_if_missing(&mut req.account_id, access_token);
                access_token.assert_is_member(req.account_id)?;

                self.blob_upload_many(req, access_token).await?.into()
            }
            RequestMethod::Echo(req) => req.into(),
            RequestMethod::Error(error) => return Err(error),
        };

        trc::event!(
            Jmap(JmapEvent::MethodCall),
            Id = method_name.as_str(),
            SpanId = session.session_id,
            AccountId = access_token.primary_id(),
            Elapsed = op_start.elapsed(),
        );

        Ok(response)
    }
}

#[inline]
pub(crate) fn set_account_id_if_missing(account_id: &mut Id, access_token: &AccessToken) {
    if !account_id.is_valid() {
        *account_id = Id::from(access_token.primary_id());
    }
}
