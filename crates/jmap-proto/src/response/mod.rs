/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod serialize;
pub mod status;

use self::serialize::serialize_hex;
use crate::{
    error::method::MethodErrorWrapper,
    method::{
        changes::ChangesResponse,
        copy::{CopyBlobResponse, CopyResponse},
        get::GetResponse,
        import::ImportEmailResponse,
        lookup::BlobLookupResponse,
        parse::ParseEmailResponse,
        query::QueryResponse,
        query_changes::QueryChangesResponse,
        search_snippet::GetSearchSnippetResponse,
        set::SetResponse,
        upload::BlobUploadResponse,
        validate::ValidateSieveScriptResponse,
    },
    object::{
        AnyId, blob::Blob, email::Email, email_submission::EmailSubmission, identity::Identity,
        mailbox::Mailbox, principal::Principal, push_subscription::PushSubscription, quota::Quota,
        sieve::Sieve, thread::Thread, vacation_response::VacationResponse,
    },
    request::{Call, method::MethodName},
};
use jmap_tools::{Null, Value};
use std::collections::HashMap;

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum ResponseMethod<'x> {
    Get(GetResponseMethod),
    Set(SetResponseMethod),
    Changes(ChangesResponseMethod),
    Copy(CopyResponseMethod),
    ImportEmail(ImportEmailResponse),
    ParseEmail(ParseEmailResponse),
    QueryChanges(QueryChangesResponse),
    Query(QueryResponse),
    SearchSnippet(GetSearchSnippetResponse),
    ValidateScript(ValidateSieveScriptResponse),
    LookupBlob(BlobLookupResponse),
    UploadBlob(BlobUploadResponse),
    Echo(Value<'x, Null, Null>),
    Error(MethodErrorWrapper),
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum GetResponseMethod {
    Email(GetResponse<Email>),
    Mailbox(GetResponse<Mailbox>),
    Thread(GetResponse<Thread>),
    Identity(GetResponse<Identity>),
    EmailSubmission(GetResponse<EmailSubmission>),
    PushSubscription(GetResponse<PushSubscription>),
    Sieve(GetResponse<Sieve>),
    VacationResponse(GetResponse<VacationResponse>),
    Principal(GetResponse<Principal>),
    Quota(GetResponse<Quota>),
    Blob(GetResponse<Blob>),
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum SetResponseMethod {
    Email(SetResponse<Email>),
    Mailbox(SetResponse<Mailbox>),
    Identity(SetResponse<Identity>),
    EmailSubmission(SetResponse<EmailSubmission>),
    PushSubscription(SetResponse<PushSubscription>),
    Sieve(SetResponse<Sieve>),
    VacationResponse(SetResponse<VacationResponse>),
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum ChangesResponseMethod {
    Email(ChangesResponse<Email>),
    Mailbox(ChangesResponse<Mailbox>),
    Thread(ChangesResponse<Thread>),
    Identity(ChangesResponse<Identity>),
    EmailSubmission(ChangesResponse<EmailSubmission>),
    Quota(ChangesResponse<Quota>),
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum CopyResponseMethod {
    Email(CopyResponse<Email>),
    Blob(CopyBlobResponse),
}

#[derive(Debug, serde::Serialize)]
pub struct Response<'x> {
    #[serde(rename = "methodResponses")]
    pub method_responses: Vec<Call<ResponseMethod<'x>>>,

    #[serde(rename = "sessionState")]
    #[serde(serialize_with = "serialize_hex")]
    pub session_state: u32,

    #[serde(rename = "createdIds")]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub created_ids: HashMap<String, AnyId>,
}

impl<'x> Response<'x> {
    pub fn new(session_state: u32, created_ids: HashMap<String, AnyId>, capacity: usize) -> Self {
        Response {
            session_state,
            created_ids,
            method_responses: Vec::with_capacity(capacity),
        }
    }

    pub fn push_response(
        &mut self,
        id: String,
        name: MethodName,
        method: impl Into<ResponseMethod<'x>>,
    ) {
        self.method_responses.push(Call {
            id,
            method: method.into(),
            name,
        });
    }

    pub fn push_error(&mut self, id: String, err: impl Into<MethodErrorWrapper>) {
        self.method_responses.push(Call {
            id,
            method: ResponseMethod::Error(err.into()),
            name: MethodName::error(),
        });
    }

    pub fn push_created_id(&mut self, create_id: String, id: impl Into<AnyId>) {
        self.created_ids.insert(create_id, id.into());
    }
}

impl From<trc::Error> for ResponseMethod<'_> {
    fn from(error: trc::Error) -> Self {
        ResponseMethod::Error(error.into())
    }
}

impl<'x, T: Into<ResponseMethod<'x>>> From<trc::Result<T>> for ResponseMethod<'x> {
    fn from(result: trc::Result<T>) -> Self {
        match result {
            Ok(value) => value.into(),
            Err(error) => error.into(),
        }
    }
}

impl<'x> From<GetResponse<Email>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Email>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Email(value))
    }
}

impl<'x> From<GetResponse<Mailbox>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Mailbox>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Mailbox(value))
    }
}

impl<'x> From<GetResponse<Thread>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Thread>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Thread(value))
    }
}

impl<'x> From<GetResponse<Identity>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Identity>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Identity(value))
    }
}

impl<'x> From<GetResponse<EmailSubmission>> for ResponseMethod<'x> {
    fn from(value: GetResponse<EmailSubmission>) -> Self {
        ResponseMethod::Get(GetResponseMethod::EmailSubmission(value))
    }
}

impl<'x> From<GetResponse<PushSubscription>> for ResponseMethod<'x> {
    fn from(value: GetResponse<PushSubscription>) -> Self {
        ResponseMethod::Get(GetResponseMethod::PushSubscription(value))
    }
}

impl<'x> From<GetResponse<Sieve>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Sieve>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Sieve(value))
    }
}

impl<'x> From<GetResponse<VacationResponse>> for ResponseMethod<'x> {
    fn from(value: GetResponse<VacationResponse>) -> Self {
        ResponseMethod::Get(GetResponseMethod::VacationResponse(value))
    }
}

impl<'x> From<GetResponse<Principal>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Principal>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Principal(value))
    }
}

impl<'x> From<GetResponse<Quota>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Quota>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Quota(value))
    }
}

impl<'x> From<GetResponse<Blob>> for ResponseMethod<'x> {
    fn from(value: GetResponse<Blob>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Blob(value))
    }
}

// Direct SetResponse conversions to ResponseMethod
impl<'x> From<SetResponse<Email>> for ResponseMethod<'x> {
    fn from(value: SetResponse<Email>) -> Self {
        ResponseMethod::Set(SetResponseMethod::Email(value))
    }
}

impl<'x> From<SetResponse<Mailbox>> for ResponseMethod<'x> {
    fn from(value: SetResponse<Mailbox>) -> Self {
        ResponseMethod::Set(SetResponseMethod::Mailbox(value))
    }
}

impl<'x> From<SetResponse<Identity>> for ResponseMethod<'x> {
    fn from(value: SetResponse<Identity>) -> Self {
        ResponseMethod::Set(SetResponseMethod::Identity(value))
    }
}

impl<'x> From<SetResponse<EmailSubmission>> for ResponseMethod<'x> {
    fn from(value: SetResponse<EmailSubmission>) -> Self {
        ResponseMethod::Set(SetResponseMethod::EmailSubmission(value))
    }
}

impl<'x> From<SetResponse<PushSubscription>> for ResponseMethod<'x> {
    fn from(value: SetResponse<PushSubscription>) -> Self {
        ResponseMethod::Set(SetResponseMethod::PushSubscription(value))
    }
}

impl<'x> From<SetResponse<Sieve>> for ResponseMethod<'x> {
    fn from(value: SetResponse<Sieve>) -> Self {
        ResponseMethod::Set(SetResponseMethod::Sieve(value))
    }
}

impl<'x> From<SetResponse<VacationResponse>> for ResponseMethod<'x> {
    fn from(value: SetResponse<VacationResponse>) -> Self {
        ResponseMethod::Set(SetResponseMethod::VacationResponse(value))
    }
}

// Direct ChangesResponse conversions to ResponseMethod
impl<'x> From<ChangesResponse<Email>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<Email>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::Email(value))
    }
}

impl<'x> From<ChangesResponse<Mailbox>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<Mailbox>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::Mailbox(value))
    }
}

impl<'x> From<ChangesResponse<Thread>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<Thread>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::Thread(value))
    }
}

impl<'x> From<ChangesResponse<Identity>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<Identity>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::Identity(value))
    }
}

impl<'x> From<ChangesResponse<EmailSubmission>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<EmailSubmission>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::EmailSubmission(value))
    }
}

impl<'x> From<ChangesResponse<Quota>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<Quota>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::Quota(value))
    }
}

// Direct CopyResponse conversions to ResponseMethod
impl<'x> From<CopyResponse<Email>> for ResponseMethod<'x> {
    fn from(value: CopyResponse<Email>) -> Self {
        ResponseMethod::Copy(CopyResponseMethod::Email(value))
    }
}

impl<'x> From<CopyBlobResponse> for ResponseMethod<'x> {
    fn from(value: CopyBlobResponse) -> Self {
        ResponseMethod::Copy(CopyResponseMethod::Blob(value))
    }
}

// Other direct conversions
impl<'x> From<ImportEmailResponse> for ResponseMethod<'x> {
    fn from(value: ImportEmailResponse) -> Self {
        ResponseMethod::ImportEmail(value)
    }
}

impl<'x> From<ParseEmailResponse> for ResponseMethod<'x> {
    fn from(value: ParseEmailResponse) -> Self {
        ResponseMethod::ParseEmail(value)
    }
}

impl<'x> From<QueryChangesResponse> for ResponseMethod<'x> {
    fn from(value: QueryChangesResponse) -> Self {
        ResponseMethod::QueryChanges(value)
    }
}

impl<'x> From<QueryResponse> for ResponseMethod<'x> {
    fn from(value: QueryResponse) -> Self {
        ResponseMethod::Query(value)
    }
}

impl<'x> From<GetSearchSnippetResponse> for ResponseMethod<'x> {
    fn from(value: GetSearchSnippetResponse) -> Self {
        ResponseMethod::SearchSnippet(value)
    }
}

impl<'x> From<ValidateSieveScriptResponse> for ResponseMethod<'x> {
    fn from(value: ValidateSieveScriptResponse) -> Self {
        ResponseMethod::ValidateScript(value)
    }
}

impl<'x> From<BlobLookupResponse> for ResponseMethod<'x> {
    fn from(value: BlobLookupResponse) -> Self {
        ResponseMethod::LookupBlob(value)
    }
}

impl<'x> From<BlobUploadResponse> for ResponseMethod<'x> {
    fn from(value: BlobUploadResponse) -> Self {
        ResponseMethod::UploadBlob(value)
    }
}

impl<'x> From<Value<'x, Null, Null>> for ResponseMethod<'x> {
    fn from(value: Value<'x, Null, Null>) -> Self {
        ResponseMethod::Echo(value)
    }
}

impl<'x> From<MethodErrorWrapper> for ResponseMethod<'x> {
    fn from(value: MethodErrorWrapper) -> Self {
        ResponseMethod::Error(value)
    }
}
