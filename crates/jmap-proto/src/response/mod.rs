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
        availability::GetAvailabilityResponse,
        changes::ChangesResponse,
        copy::{CopyBlobResponse, CopyResponse},
        get::GetResponse,
        import::ImportEmailResponse,
        lookup::BlobLookupResponse,
        parse::ParseResponse,
        query::QueryResponse,
        query_changes::QueryChangesResponse,
        search_snippet::GetSearchSnippetResponse,
        set::SetResponse,
        upload::BlobUploadResponse,
        validate::ValidateSieveScriptResponse,
    },
    object::{
        AnyId,
        addressbook::AddressBook,
        blob::Blob,
        calendar::Calendar,
        calendar_event::CalendarEvent,
        calendar_event_notification::{
            CalendarEventNotification, CalendarEventNotificationGetResponse,
        },
        contact::ContactCard,
        email::Email,
        email_submission::EmailSubmission,
        file_node::FileNode,
        identity::Identity,
        mailbox::Mailbox,
        participant_identity::ParticipantIdentity,
        principal::Principal,
        push_subscription::PushSubscription,
        quota::Quota,
        share_notification::ShareNotification,
        sieve::Sieve,
        thread::Thread,
        vacation_response::VacationResponse,
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
    Parse(ParseResponseMethod),
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
    PrincipalAvailability(GetAvailabilityResponse),
    Quota(GetResponse<Quota>),
    Blob(GetResponse<Blob>),
    AddressBook(GetResponse<AddressBook>),
    ContactCard(GetResponse<ContactCard>),
    FileNode(GetResponse<FileNode>),
    Calendar(GetResponse<Calendar>),
    CalendarEvent(GetResponse<CalendarEvent>),
    CalendarEventNotification(CalendarEventNotificationGetResponse),
    ParticipantIdentity(GetResponse<ParticipantIdentity>),
    ShareNotification(GetResponse<ShareNotification>),
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
    AddressBook(SetResponse<AddressBook>),
    ContactCard(SetResponse<ContactCard>),
    FileNode(SetResponse<FileNode>),
    ShareNotification(SetResponse<ShareNotification>),
    Calendar(SetResponse<Calendar>),
    CalendarEvent(SetResponse<CalendarEvent>),
    CalendarEventNotification(SetResponse<CalendarEventNotification>),
    ParticipantIdentity(SetResponse<ParticipantIdentity>),
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
    AddressBook(ChangesResponse<AddressBook>),
    ContactCard(ChangesResponse<ContactCard>),
    FileNode(ChangesResponse<FileNode>),
    Calendar(ChangesResponse<Calendar>),
    CalendarEvent(ChangesResponse<CalendarEvent>),
    CalendarEventNotification(ChangesResponse<CalendarEventNotification>),
    ShareNotification(ChangesResponse<ShareNotification>),
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum CopyResponseMethod {
    Email(CopyResponse<Email>),
    ContactCard(CopyResponse<ContactCard>),
    CalendarEvent(CopyResponse<CalendarEvent>),
    Blob(CopyBlobResponse),
}

#[derive(Debug, serde::Serialize)]
#[serde(untagged)]
pub enum ParseResponseMethod {
    Email(ParseResponse<Email>),
    ContactCard(ParseResponse<ContactCard>),
    CalendarEvent(ParseResponse<CalendarEvent>),
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

impl<'x> From<GetResponse<ContactCard>> for ResponseMethod<'x> {
    fn from(value: GetResponse<ContactCard>) -> Self {
        ResponseMethod::Get(GetResponseMethod::ContactCard(value))
    }
}

impl<'x> From<GetResponse<AddressBook>> for ResponseMethod<'x> {
    fn from(value: GetResponse<AddressBook>) -> Self {
        ResponseMethod::Get(GetResponseMethod::AddressBook(value))
    }
}

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

impl<'x> From<SetResponse<AddressBook>> for ResponseMethod<'x> {
    fn from(value: SetResponse<AddressBook>) -> Self {
        ResponseMethod::Set(SetResponseMethod::AddressBook(value))
    }
}

impl<'x> From<SetResponse<ContactCard>> for ResponseMethod<'x> {
    fn from(value: SetResponse<ContactCard>) -> Self {
        ResponseMethod::Set(SetResponseMethod::ContactCard(value))
    }
}

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

impl<'x> From<ChangesResponse<AddressBook>> for ResponseMethod<'x> {
    fn from(value: ChangesResponse<AddressBook>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::AddressBook(value))
    }
}

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

impl<'x> From<CopyResponse<ContactCard>> for ResponseMethod<'x> {
    fn from(value: CopyResponse<ContactCard>) -> Self {
        ResponseMethod::Copy(CopyResponseMethod::ContactCard(value))
    }
}

impl<'x> From<ImportEmailResponse> for ResponseMethod<'x> {
    fn from(value: ImportEmailResponse) -> Self {
        ResponseMethod::ImportEmail(value)
    }
}

impl<'x> From<ParseResponse<Email>> for ResponseMethod<'x> {
    fn from(value: ParseResponse<Email>) -> Self {
        ResponseMethod::Parse(ParseResponseMethod::Email(value))
    }
}

impl<'x> From<ParseResponse<ContactCard>> for ResponseMethod<'x> {
    fn from(value: ParseResponse<ContactCard>) -> Self {
        ResponseMethod::Parse(ParseResponseMethod::ContactCard(value))
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

impl From<GetResponse<FileNode>> for ResponseMethod<'_> {
    fn from(response: GetResponse<FileNode>) -> Self {
        ResponseMethod::Get(GetResponseMethod::FileNode(response))
    }
}

impl From<SetResponse<FileNode>> for ResponseMethod<'_> {
    fn from(response: SetResponse<FileNode>) -> Self {
        ResponseMethod::Set(SetResponseMethod::FileNode(response))
    }
}

impl From<ChangesResponse<FileNode>> for ResponseMethod<'_> {
    fn from(response: ChangesResponse<FileNode>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::FileNode(response))
    }
}

impl From<GetAvailabilityResponse> for ResponseMethod<'_> {
    fn from(response: GetAvailabilityResponse) -> Self {
        ResponseMethod::Get(GetResponseMethod::PrincipalAvailability(response))
    }
}

impl From<GetResponse<Calendar>> for ResponseMethod<'_> {
    fn from(response: GetResponse<Calendar>) -> Self {
        ResponseMethod::Get(GetResponseMethod::Calendar(response))
    }
}

impl From<SetResponse<Calendar>> for ResponseMethod<'_> {
    fn from(response: SetResponse<Calendar>) -> Self {
        ResponseMethod::Set(SetResponseMethod::Calendar(response))
    }
}

impl From<ChangesResponse<CalendarEvent>> for ResponseMethod<'_> {
    fn from(response: ChangesResponse<CalendarEvent>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::CalendarEvent(response))
    }
}

impl From<ChangesResponse<CalendarEventNotification>> for ResponseMethod<'_> {
    fn from(response: ChangesResponse<CalendarEventNotification>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::CalendarEventNotification(response))
    }
}

impl From<SetResponse<CalendarEvent>> for ResponseMethod<'_> {
    fn from(response: SetResponse<CalendarEvent>) -> Self {
        ResponseMethod::Set(SetResponseMethod::CalendarEvent(response))
    }
}

impl From<SetResponse<ParticipantIdentity>> for ResponseMethod<'_> {
    fn from(response: SetResponse<ParticipantIdentity>) -> Self {
        ResponseMethod::Set(SetResponseMethod::ParticipantIdentity(response))
    }
}

impl From<GetResponse<ParticipantIdentity>> for ResponseMethod<'_> {
    fn from(response: GetResponse<ParticipantIdentity>) -> Self {
        ResponseMethod::Get(GetResponseMethod::ParticipantIdentity(response))
    }
}

impl From<ChangesResponse<ShareNotification>> for ResponseMethod<'_> {
    fn from(response: ChangesResponse<ShareNotification>) -> Self {
        ResponseMethod::Changes(ChangesResponseMethod::ShareNotification(response))
    }
}

impl From<SetResponse<ShareNotification>> for ResponseMethod<'_> {
    fn from(response: SetResponse<ShareNotification>) -> Self {
        ResponseMethod::Set(SetResponseMethod::ShareNotification(response))
    }
}

impl From<GetResponse<ShareNotification>> for ResponseMethod<'_> {
    fn from(response: GetResponse<ShareNotification>) -> Self {
        ResponseMethod::Get(GetResponseMethod::ShareNotification(response))
    }
}

impl From<GetResponse<CalendarEvent>> for ResponseMethod<'_> {
    fn from(response: GetResponse<CalendarEvent>) -> Self {
        ResponseMethod::Get(GetResponseMethod::CalendarEvent(response))
    }
}

impl From<ParseResponse<CalendarEvent>> for ResponseMethod<'_> {
    fn from(value: ParseResponse<CalendarEvent>) -> Self {
        ResponseMethod::Parse(ParseResponseMethod::CalendarEvent(value))
    }
}

impl From<CopyResponse<CalendarEvent>> for ResponseMethod<'_> {
    fn from(value: CopyResponse<CalendarEvent>) -> Self {
        ResponseMethod::Copy(CopyResponseMethod::CalendarEvent(value))
    }
}

impl From<CalendarEventNotificationGetResponse> for ResponseMethod<'_> {
    fn from(value: CalendarEventNotificationGetResponse) -> Self {
        ResponseMethod::Get(GetResponseMethod::CalendarEventNotification(value))
    }
}

impl From<SetResponse<CalendarEventNotification>> for ResponseMethod<'_> {
    fn from(value: SetResponse<CalendarEventNotification>) -> Self {
        ResponseMethod::Set(SetResponseMethod::CalendarEventNotification(value))
    }
}
