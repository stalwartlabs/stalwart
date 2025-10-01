/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod capability;
pub mod deserialize;
pub mod method;
pub mod parser;
pub mod reference;
pub mod websocket;

use self::method::MethodName;
use crate::{
    method::{
        changes::ChangesRequest,
        copy::{CopyBlobRequest, CopyRequest},
        get::GetRequest,
        import::ImportEmailRequest,
        lookup::BlobLookupRequest,
        parse::ParseEmailRequest,
        query::QueryRequest,
        query_changes::QueryChangesRequest,
        search_snippet::GetSearchSnippetRequest,
        set::SetRequest,
        upload::BlobUploadRequest,
        validate::ValidateSieveScriptRequest,
    },
    object::{
        AnyId, blob::Blob, email::Email, email_submission::EmailSubmission, identity::Identity,
        mailbox::Mailbox, principal::Principal, push_subscription::PushSubscription, quota::Quota,
        sieve::Sieve, thread::Thread, vacation_response::VacationResponse,
    },
    request::{capability::CapabilityIds, reference::MaybeIdReference},
};
use jmap_tools::{Null, Value};
use std::{collections::HashMap, fmt::Debug, str::FromStr};
use utils::map::vec_map::VecMap;

#[derive(Debug)]
pub struct Request<'x> {
    pub using: CapabilityIds,
    pub method_calls: Vec<Call<RequestMethod<'x>>>,
    pub created_ids: Option<HashMap<String, AnyId>>,
}

#[derive(Debug)]
pub struct Call<T> {
    pub id: String,
    pub name: MethodName,
    pub method: T,
}

#[derive(Debug)]
pub enum RequestMethod<'x> {
    Get(GetRequestMethod),
    Set(SetRequestMethod<'x>),
    Changes(ChangesRequest),
    Copy(CopyRequestMethod<'x>),
    ImportEmail(ImportEmailRequest),
    ParseEmail(ParseEmailRequest),
    Query(QueryRequestMethod),
    QueryChanges(QueryChangesRequestMethod),
    SearchSnippet(GetSearchSnippetRequest),
    ValidateScript(ValidateSieveScriptRequest),
    LookupBlob(BlobLookupRequest),
    UploadBlob(BlobUploadRequest),
    Echo(Value<'x, Null, Null>),
    Error(trc::Error),
}

#[derive(Debug)]
pub enum GetRequestMethod {
    Email(GetRequest<Email>),
    Mailbox(GetRequest<Mailbox>),
    Thread(GetRequest<Thread>),
    Identity(GetRequest<Identity>),
    EmailSubmission(GetRequest<EmailSubmission>),
    PushSubscription(GetRequest<PushSubscription>),
    Sieve(GetRequest<Sieve>),
    VacationResponse(GetRequest<VacationResponse>),
    Principal(GetRequest<Principal>),
    Quota(GetRequest<Quota>),
    Blob(GetRequest<Blob>),
}

#[derive(Debug)]
pub enum SetRequestMethod<'x> {
    Email(SetRequest<'x, Email>),
    Mailbox(SetRequest<'x, Mailbox>),
    Identity(SetRequest<'x, Identity>),
    EmailSubmission(SetRequest<'x, EmailSubmission>),
    PushSubscription(SetRequest<'x, PushSubscription>),
    Sieve(SetRequest<'x, Sieve>),
    VacationResponse(SetRequest<'x, VacationResponse>),
}

#[derive(Debug)]
pub enum CopyRequestMethod<'x> {
    Email(CopyRequest<'x, Email>),
    Blob(CopyBlobRequest),
}

#[derive(Debug)]
pub enum QueryRequestMethod {
    Email(QueryRequest<Email>),
    Mailbox(QueryRequest<Mailbox>),
    EmailSubmission(QueryRequest<EmailSubmission>),
    Sieve(QueryRequest<Sieve>),
    Principal(QueryRequest<Principal>),
    Quota(QueryRequest<Quota>),
}

#[derive(Debug)]
pub enum QueryChangesRequestMethod {
    Email(QueryChangesRequest<Email>),
    Mailbox(QueryChangesRequest<Mailbox>),
    EmailSubmission(QueryChangesRequest<EmailSubmission>),
    Sieve(QueryChangesRequest<Sieve>),
    Principal(QueryChangesRequest<Principal>),
    Quota(QueryChangesRequest<Quota>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeInvalid<V: FromStr> {
    Value(V),
    Invalid(String),
}

impl<'de, V: FromStr> serde::Deserialize<'de> for MaybeInvalid<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;

        if let Ok(id) = V::from_str(value) {
            Ok(MaybeInvalid::Value(id))
        } else {
            Ok(MaybeInvalid::Invalid(value.to_string()))
        }
    }
}

impl<V: serde::Serialize + FromStr> serde::Serialize for MaybeInvalid<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            MaybeInvalid::Value(id) => id.serialize(serializer),
            MaybeInvalid::Invalid(str) => serializer.serialize_str(str),
        }
    }
}

impl<V: FromStr> Default for MaybeInvalid<V> {
    fn default() -> Self {
        MaybeInvalid::Invalid("".to_string())
    }
}

#[allow(clippy::derivable_impls)]
impl Default for Request<'_> {
    fn default() -> Self {
        Request {
            using: CapabilityIds::default(),
            method_calls: Vec::new(),
            created_ids: None,
        }
    }
}

impl<T> MaybeInvalid<T>
where
    T: FromStr,
{
    pub fn try_unwrap(self) -> Option<T> {
        match self {
            MaybeInvalid::Value(id) => Some(id),
            MaybeInvalid::Invalid(_) => None,
        }
    }
}

pub trait IntoValid {
    type Item;

    fn into_valid(self) -> impl Iterator<Item = Self::Item>;
}

impl<T: FromStr> IntoValid for Vec<MaybeInvalid<T>> {
    type Item = T;

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter().filter_map(|v| v.try_unwrap())
    }
}

impl<T: FromStr> IntoValid for Vec<MaybeIdReference<T>> {
    type Item = T;

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter().filter_map(|v| v.try_unwrap())
    }
}

impl<T: FromStr + Eq, V> IntoValid for VecMap<MaybeInvalid<T>, V> {
    type Item = (T, V);

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter()
            .filter_map(|(k, v)| k.try_unwrap().map(|k| (k, v)))
    }
}

impl<T: FromStr + Eq, V> IntoValid for VecMap<MaybeIdReference<T>, V> {
    type Item = (T, V);

    fn into_valid(self) -> impl Iterator<Item = Self::Item> {
        self.into_iter()
            .filter_map(|(k, v)| k.try_unwrap().map(|k| (k, v)))
    }
}
