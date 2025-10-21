/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodName {
    pub obj: MethodObject,
    pub fnc: MethodFunction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodObject {
    Email,
    Mailbox,
    Core,
    Blob,
    PushSubscription,
    Thread,
    SearchSnippet,
    Identity,
    EmailSubmission,
    VacationResponse,
    SieveScript,
    Principal,
    Quota,
    Calendar,
    CalendarEvent,
    CalendarEventNotification,
    AddressBook,
    ContactCard,
    FileNode,
    ParticipantIdentity,
    ShareNotification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodFunction {
    Get,
    Set,
    Changes,
    Query,
    QueryChanges,
    Copy,
    Import,
    Parse,
    Validate,
    Lookup,
    Upload,
    Echo,
    GetAvailability,
}

impl Display for MethodName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MethodName {
    pub fn new(obj: MethodObject, fnc: MethodFunction) -> Self {
        Self { obj, fnc }
    }

    pub fn error() -> Self {
        Self {
            obj: MethodObject::Thread,
            fnc: MethodFunction::Echo,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match (self.fnc, self.obj) {
            (MethodFunction::Get, MethodObject::PushSubscription) => "PushSubscription/get",
            (MethodFunction::Set, MethodObject::PushSubscription) => "PushSubscription/set",

            (MethodFunction::Get, MethodObject::Mailbox) => "Mailbox/get",
            (MethodFunction::Changes, MethodObject::Mailbox) => "Mailbox/changes",
            (MethodFunction::Query, MethodObject::Mailbox) => "Mailbox/query",
            (MethodFunction::QueryChanges, MethodObject::Mailbox) => "Mailbox/queryChanges",
            (MethodFunction::Set, MethodObject::Mailbox) => "Mailbox/set",

            (MethodFunction::Get, MethodObject::Thread) => "Thread/get",
            (MethodFunction::Changes, MethodObject::Thread) => "Thread/changes",

            (MethodFunction::Get, MethodObject::Email) => "Email/get",
            (MethodFunction::Changes, MethodObject::Email) => "Email/changes",
            (MethodFunction::Query, MethodObject::Email) => "Email/query",
            (MethodFunction::QueryChanges, MethodObject::Email) => "Email/queryChanges",
            (MethodFunction::Set, MethodObject::Email) => "Email/set",
            (MethodFunction::Copy, MethodObject::Email) => "Email/copy",
            (MethodFunction::Import, MethodObject::Email) => "Email/import",
            (MethodFunction::Parse, MethodObject::Email) => "Email/parse",

            (MethodFunction::Get, MethodObject::SearchSnippet) => "SearchSnippet/get",

            (MethodFunction::Get, MethodObject::Identity) => "Identity/get",
            (MethodFunction::Changes, MethodObject::Identity) => "Identity/changes",
            (MethodFunction::Set, MethodObject::Identity) => "Identity/set",

            (MethodFunction::Get, MethodObject::EmailSubmission) => "EmailSubmission/get",
            (MethodFunction::Changes, MethodObject::EmailSubmission) => "EmailSubmission/changes",
            (MethodFunction::Query, MethodObject::EmailSubmission) => "EmailSubmission/query",
            (MethodFunction::QueryChanges, MethodObject::EmailSubmission) => {
                "EmailSubmission/queryChanges"
            }
            (MethodFunction::Set, MethodObject::EmailSubmission) => "EmailSubmission/set",

            (MethodFunction::Get, MethodObject::VacationResponse) => "VacationResponse/get",
            (MethodFunction::Set, MethodObject::VacationResponse) => "VacationResponse/set",

            (MethodFunction::Get, MethodObject::SieveScript) => "SieveScript/get",
            (MethodFunction::Set, MethodObject::SieveScript) => "SieveScript/set",
            (MethodFunction::Query, MethodObject::SieveScript) => "SieveScript/query",
            (MethodFunction::Validate, MethodObject::SieveScript) => "SieveScript/validate",

            (MethodFunction::Get, MethodObject::Principal) => "Principal/get",
            (MethodFunction::Set, MethodObject::Principal) => "Principal/set",
            (MethodFunction::Query, MethodObject::Principal) => "Principal/query",
            (MethodFunction::Changes, MethodObject::Principal) => "Principal/changes",
            (MethodFunction::QueryChanges, MethodObject::Principal) => "Principal/queryChanges",
            (MethodFunction::GetAvailability, MethodObject::Principal) => "Principal/getAvailability",

            (MethodFunction::Get, MethodObject::Quota) => "Quota/get",
            (MethodFunction::Changes, MethodObject::Quota) => "Quota/changes",
            (MethodFunction::Query, MethodObject::Quota) => "Quota/query",
            (MethodFunction::QueryChanges, MethodObject::Quota) => "Quota/queryChanges",

            (MethodFunction::Get, MethodObject::Blob) => "Blob/get",
            (MethodFunction::Copy, MethodObject::Blob) => "Blob/copy",
            (MethodFunction::Lookup, MethodObject::Blob) => "Blob/lookup",
            (MethodFunction::Upload, MethodObject::Blob) => "Blob/upload",

            (MethodFunction::Get, MethodObject::AddressBook) => "AddressBook/get",
            (MethodFunction::Changes, MethodObject::AddressBook) => "AddressBook/changes",
            (MethodFunction::Set, MethodObject::AddressBook) => "AddressBook/set",

            (MethodFunction::Get, MethodObject::ContactCard) => "ContactCard/get",
            (MethodFunction::Changes, MethodObject::ContactCard) => "ContactCard/changes",
            (MethodFunction::Query, MethodObject::ContactCard) => "ContactCard/query",
            (MethodFunction::QueryChanges, MethodObject::ContactCard) => "ContactCard/queryChanges",
            (MethodFunction::Set, MethodObject::ContactCard) => "ContactCard/set",
            (MethodFunction::Copy, MethodObject::ContactCard) => "ContactCard/copy",
            (MethodFunction::Parse, MethodObject::ContactCard) => "ContactCard/parse",

            (MethodFunction::Get, MethodObject::FileNode) => "FileNode/get",
            (MethodFunction::Changes, MethodObject::FileNode) => "FileNode/changes",
            (MethodFunction::Query, MethodObject::FileNode) => "FileNode/query",
            (MethodFunction::QueryChanges, MethodObject::FileNode) => "FileNode/queryChanges",
            (MethodFunction::Set, MethodObject::FileNode) => "FileNode/set",

            (MethodFunction::Get, MethodObject::ShareNotification) => "ShareNotification/get",
            (MethodFunction::Changes, MethodObject::ShareNotification) => "ShareNotification/changes",
            (MethodFunction::Query, MethodObject::ShareNotification) => "ShareNotification/query",
            (MethodFunction::QueryChanges, MethodObject::ShareNotification) => "ShareNotification/queryChanges",
            (MethodFunction::Set, MethodObject::ShareNotification) => "ShareNotification/set",

            (MethodFunction::Get, MethodObject::Calendar) => "Calendar/get",
            (MethodFunction::Changes, MethodObject::Calendar) => "Calendar/changes",
            (MethodFunction::Set, MethodObject::Calendar) => "Calendar/set",

            (MethodFunction::Get, MethodObject::CalendarEvent) => "CalendarEvent/get",
            (MethodFunction::Changes, MethodObject::CalendarEvent) => "CalendarEvent/changes",
            (MethodFunction::Query, MethodObject::CalendarEvent) => "CalendarEvent/query",
            (MethodFunction::QueryChanges, MethodObject::CalendarEvent) => "CalendarEvent/queryChanges",
            (MethodFunction::Set, MethodObject::CalendarEvent) => "CalendarEvent/set",
            (MethodFunction::Copy, MethodObject::CalendarEvent) => "CalendarEvent/copy",
            (MethodFunction::Parse, MethodObject::CalendarEvent) => "CalendarEvent/parse",

            (MethodFunction::Get, MethodObject::CalendarEventNotification) => "CalendarEventNotification/get",
            (MethodFunction::Changes, MethodObject::CalendarEventNotification) => "CalendarEventNotification/changes",
            (MethodFunction::Query, MethodObject::CalendarEventNotification) => "CalendarEventNotification/query",
            (MethodFunction::QueryChanges, MethodObject::CalendarEventNotification) => "CalendarEventNotification/queryChanges",
            (MethodFunction::Set, MethodObject::CalendarEventNotification) => "CalendarEventNotification/set",

            (MethodFunction::Get, MethodObject::ParticipantIdentity) => "ParticipantIdentity/get",
            (MethodFunction::Changes, MethodObject::ParticipantIdentity) => "ParticipantIdentity/changes",
            (MethodFunction::Set, MethodObject::ParticipantIdentity) => "ParticipantIdentity/set",

            (MethodFunction::Echo, MethodObject::Core) => "Core/echo",
            _ => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
       hashify::tiny_map!(s.as_bytes(), 
            "PushSubscription/get" => (MethodObject::PushSubscription, MethodFunction::Get),
            "PushSubscription/set" => (MethodObject::PushSubscription, MethodFunction::Set),

            "Mailbox/get" => (MethodObject::Mailbox, MethodFunction::Get),
            "Mailbox/changes" => (MethodObject::Mailbox, MethodFunction::Changes),
            "Mailbox/query" => (MethodObject::Mailbox, MethodFunction::Query),
            "Mailbox/queryChanges" => (MethodObject::Mailbox, MethodFunction::QueryChanges),
            "Mailbox/set" => (MethodObject::Mailbox, MethodFunction::Set),

            "Thread/get" => (MethodObject::Thread, MethodFunction::Get),
            "Thread/changes" => (MethodObject::Thread, MethodFunction::Changes),

            "Email/get" => (MethodObject::Email, MethodFunction::Get),
            "Email/changes" => (MethodObject::Email, MethodFunction::Changes),
            "Email/query" => (MethodObject::Email, MethodFunction::Query),
            "Email/queryChanges" => (MethodObject::Email, MethodFunction::QueryChanges),
            "Email/set" => (MethodObject::Email, MethodFunction::Set),
            "Email/copy" => (MethodObject::Email, MethodFunction::Copy),
            "Email/import" => (MethodObject::Email, MethodFunction::Import),
            "Email/parse" => (MethodObject::Email, MethodFunction::Parse),

            "SearchSnippet/get" => (MethodObject::SearchSnippet, MethodFunction::Get),

            "Identity/get" => (MethodObject::Identity, MethodFunction::Get),
            "Identity/changes" => (MethodObject::Identity, MethodFunction::Changes),
            "Identity/set" => (MethodObject::Identity, MethodFunction::Set),

            "EmailSubmission/get" => (MethodObject::EmailSubmission, MethodFunction::Get),
            "EmailSubmission/changes" => (MethodObject::EmailSubmission, MethodFunction::Changes),
            "EmailSubmission/query" => (MethodObject::EmailSubmission, MethodFunction::Query),
            "EmailSubmission/queryChanges" => (MethodObject::EmailSubmission, MethodFunction::QueryChanges),
            "EmailSubmission/set" => (MethodObject::EmailSubmission, MethodFunction::Set),

            "VacationResponse/get" => (MethodObject::VacationResponse, MethodFunction::Get),
            "VacationResponse/set" => (MethodObject::VacationResponse, MethodFunction::Set),

            "SieveScript/get" => (MethodObject::SieveScript, MethodFunction::Get),
            "SieveScript/set" => (MethodObject::SieveScript, MethodFunction::Set),
            "SieveScript/query" => (MethodObject::SieveScript, MethodFunction::Query),
            "SieveScript/validate" => (MethodObject::SieveScript, MethodFunction::Validate),

            "Principal/get" => (MethodObject::Principal, MethodFunction::Get),
            "Principal/set" => (MethodObject::Principal, MethodFunction::Set),
            "Principal/query" => (MethodObject::Principal, MethodFunction::Query),
            "Principal/changes" => (MethodObject::Principal, MethodFunction::Changes),
            "Principal/queryChanges" => (MethodObject::Principal, MethodFunction::QueryChanges),
            "Principal/getAvailability" => (MethodObject::Principal, MethodFunction::GetAvailability),

            "Quota/get" => (MethodObject::Quota, MethodFunction::Get),
            "Quota/changes" => (MethodObject::Quota, MethodFunction::Changes),
            "Quota/query" => (MethodObject::Quota, MethodFunction::Query),
            "Quota/queryChanges" => (MethodObject::Quota, MethodFunction::QueryChanges),

            "Blob/get" => (MethodObject::Blob, MethodFunction::Get),
            "Blob/copy" => (MethodObject::Blob, MethodFunction::Copy),
            "Blob/lookup" => (MethodObject::Blob, MethodFunction::Lookup),
            "Blob/upload" => (MethodObject::Blob, MethodFunction::Upload),

            "AddressBook/get" => (MethodObject::AddressBook, MethodFunction::Get),
            "AddressBook/changes" => (MethodObject::AddressBook, MethodFunction::Changes),
            "AddressBook/set" => (MethodObject::AddressBook, MethodFunction::Set),

            "ContactCard/get" => (MethodObject::ContactCard, MethodFunction::Get),
            "ContactCard/changes" => (MethodObject::ContactCard, MethodFunction::Changes),
            "ContactCard/query" => (MethodObject::ContactCard, MethodFunction::Query),
            "ContactCard/queryChanges" => (MethodObject::ContactCard, MethodFunction::QueryChanges),
            "ContactCard/set" => (MethodObject::ContactCard, MethodFunction::Set),
            "ContactCard/copy" => (MethodObject::ContactCard, MethodFunction::Copy),
            "ContactCard/parse" => (MethodObject::ContactCard, MethodFunction::Parse),

            "FileNode/get" => (MethodObject::FileNode, MethodFunction::Get),
            "FileNode/changes" => (MethodObject::FileNode, MethodFunction::Changes),
            "FileNode/query" => (MethodObject::FileNode, MethodFunction::Query),
            "FileNode/queryChanges" => (MethodObject::FileNode, MethodFunction::QueryChanges),
            "FileNode/set" => (MethodObject::FileNode, MethodFunction::Set),

            "ShareNotification/get" => (MethodObject::ShareNotification, MethodFunction::Get),
            "ShareNotification/changes" => (MethodObject::ShareNotification, MethodFunction::Changes),
            "ShareNotification/set" => (MethodObject::ShareNotification, MethodFunction::Set),
            "ShareNotification/query" => (MethodObject::ShareNotification, MethodFunction::Query),
            "ShareNotification/queryChanges" => (MethodObject::ShareNotification, MethodFunction::QueryChanges),

            "Calendar/get" => (MethodObject::Calendar, MethodFunction::Get),
            "Calendar/changes" => (MethodObject::Calendar, MethodFunction::Changes),
            "Calendar/set" => (MethodObject::Calendar, MethodFunction::Set),

            "CalendarEvent/get" => (MethodObject::CalendarEvent, MethodFunction::Get),
            "CalendarEvent/changes" => (MethodObject::CalendarEvent, MethodFunction::Changes),
            "CalendarEvent/query" => (MethodObject::CalendarEvent, MethodFunction::Query),
            "CalendarEvent/queryChanges" => (MethodObject::CalendarEvent, MethodFunction::QueryChanges),
            "CalendarEvent/set" => (MethodObject::CalendarEvent, MethodFunction::Set),
            "CalendarEvent/copy" => (MethodObject::CalendarEvent, MethodFunction::Copy),
            "CalendarEvent/parse" => (MethodObject::CalendarEvent, MethodFunction::Parse),

            "CalendarEventNotification/get" => (MethodObject::CalendarEventNotification, MethodFunction::Get),
            "CalendarEventNotification/changes" => (MethodObject::CalendarEventNotification, MethodFunction::Changes),
            "CalendarEventNotification/set" => (MethodObject::CalendarEventNotification, MethodFunction::Set),
            "CalendarEventNotification/query" => (MethodObject::CalendarEventNotification, MethodFunction::Query),
            "CalendarEventNotification/queryChanges" => (MethodObject::CalendarEventNotification, MethodFunction::QueryChanges),

            "ParticipantIdentity/get" => (MethodObject::ParticipantIdentity, MethodFunction::Get),
            "ParticipantIdentity/changes" => (MethodObject::ParticipantIdentity, MethodFunction::Changes),
            "ParticipantIdentity/set" => (MethodObject::ParticipantIdentity, MethodFunction::Set),

            "Core/echo" => (MethodObject::Core, MethodFunction::Echo),

        ).map(|(obj, fnc)| MethodName { obj, fnc })
    }

}

impl Display for MethodObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MethodObject::Blob => "Blob",
            MethodObject::EmailSubmission => "EmailSubmission",
            MethodObject::SearchSnippet => "SearchSnippet",
            MethodObject::Identity => "Identity",
            MethodObject::VacationResponse => "VacationResponse",
            MethodObject::PushSubscription => "PushSubscription",
            MethodObject::SieveScript => "SieveScript",
            MethodObject::Principal => "Principal",
            MethodObject::Core => "Core",
            MethodObject::Mailbox => "Mailbox",
            MethodObject::Thread => "Thread",
            MethodObject::Email => "Email",
            MethodObject::Quota => "Quota",
            MethodObject::AddressBook => "AddressBook",
            MethodObject::ContactCard => "ContactCard",
            MethodObject::FileNode => "FileNode",
            MethodObject::ParticipantIdentity => "ParticipantIdentity",
            MethodObject::Calendar => "Calendar",
            MethodObject::CalendarEvent => "CalendarEvent",
            MethodObject::CalendarEventNotification => "CalendarEventNotification",
            MethodObject::ShareNotification => "ShareNotification",
        })
    }
}


impl<'de> serde::Deserialize<'de> for MethodName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = <&str>::deserialize(deserializer)?;

        MethodName::parse(value).ok_or_else(|| {
            serde::de::Error::custom(format!("Invalid method name: {:?}", value))
        })
    }
}

impl serde::Serialize for MethodName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
