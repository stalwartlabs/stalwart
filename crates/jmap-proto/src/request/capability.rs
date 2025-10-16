/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use crate::{
    object::{email::EmailComparator, file_node::FileNodeComparator},
    response::serialize::serialize_hex,
    types::date::UTCDate,
};
use ahash::AHashMap;
use serde::{Deserialize, Deserializer};
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Session {
    #[serde(rename(serialize = "capabilities"))]
    pub capabilities: VecMap<Capability, Capabilities>,
    #[serde(rename(serialize = "accounts"))]
    pub accounts: VecMap<Id, Account>,
    #[serde(rename(serialize = "primaryAccounts"))]
    pub primary_accounts: VecMap<Capability, Id>,
    #[serde(rename(serialize = "username"))]
    pub username: String,
    #[serde(rename(serialize = "apiUrl"))]
    pub api_url: String,
    #[serde(rename(serialize = "downloadUrl"))]
    pub download_url: String,
    #[serde(rename(serialize = "uploadUrl"))]
    pub upload_url: String,
    #[serde(rename(serialize = "eventSourceUrl"))]
    pub event_source_url: String,
    #[serde(rename(serialize = "state"))]
    #[serde(serialize_with = "serialize_hex")]
    pub state: u32,
    #[serde(skip)]
    pub base_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Account {
    #[serde(rename(serialize = "name"))]
    pub name: String,
    #[serde(rename(serialize = "isPersonal"))]
    pub is_personal: bool,
    #[serde(rename(serialize = "isReadOnly"))]
    pub is_read_only: bool,
    #[serde(rename(serialize = "accountCapabilities"))]
    pub account_capabilities: VecMap<Capability, Capabilities>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    #[serde(rename(serialize = "urn:ietf:params:jmap:core"))]
    Core = 1 << 0,
    #[serde(rename(serialize = "urn:ietf:params:jmap:mail"))]
    Mail = 1 << 1,
    #[serde(rename(serialize = "urn:ietf:params:jmap:submission"))]
    Submission = 1 << 2,
    #[serde(rename(serialize = "urn:ietf:params:jmap:vacationresponse"))]
    VacationResponse = 1 << 3,
    #[serde(rename(serialize = "urn:ietf:params:jmap:contacts"))]
    Contacts = 1 << 4,
    #[serde(rename(serialize = "urn:ietf:params:jmap:contacts:parse"))]
    ContactsParse = 1 << 5,
    #[serde(rename(serialize = "urn:ietf:params:jmap:calendars"))]
    Calendars = 1 << 6,
    #[serde(rename(serialize = "urn:ietf:params:jmap:calendars:parse"))]
    CalendarsParse = 1 << 7,
    #[serde(rename(serialize = "urn:ietf:params:jmap:websocket"))]
    WebSocket = 1 << 8,
    #[serde(rename(serialize = "urn:ietf:params:jmap:sieve"))]
    Sieve = 1 << 9,
    #[serde(rename(serialize = "urn:ietf:params:jmap:blob"))]
    Blob = 1 << 10,
    #[serde(rename(serialize = "urn:ietf:params:jmap:quota"))]
    Quota = 1 << 11,
    #[serde(rename(serialize = "urn:ietf:params:jmap:principals"))]
    Principals = 1 << 12,
    #[serde(rename(serialize = "urn:ietf:params:jmap:principals:owner"))]
    PrincipalsOwner = 1 << 13,
    #[serde(rename(serialize = "urn:ietf:params:jmap:principals:availability"))]
    PrincipalsAvailability = 1 << 14,
    #[serde(rename(serialize = "urn:ietf:params:jmap:filenode"))]
    FileNode = 1 << 15,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(transparent)]
pub struct CapabilityIds(pub u32);

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
#[allow(dead_code)]
pub enum Capabilities {
    Core(CoreCapabilities),
    Mail(MailCapabilities),
    Submission(SubmissionCapabilities),
    WebSocket(WebSocketCapabilities),
    SieveAccount(SieveAccountCapabilities),
    SieveSession(SieveSessionCapabilities),
    Blob(BlobCapabilities),
    Contacts(ContactsCapabilities),
    Principals(PrincipalCapabilities),
    PrincipalsAvailability(PrincipalAvailabilityCapabilities),
    Calendar(CalendarCapabilities),
    FileNode(FileNodeCapabilities),
    Empty(EmptyCapabilities),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CoreCapabilities {
    #[serde(rename(serialize = "maxSizeUpload"))]
    pub max_size_upload: usize,
    #[serde(rename(serialize = "maxConcurrentUpload"))]
    pub max_concurrent_upload: usize,
    #[serde(rename(serialize = "maxSizeRequest"))]
    pub max_size_request: usize,
    #[serde(rename(serialize = "maxConcurrentRequests"))]
    pub max_concurrent_requests: usize,
    #[serde(rename(serialize = "maxCallsInRequest"))]
    pub max_calls_in_request: usize,
    #[serde(rename(serialize = "maxObjectsInGet"))]
    pub max_objects_in_get: usize,
    #[serde(rename(serialize = "maxObjectsInSet"))]
    pub max_objects_in_set: usize,
    #[serde(rename(serialize = "collationAlgorithms"))]
    pub collation_algorithms: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebSocketCapabilities {
    #[serde(rename(serialize = "url"))]
    pub url: String,
    #[serde(rename(serialize = "supportsPush"))]
    pub supports_push: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SieveSessionCapabilities {
    #[serde(rename(serialize = "implementation"))]
    pub implementation: &'static str,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SieveAccountCapabilities {
    #[serde(rename(serialize = "maxSizeScriptName"))]
    pub max_script_name: usize,
    #[serde(rename(serialize = "maxSizeScript"))]
    pub max_script_size: usize,
    #[serde(rename(serialize = "maxNumberScripts"))]
    pub max_scripts: usize,
    #[serde(rename(serialize = "maxNumberRedirects"))]
    pub max_redirects: usize,
    #[serde(rename(serialize = "sieveExtensions"))]
    pub extensions: Vec<String>,
    #[serde(rename(serialize = "notificationMethods"))]
    pub notification_methods: Option<Vec<String>>,
    #[serde(rename(serialize = "externalLists"))]
    pub ext_lists: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MailCapabilities {
    #[serde(rename(serialize = "maxMailboxesPerEmail"))]
    pub max_mailboxes_per_email: Option<usize>,
    #[serde(rename(serialize = "maxMailboxDepth"))]
    pub max_mailbox_depth: usize,
    #[serde(rename(serialize = "maxSizeMailboxName"))]
    pub max_size_mailbox_name: usize,
    #[serde(rename(serialize = "maxSizeAttachmentsPerEmail"))]
    pub max_size_attachments_per_email: usize,
    #[serde(rename(serialize = "emailQuerySortOptions"))]
    pub email_query_sort_options: Vec<EmailComparator>,
    #[serde(rename(serialize = "mayCreateTopLevelMailbox"))]
    pub may_create_top_level_mailbox: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SubmissionCapabilities {
    #[serde(rename(serialize = "maxDelayedSend"))]
    pub max_delayed_send: usize,
    #[serde(rename(serialize = "submissionExtensions"))]
    pub submission_extensions: VecMap<String, Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BlobCapabilities {
    #[serde(rename(serialize = "maxSizeBlobSet"))]
    pub max_size_blob_set: usize,
    #[serde(rename(serialize = "maxDataSources"))]
    pub max_data_sources: usize,
    #[serde(rename(serialize = "supportedTypeNames"))]
    pub supported_type_names: Vec<DataType>,
    #[serde(rename(serialize = "supportedDigestAlgorithms"))]
    pub supported_digest_algorithms: Vec<&'static str>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CalendarCapabilities {
    #[serde(rename(serialize = "maxCalendarsPerEvent"))]
    pub max_calendars_per_event: Option<usize>,
    #[serde(rename(serialize = "minDateTime"))]
    pub min_date_time: UTCDate,
    #[serde(rename(serialize = "maxDateTime"))]
    pub max_date_time: UTCDate,
    #[serde(rename(serialize = "maxExpandedQueryDuration"))]
    pub max_expanded_query_duration: String,
    #[serde(rename(serialize = "maxParticipantsPerEvent"))]
    pub max_participants_per_event: Option<usize>,
    #[serde(rename(serialize = "mayCreateCalendar"))]
    pub may_create_calendar: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContactsCapabilities {
    #[serde(rename(serialize = "maxAddressBooksPerCard"))]
    pub max_address_books_per_card: Option<usize>,
    #[serde(rename(serialize = "mayCreateAddressBook"))]
    pub may_create_address_book: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PrincipalAvailabilityCapabilities {
    #[serde(rename(serialize = "maxAvailabilityDuration"))]
    pub max_availability_duration: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PrincipalCapabilities {
    #[serde(rename(serialize = "currentUserPrincipalId"))]
    pub current_user_principal_id: Option<Id>,
}

/*#[derive(Debug, Clone, serde::Serialize)]
pub struct PrincipalOwnerCapabilities {
    #[serde(rename(serialize = "accountIdForPrincipal"))]
    pub account_id_for_principal: Id,

    #[serde(rename(serialize = "principalId"))]
    pub principal_id: Id,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PrincipalCalendarCapabilities {
    #[serde(rename(serialize = "accountIdForPrincipal"))]
    pub account_id_for_principal: Option<Id>,
    #[serde(rename(serialize = "mayGetAvailability"))]
    pub may_get_availability: bool,
    #[serde(rename(serialize = "mayShareWith"))]
    pub may_share_with: bool,
    #[serde(rename(serialize = "calendarAddress"))]
    pub calendar_address: String,
}*/

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileNodeCapabilities {
    #[serde(rename(serialize = "maxFileNodeDepth"))]
    pub max_file_node_depth: Option<usize>,
    #[serde(rename(serialize = "maxSizeFileNodeName"))]
    pub max_size_file_node_name: usize,
    #[serde(rename(serialize = "fileNodeQuerySortOptions"))]
    pub file_node_query_sort_options: Vec<FileNodeComparator>,
    #[serde(rename(serialize = "mayCreateTopLevelFileNode"))]
    pub may_create_top_level_file_node: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EmptyCapabilities {}

#[derive(Default, Clone)]
pub struct BaseCapabilities {
    pub session: VecMap<Capability, Capabilities>,
    pub account: AHashMap<Capability, Capabilities>,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Capability::Core => "urn:ietf:params:jmap:core",
            Capability::Mail => "urn:ietf:params:jmap:mail",
            Capability::Submission => "urn:ietf:params:jmap:submission",
            Capability::VacationResponse => "urn:ietf:params:jmap:vacationresponse",
            Capability::Contacts => "urn:ietf:params:jmap:contacts",
            Capability::ContactsParse => "urn:ietf:params:jmap:contacts:parse",
            Capability::Calendars => "urn:ietf:params:jmap:calendars",
            Capability::CalendarsParse => "urn:ietf:params:jmap:calendars:parse",
            Capability::WebSocket => "urn:ietf:params:jmap:websocket",
            Capability::Sieve => "urn:ietf:params:jmap:sieve",
            Capability::Blob => "urn:ietf:params:jmap:blob",
            Capability::Quota => "urn:ietf:params:jmap:quota",
            Capability::Principals => "urn:ietf:params:jmap:principals",
            Capability::PrincipalsOwner => "urn:ietf:params:jmap:principals:owner",
            Capability::PrincipalsAvailability => "urn:ietf:params:jmap:principals:availability",
            Capability::FileNode => "urn:ietf:params:jmap:filenode",
        }
    }

    pub fn all_capabilities() -> &'static [Capability] {
        &[
            Capability::Core,
            Capability::Mail,
            Capability::Submission,
            Capability::VacationResponse,
            Capability::Contacts,
            Capability::ContactsParse,
            Capability::Calendars,
            Capability::CalendarsParse,
            Capability::WebSocket,
            Capability::Sieve,
            Capability::Blob,
            Capability::Quota,
            Capability::Principals,
            Capability::PrincipalsAvailability,
            Capability::FileNode,
        ]
    }
}

impl Session {
    pub fn new(base_url: impl Into<String>, base_capabilities: &BaseCapabilities) -> Session {
        let base_url = base_url.into();
        let mut capabilities = base_capabilities.session.clone();
        capabilities.append(
            Capability::WebSocket,
            Capabilities::WebSocket(WebSocketCapabilities::new(&base_url)),
        );

        Session {
            capabilities,
            accounts: VecMap::new(),
            primary_accounts: VecMap::new(),
            username: "".to_string(),
            api_url: format!("{}/jmap/", base_url),
            download_url: format!(
                "{}/jmap/download/{{accountId}}/{{blobId}}/{{name}}?accept={{type}}",
                base_url
            ),
            upload_url: format!("{}/jmap/upload/{{accountId}}/", base_url),
            event_source_url: format!(
                "{}/jmap/eventsource/?types={{types}}&closeafter={{closeafter}}&ping={{ping}}",
                base_url
            ),
            base_url,
            state: 0,
        }
    }

    pub fn set_state(&mut self, state: u32) {
        self.state = state;
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Default for SieveSessionCapabilities {
    fn default() -> Self {
        Self {
            implementation: "Stalwart v1.0.0",
        }
    }
}

impl WebSocketCapabilities {
    pub fn new(base_url: &str) -> Self {
        WebSocketCapabilities {
            url: format!(
                "ws{}/jmap/ws",
                base_url.strip_prefix("http").unwrap_or_default()
            ),
            supports_push: true,
        }
    }
}

impl Capabilities {
    pub fn to_account_capabilities(
        &self,
        current_user_principal_id: Option<Id>,
        may_create: bool,
    ) -> Capabilities {
        match self {
            Capabilities::Contacts(contacts_capabilities) => {
                Capabilities::Contacts(ContactsCapabilities {
                    may_create_address_book: may_create,
                    ..contacts_capabilities.clone()
                })
            }
            Capabilities::Principals(_) => Capabilities::Principals(PrincipalCapabilities {
                current_user_principal_id,
            }),
            Capabilities::Calendar(calendar_capabilities) => {
                Capabilities::Calendar(CalendarCapabilities {
                    may_create_calendar: may_create,
                    ..calendar_capabilities.clone()
                })
            }
            Capabilities::FileNode(file_node_capabilities) => {
                Capabilities::FileNode(FileNodeCapabilities {
                    may_create_top_level_file_node: may_create,
                    ..file_node_capabilities.clone()
                })
            }
            _ => self.clone(),
        }
    }
}

impl Capability {
    pub fn parse(s: &str) -> Option<Self> {
        hashify::tiny_map!(s.as_bytes(),
            "urn:ietf:params:jmap:core" => Capability::Core,
            "urn:ietf:params:jmap:mail" => Capability::Mail,
            "urn:ietf:params:jmap:submission" => Capability::Submission,
            "urn:ietf:params:jmap:vacationresponse" => Capability::VacationResponse,
            "urn:ietf:params:jmap:contacts" => Capability::Contacts,
            "urn:ietf:params:jmap:calendars" => Capability::Calendars,
            "urn:ietf:params:jmap:websocket" => Capability::WebSocket,
            "urn:ietf:params:jmap:sieve" => Capability::Sieve,
            "urn:ietf:params:jmap:blob" => Capability::Blob,
            "urn:ietf:params:jmap:quota" => Capability::Quota,
            "urn:ietf:params:jmap:principals" => Capability::Principals,
            "urn:ietf:params:jmap:principals:owner" => Capability::PrincipalsOwner,
            "urn:ietf:params:jmap:filenode" => Capability::FileNode,
            "urn:ietf:params:jmap:principals:availability" => Capability::PrincipalsAvailability,
            "urn:ietf:params:jmap:contacts:parse" => Capability::ContactsParse,
            "urn:ietf:params:jmap:calendars:parse" => Capability::CalendarsParse,
        )
    }
}

impl<'de> Deserialize<'de> for CapabilityIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapabilityIdsVisitor;

        impl<'de> serde::de::Visitor<'de> for CapabilityIdsVisitor {
            type Value = CapabilityIds;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an array of capability strings")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut capability_flags = 0u32;

                while let Some(capability_str) = seq.next_element::<&str>()? {
                    let capability = Capability::parse(capability_str).ok_or_else(|| {
                        serde::de::Error::custom(format!("Unknown capability: {capability_str:?}"))
                    })?;

                    capability_flags |= capability as u32;
                }

                Ok(CapabilityIds(capability_flags))
            }
        }

        deserializer.deserialize_seq(CapabilityIdsVisitor)
    }
}
