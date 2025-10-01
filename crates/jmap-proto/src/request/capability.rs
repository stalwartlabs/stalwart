/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use crate::response::serialize::serialize_hex;
use serde::{Deserialize, Deserializer};
use types::{id::Id, type_state::DataType};
use utils::map::vec_map::VecMap;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Session {
    #[serde(rename(serialize = "capabilities"))]
    capabilities: VecMap<Capability, Capabilities>,
    #[serde(rename(serialize = "accounts"))]
    accounts: VecMap<Id, Account>,
    #[serde(rename(serialize = "primaryAccounts"))]
    primary_accounts: VecMap<Capability, Id>,
    #[serde(rename(serialize = "username"))]
    username: String,
    #[serde(rename(serialize = "apiUrl"))]
    api_url: String,
    #[serde(rename(serialize = "downloadUrl"))]
    download_url: String,
    #[serde(rename(serialize = "uploadUrl"))]
    upload_url: String,
    #[serde(rename(serialize = "eventSourceUrl"))]
    event_source_url: String,
    #[serde(rename(serialize = "state"))]
    #[serde(serialize_with = "serialize_hex")]
    state: u32,
    #[serde(skip)]
    base_url: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct Account {
    #[serde(rename(serialize = "name"))]
    name: String,
    #[serde(rename(serialize = "isPersonal"))]
    is_personal: bool,
    #[serde(rename(serialize = "isReadOnly"))]
    is_read_only: bool,
    #[serde(rename(serialize = "accountCapabilities"))]
    account_capabilities: VecMap<Capability, Capabilities>,
}

#[derive(Debug, Clone, Copy, serde::Serialize, Hash, PartialEq, Eq)]
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
    #[serde(rename(serialize = "urn:ietf:params:jmap:calendars"))]
    Calendars = 1 << 5,
    #[serde(rename(serialize = "urn:ietf:params:jmap:websocket"))]
    WebSocket = 1 << 6,
    #[serde(rename(serialize = "urn:ietf:params:jmap:sieve"))]
    Sieve = 1 << 7,
    #[serde(rename(serialize = "urn:ietf:params:jmap:blob"))]
    Blob = 1 << 8,
    #[serde(rename(serialize = "urn:ietf:params:jmap:quota"))]
    Quota = 1 << 9,
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
    pub email_query_sort_options: Vec<String>,
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

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct EmptyCapabilities {}

#[derive(Default, Clone)]
pub struct BaseCapabilities {
    pub session: VecMap<Capability, Capabilities>,
    pub account: VecMap<Capability, Capabilities>,
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

    pub fn set_primary_account(
        &mut self,
        account_id: Id,
        username: String,
        name: String,
        capabilities: Option<&[Capability]>,
        account_capabilities: &VecMap<Capability, Capabilities>,
    ) {
        self.username = username;

        if let Some(capabilities) = capabilities {
            for capability in capabilities {
                self.primary_accounts.append(*capability, account_id);
            }
        } else {
            for capability in self.capabilities.keys() {
                self.primary_accounts.append(*capability, account_id);
            }
        }

        self.accounts.set(
            account_id,
            Account::new(name, true, false).add_capabilities(capabilities, account_capabilities),
        );
    }

    pub fn add_account(
        &mut self,
        account_id: Id,
        name: String,
        is_personal: bool,
        is_read_only: bool,
        capabilities: Option<&[Capability]>,
        account_capabilities: &VecMap<Capability, Capabilities>,
    ) {
        self.accounts.set(
            account_id,
            Account::new(name, is_personal, is_read_only)
                .add_capabilities(capabilities, account_capabilities),
        );
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

impl Account {
    pub fn new(name: String, is_personal: bool, is_read_only: bool) -> Account {
        Account {
            name,
            is_personal,
            is_read_only,
            account_capabilities: VecMap::new(),
        }
    }

    pub fn add_capabilities(
        mut self,
        capabilities: Option<&[Capability]>,
        account_capabilities: &VecMap<Capability, Capabilities>,
    ) -> Account {
        if let Some(capabilities) = capabilities {
            for capability in capabilities {
                if let Some(value) = account_capabilities.get(capability) {
                    self.account_capabilities.append(*capability, value.clone());
                }
            }
        } else {
            self.account_capabilities = account_capabilities.clone();
        }
        self
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
