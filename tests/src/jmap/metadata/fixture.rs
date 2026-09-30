/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    jmap::{JmapResponse, JmapSetError, JmapUtils},
    server::TestServer,
};
use registry::schema::{
    enums::TaskAccountMaintenanceType,
    structs::{Task, TaskAccountMaintenance, TaskStatus},
};
use serde_json::{Map, Value, json};
use std::cell::Cell;
use store::rand::{RngExt, distr::Alphanumeric, rng};

pub const METADATA_CAPABILITY: &str = "urn:ietf:params:jmap:metadata";

const PLAIN_CAPABILITIES: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
    "urn:ietf:params:jmap:contacts",
    "urn:ietf:params:jmap:calendars",
    "urn:ietf:params:jmap:sieve",
    "urn:ietf:params:jmap:blob",
    "urn:ietf:params:jmap:quota",
    "urn:ietf:params:jmap:principals",
    "urn:ietf:params:jmap:filenode",
    "urn:ietf:params:jmap:mail:share",
    "urn:stalwart:jmap",
];

const METADATA_CAPABILITIES: &[&str] = &[
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:mail",
    "urn:ietf:params:jmap:submission",
    "urn:ietf:params:jmap:contacts",
    "urn:ietf:params:jmap:calendars",
    "urn:ietf:params:jmap:sieve",
    "urn:ietf:params:jmap:blob",
    "urn:ietf:params:jmap:quota",
    "urn:ietf:params:jmap:principals",
    "urn:ietf:params:jmap:filenode",
    "urn:ietf:params:jmap:mail:share",
    "urn:stalwart:jmap",
    METADATA_CAPABILITY,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Using {
    Metadata,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MetaType {
    Email,
    Mailbox,
    SieveScript,
    Calendar,
    CalendarEvent,
    AddressBook,
    ContactCard,
    FileNode,
}

pub struct Parents {
    pub mailboxes: [String; 2],
    pub calendars: [String; 2],
    pub address_books: [String; 2],
    pub folders: [String; 2],
}

pub struct Ctx<'x> {
    pub test: &'x TestServer,
    serial: Cell<u32>,
}

impl Using {
    pub fn capabilities(self) -> &'static [&'static str] {
        match self {
            Using::Metadata => METADATA_CAPABILITIES,
            Using::Plain => PLAIN_CAPABILITIES,
        }
    }
}

impl MetaType {
    pub const ALL: [MetaType; 8] = [
        MetaType::Email,
        MetaType::Mailbox,
        MetaType::SieveScript,
        MetaType::Calendar,
        MetaType::CalendarEvent,
        MetaType::AddressBook,
        MetaType::ContactCard,
        MetaType::FileNode,
    ];

    pub const SHAREABLE: [MetaType; 7] = [
        MetaType::Email,
        MetaType::Mailbox,
        MetaType::Calendar,
        MetaType::CalendarEvent,
        MetaType::AddressBook,
        MetaType::ContactCard,
        MetaType::FileNode,
    ];

    pub const COPYABLE: [MetaType; 4] = [
        MetaType::Email,
        MetaType::CalendarEvent,
        MetaType::ContactCard,
        MetaType::FileNode,
    ];

    pub fn name(self) -> &'static str {
        match self {
            MetaType::Email => "Email",
            MetaType::Mailbox => "Mailbox",
            MetaType::SieveScript => "SieveScript",
            MetaType::Calendar => "Calendar",
            MetaType::CalendarEvent => "CalendarEvent",
            MetaType::AddressBook => "AddressBook",
            MetaType::ContactCard => "ContactCard",
            MetaType::FileNode => "FileNode",
        }
    }

    pub fn has_changes(self) -> bool {
        self != MetaType::SieveScript
    }

    pub fn container(self) -> MetaType {
        match self {
            MetaType::Email => MetaType::Mailbox,
            MetaType::CalendarEvent => MetaType::Calendar,
            MetaType::ContactCard => MetaType::AddressBook,
            other => other,
        }
    }

    pub fn is_contained(self) -> bool {
        self.container() != self
    }

    pub fn destroy_arguments(self) -> Value {
        match self {
            MetaType::Mailbox => json!({"onDestroyRemoveEmails": true}),
            MetaType::Calendar => json!({"onDestroyRemoveEvents": true}),
            MetaType::AddressBook => json!({"onDestroyRemoveContents": true}),
            MetaType::FileNode => json!({"onDestroyRemoveChildren": true}),
            _ => json!({}),
        }
    }

    pub fn rename_patch(self, value: &str) -> Value {
        match self {
            MetaType::Email => json!({"keywords/$flagged": true}),
            MetaType::CalendarEvent => json!({"title": value}),
            MetaType::ContactCard => json!({"name": {"full": value}}),
            _ => json!({"name": value}),
        }
    }

    pub fn share_rights(self, access: Access) -> Value {
        match (self.container(), access) {
            (MetaType::Mailbox, Access::Read) => json!({"mayReadItems": true}),
            (MetaType::Mailbox, Access::Write) => json!({
                "mayReadItems": true,
                "maySetKeywords": true,
                "maySetSeen": true,
                "mayRename": true
            }),
            (MetaType::Calendar, Access::Read) => json!({"mayReadItems": true}),
            (MetaType::Calendar, Access::Write) => {
                json!({"mayReadItems": true, "mayWriteAll": true})
            }
            (MetaType::AddressBook, Access::Read) => json!({"mayRead": true}),
            (MetaType::AddressBook, Access::Write) => json!({"mayRead": true, "mayWrite": true}),
            (MetaType::FileNode, Access::Read) => json!({"mayRead": true}),
            (MetaType::FileNode, Access::Write) => json!({
                "mayRead": true,
                "mayRename": true,
                "mayModifyContent": true
            }),
            (other, _) => panic!("{} cannot be shared", other.name()),
        }
    }
}

impl Parents {
    pub fn parent(&self, ty: MetaType, slot: usize) -> Option<&str> {
        match ty {
            MetaType::Email | MetaType::Mailbox => Some(self.mailboxes[slot].as_str()),
            MetaType::CalendarEvent => Some(self.calendars[slot].as_str()),
            MetaType::ContactCard => Some(self.address_books[slot].as_str()),
            MetaType::FileNode => Some(self.folders[slot].as_str()),
            MetaType::SieveScript | MetaType::Calendar | MetaType::AddressBook => None,
        }
    }

    pub fn filter(&self, ty: MetaType, slot: usize) -> Option<Value> {
        let parent = self.parent(ty, slot)?;
        Some(match ty {
            MetaType::Email => json!({"inMailbox": parent}),
            MetaType::CalendarEvent => json!({"inCalendar": parent}),
            MetaType::ContactCard => json!({"inAddressBook": parent}),
            _ => json!({"parentId": parent}),
        })
    }
}

impl<'x> Ctx<'x> {
    pub fn new(test: &'x TestServer) -> Self {
        Ctx {
            test,
            serial: Cell::new(0),
        }
    }

    pub fn account(&self, name: &str) -> &'x Account {
        self.test.account(name)
    }

    pub fn unique(&self, ty: MetaType) -> String {
        let serial = self.serial.get() + 1;
        self.serial.set(serial);
        format!("meta-{}-{serial:05}z", ty.name().to_ascii_lowercase())
    }

    pub async fn call(&self, caller: &Account, using: Using, calls: Value) -> JmapResponse {
        caller.jmap_request(using.capabilities(), calls).await
    }

    pub async fn method(
        &self,
        caller: &Account,
        using: Using,
        method: &str,
        arguments: Value,
    ) -> JmapResponse {
        self.call(caller, using, json!([[method, arguments, "0"]]))
            .await
    }

    pub async fn parents(&self, owner: &Account) -> Parents {
        self.parents_as(owner, owner).await
    }

    pub async fn parents_as(&self, caller: &Account, owner: &Account) -> Parents {
        let mut mailboxes = Vec::with_capacity(2);
        let mut calendars = Vec::with_capacity(2);
        let mut address_books = Vec::with_capacity(2);
        let mut folders = Vec::with_capacity(2);
        for _ in 0..2 {
            for (ty, ids) in [
                (MetaType::Mailbox, &mut mailboxes),
                (MetaType::Calendar, &mut calendars),
                (MetaType::AddressBook, &mut address_books),
                (MetaType::FileNode, &mut folders),
            ] {
                let name = self.unique(ty);
                let response = self
                    .method(
                        caller,
                        Using::Plain,
                        &format!("{}/set", ty.name()),
                        json!({
                            "accountId": owner.id_string(),
                            "create": {"p": {"name": name}}
                        }),
                    )
                    .await;
                ids.push(
                    response
                        .pointer("/methodResponses/0/1/created/p/id")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("Parent {} not created: {response:?}", ty.name()))
                        .to_string(),
                );
            }
        }
        let pair = |ids: Vec<String>| -> [String; 2] { ids.try_into().expect("two parents") };
        Parents {
            mailboxes: pair(mailboxes),
            calendars: pair(calendars),
            address_books: pair(address_books),
            folders: pair(folders),
        }
    }

    pub async fn payload(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        parents: &Parents,
        slot: usize,
        extra: Value,
    ) -> Value {
        let name = self.unique(ty);
        let mut payload = match ty {
            MetaType::Email => json!({
                "mailboxIds": {parents.mailboxes[slot].as_str(): true},
                "subject": name,
                "from": [{"email": "metadata@example.com"}],
                "to": [{"email": owner.name()}],
                "bodyValues": {"1": {"value": "Metadata test message"}},
                "textBody": [{"partId": "1", "type": "text/plain"}]
            }),
            MetaType::Mailbox => json!({
                "name": name,
                "parentId": parents.mailboxes[slot]
            }),
            MetaType::SieveScript => json!({
                "name": name,
                "blobId": self.upload_script(caller, owner).await
            }),
            MetaType::Calendar | MetaType::AddressBook => json!({"name": name}),
            MetaType::CalendarEvent => json!({
                "calendarIds": {parents.calendars[slot].as_str(): true},
                "title": name,
                "start": "2024-03-01T10:00:00",
                "duration": "PT1H",
                "timeZone": "Europe/Ljubljana"
            }),
            MetaType::ContactCard => json!({
                "addressBookIds": {parents.address_books[slot].as_str(): true},
                "name": {"full": name}
            }),
            MetaType::FileNode => json!({
                "name": name,
                "parentId": parents.folders[slot]
            }),
        };
        if let (Some(payload), Value::Object(extra)) = (payload.as_object_mut(), extra) {
            payload.extend(extra);
        }
        payload
    }

    async fn upload_script(&self, caller: &Account, owner: &Account) -> String {
        let response = self
            .method(
                caller,
                Using::Plain,
                "Blob/upload",
                json!({
                    "accountId": owner.id_string(),
                    "create": {"s": {"data": [{"data:asText": "keep;"}]}}
                }),
            )
            .await;
        response
            .pointer("/methodResponses/0/1/created/s/id")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("Script blob not uploaded: {response:?}"))
            .to_string()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        parents: &Parents,
        slot: usize,
        extra: Value,
        using: Using,
    ) -> JmapResponse {
        let payload = self.payload(caller, owner, ty, parents, slot, extra).await;
        self.method(
            caller,
            using,
            &format!("{}/set", ty.name()),
            json!({
                "accountId": owner.id_string(),
                "create": {"i0": payload}
            }),
        )
        .await
    }

    pub async fn create_ok(
        &self,
        owner: &Account,
        ty: MetaType,
        parents: &Parents,
        slot: usize,
        extra: Value,
    ) -> String {
        self.create(owner, owner, ty, parents, slot, extra, Using::Metadata)
            .await
            .created(0)
            .id()
            .to_string()
    }

    pub async fn create_err(
        &self,
        owner: &Account,
        ty: MetaType,
        parents: &Parents,
        extra: Value,
    ) -> JmapSetError {
        self.create(owner, owner, ty, parents, 0, extra, Using::Metadata)
            .await
            .not_created(0)
            .to_set_error()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn get(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        ids: &[&str],
        properties: Option<&[&str]>,
        using: Using,
    ) -> JmapResponse {
        self.method(
            caller,
            using,
            &format!("{}/get", ty.name()),
            json!({
                "accountId": owner.id_string(),
                "ids": ids,
                "properties": properties
            }),
        )
        .await
    }

    pub async fn get_one(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        id: &str,
        properties: Option<&[&str]>,
        using: Using,
    ) -> Value {
        let response = self.get(caller, owner, ty, &[id], properties, using).await;
        response
            .pointer("/methodResponses/0/1/list/0")
            .cloned()
            .unwrap_or_else(|| panic!("{} {id} not returned: {response:?}", ty.name()))
    }

    pub async fn metadata(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        id: &str,
    ) -> (Value, Value) {
        let object = self
            .get_one(
                caller,
                owner,
                ty,
                id,
                Some(&["id", "metadata", "privateMetadata"]),
                Using::Metadata,
            )
            .await;
        (
            object.get("metadata").cloned().unwrap_or(Value::Null),
            object
                .get("privateMetadata")
                .cloned()
                .unwrap_or(Value::Null),
        )
    }

    pub async fn assert_metadata(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        id: &str,
        shared: Value,
        private: Value,
    ) {
        let (got_shared, got_private) = self.metadata(caller, owner, ty, id).await;
        if got_shared != shared || got_private != private {
            panic!(
                "{} {id} as {}: expected metadata {shared} and privateMetadata {private}, got {got_shared} and {got_private}",
                ty.name(),
                caller.name()
            );
        }
    }

    pub async fn state(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        using: Using,
    ) -> String {
        self.get(caller, owner, ty, &[], Some(&["id"]), using)
            .await
            .state()
            .to_string()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        id: &str,
        patch: Value,
        using: Using,
    ) -> JmapResponse {
        self.method(
            caller,
            using,
            &format!("{}/set", ty.name()),
            json!({
                "accountId": owner.id_string(),
                "update": {id: patch}
            }),
        )
        .await
    }

    pub async fn update_ok(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        id: &str,
        patch: Value,
    ) {
        let response = self
            .update(caller, owner, ty, id, patch, Using::Metadata)
            .await;
        if response
            .pointer(&format!("/methodResponses/0/1/updated/{id}"))
            .is_none()
        {
            panic!(
                "{} {id} not updated by {}: {response:?}",
                ty.name(),
                caller.name()
            );
        }
    }

    pub async fn update_err(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        id: &str,
        patch: Value,
    ) -> JmapSetError {
        self.update(caller, owner, ty, id, patch, Using::Metadata)
            .await
            .not_updated(id)
            .to_set_error()
    }

    pub async fn destroy(&self, owner: &Account, ty: MetaType, ids: &[&str]) {
        self.destroy_as(owner, owner, ty, ids).await;
    }

    pub async fn destroy_as(&self, caller: &Account, owner: &Account, ty: MetaType, ids: &[&str]) {
        let mut arguments = ty.destroy_arguments();
        if let Some(arguments) = arguments.as_object_mut() {
            arguments.insert("accountId".into(), owner.id_string().into());
            arguments.insert("destroy".into(), json!(ids));
        }
        let response = self
            .method(
                caller,
                Using::Plain,
                &format!("{}/set", ty.name()),
                arguments,
            )
            .await;
        let destroyed = response
            .pointer("/methodResponses/0/1/destroyed")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default();
        assert_eq!(
            destroyed,
            ids.len(),
            "{} destroy failed: {response:?}",
            ty.name()
        );
    }

    pub async fn changes(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        since: &str,
        arguments: Value,
        using: Using,
    ) -> JmapResponse {
        let mut request = Map::new();
        request.insert("accountId".into(), owner.id_string().into());
        request.insert("sinceState".into(), since.into());
        if let Value::Object(arguments) = arguments {
            request.extend(arguments);
        }
        self.method(
            caller,
            using,
            &format!("{}/changes", ty.name()),
            Value::Object(request),
        )
        .await
    }

    pub async fn query(
        &self,
        caller: &Account,
        owner: &Account,
        ty: MetaType,
        filter: Value,
        using: Using,
    ) -> JmapResponse {
        self.method(
            caller,
            using,
            &format!("{}/query", ty.name()),
            json!({
                "accountId": owner.id_string(),
                "filter": filter
            }),
        )
        .await
    }

    pub async fn share(
        &self,
        owner: &Account,
        ty: MetaType,
        target: &str,
        sharee: &Account,
        access: Option<Access>,
    ) {
        let container = ty.container();
        let rights = access.map_or(Value::Null, |access| ty.share_rights(access));
        let response = self
            .method(
                owner,
                Using::Plain,
                &format!("{}/set", container.name()),
                json!({
                    "accountId": owner.id_string(),
                    "update": {target: {format!("shareWith/{}", sharee.id_string()): rights}}
                }),
            )
            .await;
        if response
            .pointer(&format!("/methodResponses/0/1/updated/{target}"))
            .is_none()
        {
            panic!(
                "Sharing {} {target} with {} failed: {response:?}",
                container.name(),
                sharee.name()
            );
        }
    }

    pub async fn destroy_all(&self, account: &Account) {
        self.destroy_all_as(account, account).await;
    }

    pub async fn destroy_all_as(&self, caller: &Account, account: &Account) {
        self.test.wait_for_tasks().await;
        caller
            .destroy_all_mailboxes_for_account(account.id().document_id())
            .await;
        for ty in [
            MetaType::SieveScript,
            MetaType::FileNode,
            MetaType::AddressBook,
            MetaType::Calendar,
        ] {
            let mut arguments = ty.destroy_arguments();
            if let Some(arguments) = arguments.as_object_mut() {
                arguments.insert("accountId".into(), account.id_string().into());
                arguments.insert(
                    "#destroy".into(),
                    json!({"resultOf": "g", "name": format!("{}/get", ty.name()), "path": "/list/*/id"}),
                );
            }
            let get_arguments = if ty == MetaType::FileNode {
                json!({"accountId": account.id_string(), "ids": null, "properties": ["id", "parentId"]})
            } else {
                json!({"accountId": account.id_string(), "ids": null, "properties": ["id"]})
            };
            self.call(
                caller,
                Using::Plain,
                json!([
                    [format!("{}/get", ty.name()), get_arguments, "g"],
                    [format!("{}/set", ty.name()), arguments, "s"]
                ]),
            )
            .await;
        }
    }

    pub async fn purge(&self, accounts: &[&Account]) {
        let admin = self.test.account("admin");
        for account in accounts {
            admin
                .registry_create_object(Task::AccountMaintenance(TaskAccountMaintenance {
                    account_id: account.id(),
                    maintenance_type: TaskAccountMaintenanceType::Purge,
                    status: TaskStatus::now(),
                }))
                .await;
        }
        self.test.wait_for_tasks().await;
    }

    pub async fn cleanup(&self, accounts: &[&Account]) {
        self.test.wait_for_tasks().await;
        for account in accounts {
            self.destroy_all(account).await;
        }
        self.purge(accounts).await;
        self.test.assert_is_empty().await;
        self.test.server.invalidate_all_local_caches();
    }

    pub async fn used_quota(&self, account: &Account) -> i64 {
        self.test
            .server
            .get_used_quota_account(account.id().document_id())
            .await
            .expect("quota")
    }
}

pub fn response_ids(response: &JmapResponse) -> Vec<String> {
    let mut ids = response
        .pointer("/methodResponses/0/1/ids")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("Missing ids: {response:?}"))
        .iter()
        .filter_map(|id| id.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

pub fn sorted(ids: &[&str]) -> Vec<String> {
    let mut ids = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

pub fn method_error(response: &JmapResponse) -> Option<&str> {
    (response.name_at(0) == "error")
        .then(|| response.error_type_at(0))
        .flatten()
}

pub fn changes_list(response: &JmapResponse, kind: &str) -> Vec<String> {
    let mut ids = response
        .pointer(&format!("/methodResponses/0/1/{kind}"))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("Missing {kind}: {response:?}"))
        .iter()
        .filter_map(|id| id.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids
}

pub fn updated_properties(response: &JmapResponse) -> Option<Vec<String>> {
    let mut properties = response
        .pointer("/methodResponses/0/1/updatedProperties")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|property| property.as_str().map(str::to_string))
        .collect::<Vec<_>>();
    properties.sort_unstable();
    Some(properties)
}

pub fn depth_value(depth: usize) -> Value {
    (1..depth).fold(json!({"leaf": "value"}), |inner, _| json!({"level": inner}))
}

pub fn random_text(len: usize) -> String {
    let mut rng = rng();
    (0..len).map(|_| rng.sample(Alphanumeric) as char).collect()
}
