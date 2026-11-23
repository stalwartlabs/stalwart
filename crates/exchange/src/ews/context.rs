/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::folders::{ExchangeFolders, FolderTree, access::ViewRights};
use common::{Server, auth::AccessToken};
use exchange_proto::ews::{
    ServerVersionInfo,
    envelope::{EnvelopeWriter, XmlDecl},
    header::SoapHeader,
    schema::DateTimePrecision,
};
use http_proto::HttpSessionData;
use std::sync::{Arc, Mutex};
use types::type_state::DataType;
use utils::map::bitmap::Bitmap;

#[derive(Clone)]
pub(crate) struct EwsAccount {
    pub account_id: u32,
    pub data_types: Bitmap<DataType>,
}

#[derive(Clone, Copy)]
pub(crate) struct EwsCaller<'a> {
    pub access_token: &'a AccessToken,
    pub session: &'a HttpSessionData,
}

#[derive(Clone)]
pub(crate) struct EwsContext {
    pub version: ServerVersionInfo,
    pub precision: DateTimePrecision,
    pub account: EwsAccount,
    pub caller: AccessToken,
    pub access: ViewRights,
    pub(super) visible: Option<Arc<FolderTree>>,
    pub(super) mailbox: Option<ResolvedMailbox>,
    pub(super) owner_tree: TreeMemo,
}

#[derive(Default)]
pub(crate) struct TreeMemo(Mutex<Option<Arc<FolderTree>>>);

#[derive(Clone)]
pub(crate) struct ResolvedMailbox {
    pub address: Box<str>,
    pub account_id: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MailboxOwner {
    Target,
    Other,
    Unknown,
}

impl EwsAccount {
    pub fn new(access_token: &AccessToken) -> Self {
        let mut data_types = Bitmap::all();
        access_token.restrict_data_types(&mut data_types);
        EwsAccount {
            account_id: access_token.account_id(),
            data_types,
        }
    }
}

impl EwsContext {
    pub fn new(
        version: ServerVersionInfo,
        header: &SoapHeader<'_>,
        access_token: &AccessToken,
    ) -> Self {
        EwsContext {
            version,
            account: EwsAccount::new(access_token),
            caller: access_token.clone(),
            access: ViewRights::Owner,
            visible: None,
            mailbox: None,
            owner_tree: TreeMemo::default(),
            precision: header
                .date_time_precision
                .unwrap_or(DateTimePrecision::Seconds),
        }
    }

    pub fn targets_caller(&self) -> bool {
        self.account.account_id == self.caller.account_id()
    }

    pub async fn folder_tree(&self, server: &Server) -> trc::Result<Arc<FolderTree>> {
        if let Some(tree) = &self.visible {
            return Ok(tree.clone());
        }
        if let Some(tree) = self.owner_tree.get() {
            return Ok(tree);
        }
        let tree = Arc::new(
            server
                .exchange_folder_tree(self.account.account_id, self.account.data_types)
                .await?,
        );
        self.owner_tree.set(tree.clone());
        Ok(tree)
    }

    pub fn folders_changed(&self) {
        self.owner_tree.clear();
    }

    pub async fn account_of(&self, server: &Server, address: &str) -> trc::Result<Option<u32>> {
        match &self.mailbox {
            Some(resolved) if resolved.address.eq_ignore_ascii_case(address) => {
                Ok(resolved.account_id)
            }
            _ => server.account_id_from_email(address, false).await,
        }
    }

    pub async fn mailbox_owner(&self, server: &Server, address: &str) -> trc::Result<MailboxOwner> {
        match self.account_of(server, address).await? {
            Some(account_id) if account_id == self.account.account_id => Ok(MailboxOwner::Target),
            Some(account_id) => Ok(match server.try_account(account_id).await? {
                Some(account) if account.is_same_tenant(&self.caller) => MailboxOwner::Other,
                _ => MailboxOwner::Unknown,
            }),
            None => Ok(MailboxOwner::Unknown),
        }
    }

    pub fn envelope<'o>(&self, out: &'o mut Vec<u8>) -> EnvelopeWriter<'o> {
        self.with_precision(EnvelopeWriter::begin(out, &self.version, XmlDecl::Emit))
    }

    pub fn stream_envelope<'o>(&self, out: &'o mut Vec<u8>, decl: XmlDecl) -> EnvelopeWriter<'o> {
        self.with_precision(EnvelopeWriter::begin_stream(out, &self.version, decl))
    }

    fn with_precision<'o>(&self, mut envelope: EnvelopeWriter<'o>) -> EnvelopeWriter<'o> {
        envelope.set_millis(self.precision == DateTimePrecision::Milliseconds);
        envelope
    }
}

impl TreeMemo {
    pub(super) fn get(&self) -> Option<Arc<FolderTree>> {
        self.0.lock().ok().and_then(|tree| tree.clone())
    }

    pub(super) fn set(&self, tree: Arc<FolderTree>) {
        if let Ok(mut memo) = self.0.lock() {
            *memo = Some(tree);
        }
    }

    fn clear(&self) {
        if let Ok(mut memo) = self.0.lock() {
            *memo = None;
        }
    }
}

impl Clone for TreeMemo {
    fn clone(&self) -> Self {
        TreeMemo::default()
    }
}
