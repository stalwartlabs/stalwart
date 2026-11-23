/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    access::{DelegateRights, ItemWrite, ViewRights},
    execute::{RopContext, RopError, RopResult},
    staged::value_size,
    state::{MessageObject, ServerObject, mail_container},
};
use crate::{
    eas::folder_sync::MAX_STATE_ATTEMPTS,
    folders::FolderNode,
    mail::{CommitOutcome, FlagEdit, FlagOutcome, MailEdits, SEEN_BIT},
    mapi::ids::{IdSpace, MapiId},
    receipt::{
        Receipt, ReceiptAction, ReceiptMode, ReceiptRequests, ReceiptSender, may_send_receipts,
        receipt_pending, sent_manually,
    },
    store::{FolderKind, FolderRef},
};
use common::{
    MessageStoreCache, Server, cache::exchange::ExchangeAccountCache,
    config::mailstore::limits::EmailLimits,
};
use email::{
    cache::{MessageCacheFetch, email::MessageCacheAccess},
    message::messagedata::MessageData,
};
use exchange_proto::{
    convert::tags::message_flags,
    mapi::{
        ErrorCode,
        prop::{OwnedPropValue, PropKey, PropType, tags},
        rop::{
            DecodedRop,
            requests::{SetMessageReadFlag, SetReadFlags},
            responses::{SetMessageReadFlagResponse, SetReadFlagsResponse},
        },
    },
};
use smallvec::SmallVec;
use std::sync::Arc;
use types::type_state::DataType;

#[derive(Clone, Copy)]
pub(super) enum ReadTargets<'a> {
    Listed {
        container: Option<u32>,
        ids: &'a [u32],
    },
    Folder(u32),
}

pub(super) struct ReadMarked {
    pub(super) failed: Option<ErrorCode>,
    pub(super) committed: Option<(u64, Arc<MessageStoreCache>)>,
}

#[derive(Clone, Copy)]
pub(super) struct ReadChange {
    read: Option<bool>,
    receipt: ReceiptAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadScope {
    PerMessage,
    Bulk,
}

struct ReadPass<'a> {
    limits: &'a EmailLimits,
    account_id: u32,
    change: ReadChange,
    requests: &'a mut ReceiptRequests,
    edits: MailEdits,
    failed: Option<ErrorCode>,
    receipts: SmallVec<[(u32, ReceiptMode); 4]>,
}

const SUPPRESS_RECEIPT: u8 = 0x01;
const CLEAR_READ_FLAG: u8 = 0x04;
const GENERATE_RECEIPT_ONLY: u8 = 0x10;
const CLEAR_NOTIFY_READ: u8 = 0x20;
const CLEAR_NOTIFY_UNREAD: u8 = 0x40;

impl ReadScope {
    fn per_message(self, action: ReceiptAction) -> ReceiptAction {
        match self {
            ReadScope::PerMessage => action,
            ReadScope::Bulk => ReceiptAction::Keep,
        }
    }
}

impl ReadChange {
    fn from_flags(read_flags: u8, scope: ReadScope) -> Self {
        let (read, receipt) = if read_flags & GENERATE_RECEIPT_ONLY != 0 {
            (None, scope.per_message(ReceiptAction::Send))
        } else if read_flags & CLEAR_NOTIFY_READ != 0 {
            (None, ReceiptAction::Clear)
        } else if read_flags & CLEAR_NOTIFY_UNREAD != 0 {
            (None, ReceiptAction::Keep)
        } else if read_flags & CLEAR_READ_FLAG != 0 {
            (Some(false), ReceiptAction::Keep)
        } else if read_flags & SUPPRESS_RECEIPT != 0 {
            (Some(true), scope.per_message(ReceiptAction::Clear))
        } else {
            (Some(true), scope.per_message(ReceiptAction::Send))
        };
        ReadChange { read, receipt }
    }

    pub(super) fn imported(read: bool, scope: ReadScope) -> Self {
        ReadChange {
            read: Some(read),
            receipt: if read {
                scope.per_message(ReceiptAction::Send)
            } else {
                ReceiptAction::Keep
            },
        }
    }

    fn without_receipts(self) -> Self {
        ReadChange {
            receipt: ReceiptAction::Keep,
            ..self
        }
    }

    fn is_noop(self) -> bool {
        self.read.is_none() && self.receipt == ReceiptAction::Keep
    }

    fn selects(self, keywords: u32) -> bool {
        self.read
            .is_some_and(|read| (keywords & SEEN_BIT != 0) != read)
            || (self.receipt != ReceiptAction::Keep && receipt_pending(keywords))
    }
}

impl ReadPass<'_> {
    async fn queue(
        &mut self,
        server: &Server,
        exchange: &ExchangeAccountCache,
        document_id: u32,
        data: Option<&MessageData>,
    ) -> trc::Result<()> {
        let action = self.change.receipt;
        let receipt = match data {
            Some(data) if action != ReceiptAction::Keep && receipt_pending(data.keywords) => {
                let request = self
                    .requests
                    .resolve(server, self.account_id, document_id)
                    .await;
                let manual = action.reads_disposition_mode(request)
                    && sent_manually(server, exchange, self.account_id, document_id).await;
                action.receipt(request, manual)
            }
            _ => Receipt::Skip,
        };
        self.apply(document_id, data, receipt)
    }

    fn apply(
        &mut self,
        document_id: u32,
        data: Option<&MessageData>,
        receipt: Receipt,
    ) -> trc::Result<()> {
        let Some(data) = data else {
            self.failed = Some(ErrorCode::OBJECT_DELETED);
            return Ok(());
        };
        let mut edit = FlagEdit {
            read: self.change.read,
            mdn_sent: receipt.mdn_sent().then_some(true),
            ..Default::default()
        };
        let mut outcome = self.edits.set_flags(self.limits, document_id, data, edit)?;
        if outcome == FlagOutcome::KeywordLimit && edit.mdn_sent.is_some() {
            edit.mdn_sent = None;
            outcome = self.edits.set_flags(self.limits, document_id, data, edit)?;
        }
        match (outcome, receipt) {
            (FlagOutcome::KeywordLimit, _) => self.failed = Some(ErrorCode::ERROR),
            (FlagOutcome::Changed, Receipt::Send(mode)) if edit.mdn_sent.is_some() => {
                self.receipts.push((document_id, mode))
            }
            (FlagOutcome::Changed | FlagOutcome::Unchanged, _) => {}
        }
        Ok(())
    }
}

fn may_mark(rights: Option<&DelegateRights>, mut mailboxes: impl Iterator<Item = u32>) -> bool {
    let Some(rights) = rights else {
        return true;
    };
    mailboxes.all(|id| {
        let node = FolderNode::Stored(FolderRef {
            kind: FolderKind::Mailbox,
            id,
        });
        rights.of(node).contains(ItemWrite::ReadState.needs(node))
    })
}

impl RopContext<'_, '_> {
    pub async fn set_read_flags(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetReadFlags<'_>,
    ) -> RopResult {
        let handle = self.input(rop.header.input_handle)?;
        let (mailbox_id, folder, container) = match self.state.get(handle) {
            Some(ServerObject::Folder(folder)) => (
                folder.mailbox_id,
                folder.counter,
                match folder.id().and_then(MapiId::to_node) {
                    Some(FolderNode::Stored(FolderRef {
                        kind: FolderKind::Mailbox,
                        id,
                    })) => Some(id),
                    _ => None,
                },
            ),
            Some(_) => return Err(RopError::Code(ErrorCode::NOT_SUPPORTED)),
            None => return Err(RopError::Code(ErrorCode::NULL_OBJECT)),
        };
        let mut ids: SmallVec<[u32; 16]> = SmallVec::new();
        let mut partial = false;
        let view = self.mailbox(mailbox_id).await?;
        for eid in request.message_ids.iter() {
            match MapiId::from_eid(eid).filter(|id| id.space == IdSpace::Email) {
                Some(id) => ids.push(view.stored_id(container, id).id),
                None => partial = true,
            }
        }
        ids.sort_unstable();
        ids.dedup();
        let (targets, scope) = match container {
            Some(container) if request.message_ids.is_empty() => {
                (Some(ReadTargets::Folder(container)), ReadScope::Bulk)
            }
            Some(container) => (
                Some(ReadTargets::Listed {
                    container: Some(container),
                    ids: &ids,
                }),
                ReadScope::PerMessage,
            ),
            None => (None, ReadScope::PerMessage),
        };
        let change = ReadChange::from_flags(request.read_flags, scope);
        match targets {
            _ if change.is_noop() => {}
            Some(targets) => {
                partial |= self
                    .mark_read(mailbox_id, folder, targets, change)
                    .await?
                    .failed
                    .is_some();
            }
            None => partial |= !ids.is_empty(),
        }
        self.respond(
            rop,
            index,
            &SetReadFlagsResponse {
                partial_completion: partial,
            },
        )
    }

    pub async fn set_message_read_flag(
        &mut self,
        rop: &DecodedRop<'_>,
        index: u8,
        request: &SetMessageReadFlag,
    ) -> RopResult {
        let handle = self.input(request.input_handle_index)?;
        let message = self.message_object(handle)?;
        let Some(id) = message
            .id()
            .filter(|id| id.space == IdSpace::Email && message.path.is_empty())
        else {
            if message.staged.is_none() || (message.id().is_some() && message.path.is_empty()) {
                return Err(RopError::Code(ErrorCode::NOT_SUPPORTED));
            }
            if let Some(read) =
                ReadChange::from_flags(request.read_flags, ReadScope::PerMessage).read
            {
                self.stage_read_flag(&message, read)?;
            }
            return self.respond(rop, index, &SetMessageReadFlagResponse { changed: None });
        };
        let id = self
            .mailbox(message.mailbox_id)
            .await?
            .stored_item(message.folder, id)
            .filter(|id| id.space == IdSpace::Email)
            .ok_or(ErrorCode::NOT_SUPPORTED)?;
        let container = mail_container(message.folder)
            .filter(|_| !self.request.access_token.is_account_id(message.mailbox_id));
        let change = ReadChange::from_flags(request.read_flags, ReadScope::PerMessage);
        if !change.is_noop()
            && let Some(code) = self
                .mark_read(
                    message.mailbox_id,
                    message.folder,
                    ReadTargets::Listed {
                        container,
                        ids: &[id.id],
                    },
                    change,
                )
                .await?
                .failed
        {
            return Err(RopError::Code(code));
        }
        self.respond(rop, index, &SetMessageReadFlagResponse { changed: None })
    }

    fn stage_read_flag(&mut self, message: &MessageObject, read: bool) -> Result<(), RopError> {
        let id = message.staged.ok_or(ErrorCode::NULL_OBJECT)?;
        let key = PropKey::tag(tags::MESSAGE_FLAGS.id());
        let current = match self
            .staged_message(message)?
            .content_at(&message.path)?
            .props
            .get(key.as_ref(), PropType::I32)
        {
            Some(OwnedPropValue::I32(flags)) => Some(*flags),
            _ => None,
        };
        let flags = current.unwrap_or_default();
        let value = OwnedPropValue::I32(if read {
            flags | message_flags::READ
        } else {
            flags & !message_flags::READ
        });
        if current.is_none() {
            self.staged().recharge(id, value_size(&value), 0)?;
        }
        self.staged_message(message)?
            .edit_key_at(&message.path, key.as_ref())?
            .props
            .set(key, value);
        Ok(())
    }

    pub(super) async fn mark_read(
        &mut self,
        mailbox_id: u32,
        folder: u64,
        targets: ReadTargets<'_>,
        change: ReadChange,
    ) -> Result<ReadMarked, RopError> {
        self.require_write(mailbox_id, folder, ItemWrite::ReadState)
            .await?;
        let access_token = self.request.access_token;
        if !self.types.contains(DataType::Email) {
            return Ok(ReadMarked {
                failed: matches!(targets, ReadTargets::Listed { ids, .. } if !ids.is_empty())
                    .then_some(ErrorCode::OBJECT_DELETED),
                committed: None,
            });
        }
        let change = if may_send_receipts(access_token, mailbox_id) {
            change
        } else {
            change.without_receipts()
        };
        let delegate = if access_token.is_account_id(mailbox_id) {
            None
        } else {
            match self.view_rights(mailbox_id).await? {
                ViewRights::Delegate(rights) => Some(rights),
                ViewRights::Owner | ViewRights::Member | ViewRights::Revoked => None,
            }
        };
        let server = self.request.server;
        let session_id = u64::try_from(self.session & u128::from(u64::MAX)).unwrap_or_default();
        let mut cache = server.get_cached_messages(mailbox_id).await?;
        let mut requests = ReceiptRequests::default();
        let exchange = self.mailbox(mailbox_id).await?.exchange;
        for _ in 0..MAX_STATE_ATTEMPTS {
            let mut pass = ReadPass {
                limits: &server.core.email.limits,
                account_id: mailbox_id,
                change,
                requests: &mut requests,
                edits: MailEdits::new(mailbox_id),
                failed: None,
                receipts: SmallVec::new(),
            };
            match targets {
                ReadTargets::Listed { container, ids } => {
                    for document_id in ids {
                        let item = cache.email_by_id(document_id);
                        let in_container = container.is_none_or(|container| {
                            item.is_some_and(|item| item.has_mailbox_id(container))
                        });
                        if in_container
                            && let Some(item) = item
                            && !may_mark(
                                delegate.as_deref(),
                                item.mailboxes().iter().map(|uid| uid.mailbox_id),
                            )
                        {
                            pass.failed = Some(ErrorCode::ACCESS_DENIED);
                            continue;
                        }
                        let data = cache.message_data(*document_id).filter(|_| in_container);
                        pass.queue(server, &exchange, *document_id, data.as_ref())
                            .await?;
                    }
                }
                ReadTargets::Folder(container) => {
                    for item in cache
                        .in_mailbox(container)
                        .filter(|item| change.selects(item.keywords()))
                    {
                        if !may_mark(
                            delegate.as_deref(),
                            item.mailboxes().iter().map(|uid| uid.mailbox_id),
                        ) {
                            pass.failed = Some(ErrorCode::ACCESS_DENIED);
                            continue;
                        }
                        let document_id = item.document_id();
                        pass.queue(
                            server,
                            &exchange,
                            document_id,
                            cache.message_data(document_id).as_ref(),
                        )
                        .await?;
                    }
                }
            }
            let ReadPass {
                edits,
                failed,
                receipts,
                ..
            } = pass;
            match edits.commit(server, access_token, session_id).await? {
                CommitOutcome::Committed(change_id) => {
                    self.invalidate_mailbox();
                    if !receipts.is_empty() {
                        match self.cached_account_info(mailbox_id).await.cloned() {
                            Ok(account) => {
                                if let Some(mut sender) = ReceiptSender::new(
                                    server,
                                    self.request.instance,
                                    mailbox_id,
                                    account,
                                    session_id,
                                ) {
                                    for (document_id, mode) in receipts {
                                        if let Some(request) = requests.take(document_id) {
                                            sender.send(document_id, mode, request).await;
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                trc::error!(err.caused_by(trc::location!()));
                            }
                        }
                    }
                    return Ok(ReadMarked {
                        failed,
                        committed: change_id.map(|change_id| (change_id, cache)),
                    });
                }
                CommitOutcome::Conflict => {
                    cache = server.get_cached_messages(mailbox_id).await?;
                }
            }
        }
        Err(RopError::Code(ErrorCode::ERROR))
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/exchange/src/mapi/emsmdb/read_flags/tests.rs"]
mod tests;
