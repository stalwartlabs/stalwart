/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    eas::convert::flag::decode,
    mail::{MDN_SENT_BIT, SEEN_BIT, metadata_row},
    store::object::{ArchivedExchangeObject, ExchangeObject, ExchangeObjectStore},
};
use ahash::AHashMap;
use common::{
    Server,
    auth::{AccessToken, AccountInfo, oauth::scope::data_type_scopes},
    cache::exchange::ExchangeAccountCache,
    network::ServerInstance,
};
use email::message::mdn::{MdnMessage, MdnRequest, MdnStatus};
use exchange_proto::mapi::prop::{PropValue, tags};
use jmap_proto::object::mdn::{ActionMode, Disposition, DispositionType, Mdn, SendingMode};
use registry::schema::enums::Permission;
use smtp::{
    queue::spool::QueueOutcome,
    reporting::mdn::{MdnOutcome, MdnSender},
};
use std::{collections::hash_map::Entry, sync::Arc};
use trc::AddContext;
use types::{collection::Collection, type_state::DataType};

const DISPLAYED: Disposition = Disposition {
    action_mode: ActionMode::Manual,
    sending_mode: SendingMode::Automatic,
    disposition_type: DispositionType::Displayed,
};
const DISPLAYED_MANUALLY: Disposition = Disposition {
    action_mode: ActionMode::Manual,
    sending_mode: SendingMode::Manual,
    disposition_type: DispositionType::Displayed,
};
const SENT_MANUALLY: &str = "manual-action/MDN-sent-manually";
const REPORT_DISPOSITION_MODE_KEY: [u8; 3] = tags::REPORT_DISPOSITION_MODE.id().canonical_key();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptAction {
    Keep,
    Send,
    Clear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptMode {
    Automatic,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    Skip,
    Cancel,
    Send(ReceiptMode),
}

#[derive(Default)]
pub struct ReceiptRequests(AHashMap<u32, Option<MdnRequest>>);

pub struct ReceiptSender {
    sender: MdnSender,
    account_id: u32,
    from: String,
    name: Option<Box<str>>,
}

pub fn may_send_receipts(access_token: &AccessToken, account_id: u32) -> bool {
    access_token.is_account_id(account_id)
        && access_token.has_permission(Permission::EmailSend)
        && access_token.allows_oauth_scopes(data_type_scopes(DataType::EmailSubmission))
}

pub fn receipt_pending(keywords: u32) -> bool {
    keywords & (SEEN_BIT | MDN_SENT_BIT) == 0
}

impl ReceiptAction {
    pub fn reads_disposition_mode(self, request: Option<&MdnRequest>) -> bool {
        self == ReceiptAction::Send && request.is_some()
    }

    pub fn receipt(self, request: Option<&MdnRequest>, sent_manually: bool) -> Receipt {
        match (self, request) {
            (ReceiptAction::Keep, _) | (_, None) => Receipt::Skip,
            (ReceiptAction::Clear, Some(_)) => Receipt::Cancel,
            (ReceiptAction::Send, Some(_)) if sent_manually => Receipt::Send(ReceiptMode::Manual),
            (ReceiptAction::Send, Some(request)) if request.allows_automatic() => {
                Receipt::Send(ReceiptMode::Automatic)
            }
            (ReceiptAction::Send, Some(_)) => Receipt::Skip,
        }
    }
}

impl Receipt {
    pub fn mdn_sent(self) -> bool {
        self != Receipt::Skip
    }
}

impl ReceiptMode {
    fn disposition(self) -> Disposition {
        match self {
            ReceiptMode::Automatic => DISPLAYED,
            ReceiptMode::Manual => DISPLAYED_MANUALLY,
        }
    }
}

pub async fn sent_manually(
    server: &Server,
    exchange: &ExchangeAccountCache,
    account_id: u32,
    document_id: u32,
) -> bool {
    if !exchange.has_object(Collection::Email, document_id) {
        return false;
    }
    read_sent_manually(server, account_id, document_id)
        .await
        .unwrap_or_else(|err| {
            read_failed(err, account_id, document_id);
            false
        })
}

async fn read_sent_manually(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<bool> {
    let Some(archive) = server
        .exchange_object(account_id, Collection::Email, document_id)
        .await?
    else {
        return Ok(false);
    };
    Ok(row_sent_manually(
        archive
            .unarchive::<ExchangeObject>()
            .caused_by(trc::location!())?,
    ))
}

#[cold]
fn read_failed(err: trc::Error, account_id: u32, document_id: u32) {
    trc::error!(
        err.account_id(account_id)
            .document_id(document_id)
            .caused_by(trc::location!())
    );
}

fn row_sent_manually(row: &ArchivedExchangeObject) -> bool {
    matches!(
        row.property(&REPORT_DISPOSITION_MODE_KEY).and_then(decode),
        Some(PropValue::Unicode(mode)) if mode.eq_ignore_ascii_case(SENT_MANUALLY)
    )
}

impl ReceiptRequests {
    pub async fn resolve(
        &mut self,
        server: &Server,
        account_id: u32,
        document_id: u32,
    ) -> Option<&MdnRequest> {
        match self.0.entry(document_id) {
            Entry::Occupied(entry) => entry.into_mut().as_ref(),
            Entry::Vacant(entry) => entry
                .insert(
                    mdn_request(server, account_id, document_id)
                        .await
                        .unwrap_or_else(|err| {
                            read_failed(err, account_id, document_id);
                            None
                        }),
                )
                .as_ref(),
        }
    }

    pub fn take(&mut self, document_id: u32) -> Option<MdnRequest> {
        self.0.remove(&document_id).flatten()
    }
}

async fn mdn_request(
    server: &Server,
    account_id: u32,
    document_id: u32,
) -> trc::Result<Option<MdnRequest>> {
    let Some(row) = metadata_row(server, account_id, document_id).await? else {
        return Ok(None);
    };
    let metadata = row.unarchive().caused_by(trc::location!())?;
    let raw_headers = row.raw_headers().caused_by(trc::location!())?;
    Ok(match MdnStatus::new(metadata, &raw_headers) {
        MdnStatus::Requested(request) => Some(request),
        MdnStatus::NotRequested | MdnStatus::Report => None,
    })
}

impl ReceiptSender {
    pub fn new(
        server: &Server,
        instance: &Arc<ServerInstance>,
        account_id: u32,
        account: AccountInfo,
        session_id: u64,
    ) -> Option<Self> {
        let Some(from) = account.addresses.first().cloned() else {
            trc::event!(
                OutgoingReport(trc::OutgoingReportEvent::SubmissionError),
                AccountId = account_id,
                Details = "Read receipt not sent: the account has no address",
            );
            return None;
        };
        let name = account.account.description.clone();
        Some(ReceiptSender {
            sender: MdnSender::new(server.clone(), instance.clone(), account, &from, session_id),
            account_id,
            from,
            name,
        })
    }

    pub async fn send(&mut self, document_id: u32, mode: ReceiptMode, mut request: MdnRequest) {
        let disposition = mode.disposition();
        let mut mdn = Mdn {
            disposition: Some(disposition),
            ..Default::default()
        };
        request.apply_defaults(&mut mdn, disposition, &self.from);
        let Some(raw) = (MdnMessage {
            mdn: &mdn,
            disposition,
            from_name: self.name.as_deref().filter(|name| !name.is_empty()),
            from_address: &self.from,
            to: &request.notify,
            original_message: None,
        })
        .build() else {
            self.not_sent(document_id, "the report could not be built");
            return;
        };
        match self.sender.send(&self.from, &request.notify, &raw).await {
            MdnOutcome::Queue(QueueOutcome::Queued) => {}
            MdnOutcome::RateLimited => self.not_sent(document_id, "rate limited"),
            MdnOutcome::Queue(QueueOutcome::QuotaExceeded) => {
                self.not_sent(document_id, "sending quota exceeded")
            }
            MdnOutcome::Queue(QueueOutcome::Failed) => {
                self.not_sent(document_id, "the message could not be queued")
            }
        }
    }

    #[cold]
    fn not_sent(&self, document_id: u32, reason: &'static str) {
        trc::event!(
            OutgoingReport(trc::OutgoingReportEvent::SubmissionError),
            AccountId = self.account_id,
            DocumentId = document_id,
            Details = "Read receipt not sent",
            Reason = reason,
        );
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/exchange/src/receipt/tests.rs"]
mod tests;
