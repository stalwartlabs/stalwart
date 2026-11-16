/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    cache::{MessageCacheFetch, email::MessageCacheAccess, mailbox::MailboxCacheAccess},
    mailbox::{JUNK_ID, Mailbox, SENT_ID, lookup::MailboxLookup},
    message::messagedata::{EmailMessageData, MessageData},
};
use common::Server;
use store::{
    Deserialize, IterateParams, U32_LEN, ValueKey,
    dispatch::DocumentSet,
    write::{Archive, ArchiveBytes, ValueClass, key::DeserializeBigEndian},
};
use tinyvec::TinyVec;
use trc::AddContext;
use types::{collection::Collection, field::Field, keyword::DRAFT, special_use::SpecialUse};

const DRAFT_BIT: u32 = 1 << DRAFT;

pub(super) async fn has_duplicate_in(
    server: &Server,
    account_id: u32,
    duplicate_ids: &[u32],
    mailbox_id: u32,
) -> trc::Result<bool> {
    let is_target = |target: u32| target == mailbox_id || target == JUNK_ID;
    if let Some(cache) = server.fresh_messages(account_id) {
        return Ok(duplicate_ids.iter().any(|document_id| {
            cache.email_by_id(document_id).is_some_and(|message| {
                message.keywords() & DRAFT_BIT == 0
                    && message
                        .mailboxes()
                        .iter()
                        .any(|mailbox| is_target(mailbox.mailbox_id))
            })
        }));
    }

    let documents = sorted_ids(duplicate_ids);
    let mut found = false;
    server
        .message_datas(account_id, &documents, |_, data| {
            found |= data.keywords & DRAFT_BIT == 0
                && data
                    .mailboxes
                    .iter()
                    .any(|mailbox| is_target(mailbox.mailbox_id));
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;
    Ok(found)
}

pub(super) async fn is_trusted_reply(
    server: &Server,
    account_id: u32,
    thread_id: u32,
    matched_ids: &[u32],
) -> trc::Result<bool> {
    if let Some(cache) = server.fresh_messages(account_id) {
        let sent_id = cache
            .mailbox_by_role(&SpecialUse::Sent)
            .map_or(SENT_ID, |mailbox| mailbox.document_id);
        return Ok(cache.in_thread(thread_id).any(|message| {
            message
                .mailboxes()
                .iter()
                .any(|mailbox| mailbox.mailbox_id == sent_id)
        }));
    }

    let documents = sorted_ids(matched_ids);
    if documents.is_empty() {
        return Ok(false);
    }

    let store = server.store();
    let email_key = |document_id| ValueKey {
        account_id,
        collection: Collection::Email.into(),
        document_id,
        class: ValueClass::Property(Field::ARCHIVE.into()),
    };
    let sent_key = ValueKey::archive(account_id, Collection::Mailbox, SENT_ID);
    let mut ranges = documents
        .scan_ranges(store.scan_gap())
        .into_iter()
        .map(|(from, to)| IterateParams::new(email_key(from), email_key(to)))
        .collect::<Vec<_>>();
    ranges.push(IterateParams::new(sent_key.clone(), sent_key));

    let mailbox_collection: u8 = Collection::Mailbox.into();
    let mut mailbox_ids: TinyVec<[u32; 4]> = TinyVec::new();
    let mut sent_has_role = false;
    store
        .iterate_many(ranges, |key, value| {
            let document_id = key.deserialize_be_u32(key.len() - U32_LEN)?;
            let collection = key
                .len()
                .checked_sub(U32_LEN + 2)
                .and_then(|offset| key.get(offset).copied());
            if collection == Some(mailbox_collection) {
                let archive = <Archive<ArchiveBytes> as Deserialize>::deserialize(value)?;
                sent_has_role = archive.unarchive::<Mailbox>()?.role() == SpecialUse::Sent;
            } else if documents.contains(document_id) {
                for mailbox in MessageData::deserialize(value)?.mailboxes {
                    if !mailbox_ids.contains(&mailbox.mailbox_id) {
                        mailbox_ids.push(mailbox.mailbox_id);
                    }
                }
            }
            Ok(true)
        })
        .await
        .caused_by(trc::location!())?;

    if mailbox_ids.is_empty() {
        Ok(false)
    } else if sent_has_role {
        Ok(mailbox_ids.contains(&SENT_ID))
    } else {
        let sent_id = server
            .mailbox_id_by_role(account_id, SpecialUse::Sent)
            .await
            .caused_by(trc::location!())?
            .unwrap_or(SENT_ID);
        Ok(mailbox_ids.contains(&sent_id))
    }
}

fn sorted_ids(ids: &[u32]) -> Vec<u32> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}
