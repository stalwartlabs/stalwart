/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use imap_proto::{
    Command,
    protocol::ProtocolVersion,
    receiver::{Error, Receiver, Request},
};
use libfuzzer_sys::fuzz_target;

fn dispatch(request: Request<Command>) {
    let is_utf8 = request.tag.len() % 3 == 0;
    let version = if request.tag.len() % 2 == 0 {
        ProtocolVersion::Rev2
    } else {
        ProtocolVersion::Rev1
    };
    let _ = match request.command {
        Command::Authenticate => request.parse_authenticate().map(|_| ()),
        Command::Login => request.parse_login().map(|_| ()),
        Command::Enable => request.parse_enable().map(|_| ()),
        Command::Select | Command::Examine => request.parse_select(is_utf8).map(|_| ()),
        Command::Create => request.parse_create(is_utf8).map(|_| ()),
        Command::Delete => request.parse_delete(is_utf8).map(|_| ()),
        Command::Rename => request.parse_rename(is_utf8).map(|_| ()),
        Command::Subscribe | Command::Unsubscribe => request.parse_subscribe(is_utf8).map(|_| ()),
        Command::List => request.parse_list(is_utf8).map(|_| ()),
        Command::Lsub => request.parse_lsub(is_utf8).map(|_| ()),
        Command::Status => request.parse_status(is_utf8).map(|_| ()),
        Command::Append => request.parse_append(is_utf8).map(|_| ()),
        Command::Search(_) => request.parse_search(version).map(|_| ()),
        Command::Fetch(_) => request.parse_fetch().map(|_| ()),
        Command::Store(_) => request.parse_store().map(|_| ()),
        Command::Copy(_) | Command::Move(_) => request.parse_copy_move(is_utf8).map(|_| ()),
        Command::Sort(_) => request.parse_sort().map(|_| ()),
        Command::Thread(_) => request.parse_thread().map(|_| ()),
        Command::SetAcl
        | Command::DeleteAcl
        | Command::GetAcl
        | Command::ListRights
        | Command::MyRights => request.parse_acl(is_utf8).map(|_| ()),
        Command::GetQuota => request.parse_get_quota().map(|_| ()),
        Command::GetQuotaRoot => request.parse_get_quota_root(is_utf8).map(|_| ()),
        Command::UidBatches => request.parse_uidbatches().map(|_| ()),
        Command::Expunge(true) => {
            if let Some(token) = request.tokens.into_iter().next() {
                let _ = imap_proto::parser::parse_sequence_set(&token.unwrap_bytes());
            }
            Ok(())
        }
        _ => Ok(()),
    };
}

fuzz_target!(|data: &[u8]| {
    let [limit, chunk, stream @ ..] = data else {
        return;
    };
    let mut receiver = if limit & 1 == 0 {
        Receiver::<Command>::new()
    } else {
        Receiver::<Command>::with_max_request_size(16 + usize::from(*limit) * 4)
    };
    let chunk = match chunk % 8 {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 7,
        4 => 16,
        5 => 64,
        6 => 200,
        _ => usize::MAX,
    };
    for piece in stream.chunks(chunk.min(stream.len().max(1))) {
        let mut bytes = piece.iter();
        loop {
            let remaining = bytes.len();
            match receiver.parse(&mut bytes) {
                Ok(request) => dispatch(request),
                Err(Error::NeedsMoreData) => break,
                Err(Error::NeedsLiteral { .. }) | Err(Error::Error { .. }) => {
                    assert!(bytes.len() < remaining, "parse made no progress");
                }
            }
        }
    }
});
