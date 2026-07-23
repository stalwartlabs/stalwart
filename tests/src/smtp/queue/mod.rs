/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::config::smtp::queue::{QueueExpiry, QueueName};
use smtp::queue::{Message, MessageWrapper, Recipient, Schedule, Status};
use std::net::{IpAddr, Ipv4Addr};
use store::write::now;

pub mod concurrent;
pub mod dsn;
pub mod manager;
pub mod retry;
pub mod virtualq;

pub fn build_rcpt(address: &str, retry: u64, notify: u64, expires: u64) -> Recipient {
    Recipient {
        address: address.into(),
        retry: Schedule::later(retry),
        notify: Schedule::later(notify),
        expires: QueueExpiry::Ttl(expires),
        status: Status::Scheduled,
        flags: 0,
        orcpt: None,
        queue: QueueName::default(),
    }
}

pub fn new_message(queue_id: u64) -> MessageWrapper {
    MessageWrapper {
        queue_id,
        span_id: 0,
        queue_name: QueueName::default(),
        is_multi_queue: false,
        message: Message {
            size: 0,
            created: now(),
            return_path: "sender@foobar.org".into(),
            recipients: vec![],
            flags: 0,
            env_id: None,
            priority: 0,
            metadata: Default::default(),
            blob_hash: Default::default(),
            received_from_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            received_via_port: 0,
        },
    }
}
