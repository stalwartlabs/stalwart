/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    smtp::queue::{build_rcpt, new_message},
    utils::server::TestServerBuilder,
};
use registry::{
    schema::{
        enums::MtaQueueQuotaKey,
        prelude::ObjectType,
        structs::{Expression, MtaQueueQuota},
    },
    types::map::Map,
};
use smtp::queue::{Error, ErrorDetails, Metadata, Status, quota::HasQueueQuota};
use store::write::BatchBuilder;

#[tokio::test]
async fn queue_quota_rcpt_domain() {
    let mut test = TestServerBuilder::new("smtp_queue_quota")
        .await
        .with_http_listener(19071)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let admin = test.account("admin");
    for (domain, size, messages) in [("a.org", Some(1000), None), ("b.org", None, Some(1))] {
        admin
            .registry_create_object(MtaQueueQuota {
                description: None,
                enable: true,
                key: Map::new(vec![MtaQueueQuotaKey::RcptDomain]),
                match_: Expression {
                    else_: format!("rcpt_domain = '{domain}'"),
                    ..Default::default()
                },
                messages,
                size,
            })
            .await;
    }
    admin.reload_settings().await;
    test.reload_core();
    test.expect_reload_settings().await;

    let mut message = new_message(0);
    message.message.size = 100;
    message.message.recipients = vec![
        build_rcpt("x@a.org", 0, 0, 0),
        build_rcpt("y@b.org", 0, 0, 0),
        build_rcpt("z@b.org", 0, 0, 0),
        build_rcpt("w@c.org", 0, 0, 0),
    ];

    let mut quotas = test
        .server
        .has_quota(&mut message)
        .await
        .expect("message is within quota")
        .into_iter()
        .map(|metadata| match metadata {
            Metadata::QueueSize { id, .. } => ("size", id),
            Metadata::QueueCount { id, .. } => ("count", id),
            Metadata::Headers { .. } => ("headers", 0),
        })
        .collect::<Vec<_>>();
    quotas.sort_unstable();
    assert_eq!(quotas, vec![("count", 2 << 32), ("size", 1 << 32)]);

    message.message.metadata = test
        .server
        .has_quota(&mut message)
        .await
        .expect("message is within quota")
        .into_boxed_slice();
    message.message.recipients[1].status = Status::PermanentFailure(Box::new(ErrorDetails {
        entity: "b.org".into(),
        details: Error::Io("test".into()),
    }));
    let mut batch = BatchBuilder::new();
    let mut released = message.release_quota(&mut batch);
    released.sort_unstable();
    assert_eq!(released, vec![2, 2 << 32]);
    assert_eq!(
        message
            .message
            .metadata
            .iter()
            .map(|metadata| match metadata {
                Metadata::QueueSize { id, .. } => ("size", *id),
                Metadata::QueueCount { id, .. } => ("count", *id),
                Metadata::Headers { .. } => ("headers", 0),
            })
            .collect::<Vec<_>>(),
        vec![("size", 1 << 32)]
    );

    test.account("admin")
        .registry_destroy_all(ObjectType::MtaQueueQuota)
        .await;
}
