/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    imap::Type,
    system::antispam::{HAM, SPAM, TEST},
    utils::{imap::AssertResult, server::TestServer, smtp::SmtpConnection},
};
use common::{Server, manager::SPAM_TRAINER_KEY};
use imap_proto::ResponseType;
use registry::schema::{
    enums::TaskSpamFilterMaintenanceType,
    prelude::ObjectType,
    structs::{Task, TaskSpamFilterMaintenance, TaskStatus},
};
use spam_filter::modules::classifier::SpamTrainer;
use store::{
    Deserialize,
    write::{AlignedBytes, Archive},
};

pub async fn test(test: &TestServer) {
    println!("Running Spam classifier tests...");
    let admin = test.account("admin@example.com");
    let account = test.account("sgd@example.com");
    let mut imap = account.imap_client().await;
    let account_id = account.id();

    // Make sure there are no training samples
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    assert_eq!(admin.spam_training_samples().await, vec![]);

    // Train the classifier via APPEND
    imap.append("INBOX", HAM[0]).await;
    imap.append("Junk Mail", SPAM[0]).await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 1);

    // Append two spam samples to "Drafts", then train the classifier via STORE and MOVE
    imap.append("Drafts", SPAM[1]).await;
    imap.append("Drafts", SPAM[2]).await;
    imap.send_ok("SELECT Drafts").await;
    imap.send_ok("STORE 1 +FLAGS ($Junk)").await;
    imap.send_ok("MOVE 2 \"Junk Mail\"").await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 1);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 3);

    // Add the remaining messages via APPEND
    for message in HAM.iter().skip(1) {
        imap.append("INBOX", message).await;
    }
    for message in SPAM.iter().skip(3) {
        imap.append("Junk Mail", message).await;
    }
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 10);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);
    assert_eq!(samples.len(), 20);
    assert!(samples.iter().all(
        |(_, s)| s.blob_id.class.account_id() == account_id.document_id() && !s.delete_after_use
    ));

    // Train the classifier
    admin
        .registry_create_object(Task::SpamFilterMaintenance(TaskSpamFilterMaintenance {
            maintenance_type: TaskSpamFilterMaintenanceType::Train,
            status: TaskStatus::now(),
        }))
        .await;
    test.wait_for_tasks().await;
    let model = spam_classifier_model(&test.server).await;
    assert_eq!(model.reservoir.ham.total_seen, 10);
    assert_eq!(model.reservoir.spam.total_seen, 10);
    assert_eq!(
        model.last_id,
        samples.iter().map(|(id, _)| id.id()).max().unwrap()
    );
    assert_eq!(account.spam_training_samples().await.len(), 20);
    assert!(test.server.inner.data.spam_classifier.load().is_active());

    // Send 3 test emails
    for message in TEST {
        let mut lmtp = SmtpConnection::connect().await;
        lmtp.ingest("bill@example.com", &["sgd@example.com"], message)
            .await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    imap.send_ok("SELECT INBOX").await;
    imap.send("FETCH 11 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: can someone explain")
        .assert_contains("X-Spam-Status: No")
        .assert_contains("PROB_HAM_HIGH");
    imap.send("FETCH 12 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("FLAGS ($Junk")
        .assert_contains("Subject: classifier test")
        .assert_contains("X-Spam-Status: No")
        .assert_contains_any(&["PROB_SPAM_UNCERTAIN", "PROB_HAM_LOW"]);
    imap.send_ok("SELECT \"Junk Mail\"").await;
    imap.send("FETCH 10 (FLAGS RFC822.TEXT)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($Junk")
        .assert_contains("Subject: save up to")
        .assert_contains("X-Spam-Status: Yes")
        .assert_contains("PROB_SPAM_HIGH");
    imap.send_ok("MOVE 10 INBOX").await;
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 11);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);

    // Make sure spam traps trigger spam classification
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest("bill@example.com", &["spamtrap@example.com"], SPAM[4])
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let samples = admin.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 11);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 11);

    // Global spam samples should not appear in the account
    let samples = account.spam_training_samples().await;
    assert_eq!(samples.iter().filter(|x| !x.1.is_spam).count(), 11);
    assert_eq!(samples.iter().filter(|x| x.1.is_spam).count(), 10);
}

pub async fn spam_classifier_model(server: &Server) -> SpamTrainer {
    server
        .blob_store()
        .get_blob(SPAM_TRAINER_KEY, 0..usize::MAX)
        .await
        .and_then(|archive| match archive {
            Some(archive) => <Archive<AlignedBytes> as Deserialize>::deserialize(&archive)
                .and_then(|archive| archive.deserialize_untrusted::<SpamTrainer>())
                .map(Some),
            None => Ok(None),
        })
        .unwrap()
        .unwrap()
}
