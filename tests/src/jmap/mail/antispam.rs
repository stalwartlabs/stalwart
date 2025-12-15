/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use email::mailbox::{DRAFTS_ID, INBOX_ID, JUNK_ID};
use store::write::now;
use types::{id::Id, keyword::Keyword};

use crate::{imap::antispam::*, jmap::JMAPTest};

pub async fn test(params: &mut JMAPTest) {
    println!("Running Email Spam classifier tests...");
    let account = params.account("jdoe@example.com");
    let client = account.client();
    let account_id = account.id().document_id();

    // Make sure there are no training samples
    spam_delete_samples(&params.server).await;
    assert_eq!(spam_training_samples(&params.server).await.total_count, 0);

    // Import samples
    let mut spam_ids = vec![];
    let mut ham_ids = vec![];
    for (idx, samples) in [&SPAM, &HAM].into_iter().enumerate() {
        let is_spam = idx == 0;
        for (num, sample) in samples.iter().enumerate() {
            let mut mailbox_ids = vec![];
            let mut keywords = vec![];

            if num == 0 {
                if is_spam {
                    mailbox_ids.push(Id::from(JUNK_ID).to_string());
                    keywords.push(Keyword::Junk.to_string());
                } else {
                    mailbox_ids.push(Id::from(INBOX_ID).to_string());
                    keywords.push(Keyword::NotJunk.to_string());
                }
            } else {
                mailbox_ids.push(Id::from(DRAFTS_ID).to_string());
            }

            let mail_id = client
                .email_import(
                    sample.as_bytes().to_vec(),
                    &mailbox_ids,
                    Some(&keywords),
                    None,
                )
                .await
                .unwrap()
                .take_id();
            if is_spam {
                spam_ids.push(mail_id);
            } else {
                ham_ids.push(mail_id);
            }
        }
    }
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 1);
    assert_eq!(samples.spam_count, 1);

    // Train the classifier via JMAP
    for (ids, is_spam) in [(&spam_ids, true), (&ham_ids, false)] {
        for (idx, id) in ids.iter().skip(1).enumerate() {
            // Set keywords and mailboxes
            let mut request = client.build();
            let req = request.set_email().update(id);
            if idx < 5 || !is_spam {
                // Update via keywords
                let keyword = if is_spam {
                    Keyword::Junk
                } else {
                    Keyword::NotJunk
                }
                .to_string();
                req.keywords([&keyword]);
            } else {
                // Update via mailbox
                let mailbox_id = if is_spam { JUNK_ID } else { INBOX_ID };
                req.mailbox_ids([&Id::from(mailbox_id).to_string()]);
            }

            request.send_set_email().await.unwrap().updated(id).unwrap();
        }
    }
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 10);
    assert_eq!(samples.spam_count, 10);

    // Reclassifying an email should not add a new sample
    let mut request = client.build();
    request
        .set_email()
        .update(&ham_ids[0])
        .keywords([Keyword::Junk.to_string()]);
    request
        .send_set_email()
        .await
        .unwrap()
        .updated(&ham_ids[0])
        .unwrap();
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 9);
    assert_eq!(samples.spam_count, 11);
    assert_eq!(samples.samples.len(), 20);
    let hold_for = params
        .server
        .core
        .spam
        .classifier
        .as_ref()
        .unwrap()
        .hold_samples_for;
    assert!(hold_for > 2 * 86400);
    let hold_until = now() + hold_for;
    let hold_range = (hold_until - 86400)..=hold_until;
    assert!(samples.samples.iter().all(|s| s.account_id == account_id
        && s.remove.is_none()
        && hold_range.contains(&s.until)));

    // Purging blobs should not remove training samples
    params
        .server
        .store()
        .purge_blobs(params.server.blob_store().clone())
        .await
        .unwrap();
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 9);
    assert_eq!(samples.spam_count, 11);
    assert_eq!(samples.samples.len(), 20);

    // Extend hold period so a new training sample is generated
    let old_core = params.server.core.clone();
    let mut new_core = old_core.as_ref().clone();
    new_core.spam.classifier.as_mut().unwrap().hold_samples_for += 2 * 86400;
    params.server.inner.shared_core.store(Arc::new(new_core));

    // Reclassifying an email will now add a new sample
    let mut request = client.build();
    request
        .set_email()
        .update(&ham_ids[0])
        .keywords([Keyword::NotJunk.to_string()]);
    request
        .send_set_email()
        .await
        .unwrap()
        .updated(&ham_ids[0])
        .unwrap();
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 10);
    assert_eq!(samples.spam_count, 11);
    assert_eq!(samples.samples.len(), 21);

    // Blob purge should remove the duplicated sample
    params
        .server
        .store()
        .purge_blobs(params.server.blob_store().clone())
        .await
        .unwrap();
    let samples = spam_training_samples(&params.server).await;
    assert_eq!(samples.ham_count, 10);
    assert_eq!(samples.spam_count, 10);
    assert_eq!(samples.samples.len(), 20);

    params.destroy_all_mailboxes(account).await;
    params.assert_is_empty().await;
}
