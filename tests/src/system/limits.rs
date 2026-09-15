/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    account::Account,
    imap::{ImapConnection, Type},
    jmap::JmapUtils,
    server::TestServer,
    smtp::SmtpConnection,
    webdav::{DummyWebDavClient, GenerateTestDavResource},
};
use email::{cache::MessageCacheFetch, mailbox::INBOX_ID};
use groupware::DavResourceName;
use hyper::StatusCode;
use imap_proto::ResponseType;
use jmap_proto::request::method::MethodObject;
use registry::{
    schema::{
        enums::{Permission, StorageQuota},
        prelude::{ObjectType, Property},
        structs::{
            self, AddressBook, Calendar, Credential, Email, PasswordCredential, PermissionsList,
            UserAccount,
        },
    },
    types::{list::List, map::Map},
};
use serde_json::{Value, json};
use types::id::Id;
use utils::map::vec_map::VecMap;

const NAME: &str = "limits@example.org";
const SECRET: &str = "this is a very strong password";
const DAV_NAME: &str = "limits%40example.org";

const MAILBOXES_PER_EMAIL: u64 = 2;
const FLAGS_PER_EMAIL: u64 = 3;
const FLAG_LENGTH: u64 = 10;
const CALENDARS_PER_EVENT: u64 = 2;
const ADDRESS_BOOKS_PER_CARD: u64 = 2;

const MAX_EMAILS: u64 = 3;
const MAX_CALENDARS: u64 = 4;
const MAX_EVENTS: u64 = 2;
const MAX_ADDRESS_BOOKS: u64 = 4;
const MAX_CONTACTS: u64 = 2;
const MAX_FILES: u64 = 2;
const MAX_FOLDERS: u64 = 2;

pub async fn test(test: &mut TestServer) {
    println!("Running object limit tests...");
    let account = setup(test).await;

    email_limits(test, &account).await;
    calendar_limits(&account).await;
    contact_limits(&account).await;
    file_limits(&account).await;

    cleanup(test, &account).await;
}

async fn cleanup(test: &TestServer, account: &Account) {
    let dav = dav_client(account);
    let files_base = format!("{}/{DAV_NAME}", DavResourceName::File.base_path());
    for idx in 0..MAX_FOLDERS {
        dav.request("DELETE", &format!("{files_base}/folder-{idx}"), "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
    account.destroy_all_calendars().await;
    account.destroy_all_addressbooks().await;
    account.destroy_all_event_notifications().await;
    test.destroy_all_mailboxes(account).await;

    let admin = test.account("admin@example.org");
    admin.registry_destroy_all(ObjectType::QueuedMessage).await;
    admin
        .registry_destroy_all(ObjectType::SpamTrainingSample)
        .await;
    admin
        .registry_update_setting(
            Email::default(),
            &[
                Property::MaxMailboxesPerEmail,
                Property::MaxFlagsPerEmail,
                Property::MaxFlagLength,
            ],
        )
        .await;
    admin
        .registry_update_setting(Calendar::default(), &[Property::MaxCalendarsPerEvent])
        .await;
    admin
        .registry_update_setting(AddressBook::default(), &[Property::MaxAddressBooksPerCard])
        .await;
    admin.reload_settings().await;

    test.wait_for_tasks().await;
    test.assert_is_empty().await;
    admin
        .registry_destroy(ObjectType::Account, [account.id()])
        .await
        .assert_destroyed(&[account.id()]);
    test.cleanup().await;
}

async fn setup(test: &TestServer) -> Account {
    let admin = test.account("admin@example.org");
    let domain_id = admin.find_or_create_domain("example.org").await;

    admin
        .registry_update_setting(
            Email {
                max_mailboxes_per_email: MAILBOXES_PER_EMAIL,
                max_flags_per_email: FLAGS_PER_EMAIL,
                max_flag_length: FLAG_LENGTH,
                ..Default::default()
            },
            &[
                Property::MaxMailboxesPerEmail,
                Property::MaxFlagsPerEmail,
                Property::MaxFlagLength,
            ],
        )
        .await;
    admin
        .registry_update_setting(
            Calendar {
                max_calendars_per_event: CALENDARS_PER_EVENT,
                ..Default::default()
            },
            &[Property::MaxCalendarsPerEvent],
        )
        .await;
    admin
        .registry_update_setting(
            AddressBook {
                max_address_books_per_card: ADDRESS_BOOKS_PER_CARD,
                ..Default::default()
            },
            &[Property::MaxAddressBooksPerCard],
        )
        .await;
    admin.reload_settings().await;

    let account_id = admin
        .registry_create_object(structs::Account::User(UserAccount {
            name: "limits".to_string(),
            domain_id,
            credentials: List::from_iter([Credential::Password(PasswordCredential {
                secret: SECRET.to_string(),
                ..Default::default()
            })]),
            quotas: VecMap::from_iter([
                (StorageQuota::MaxEmails, MAX_EMAILS),
                (StorageQuota::MaxCalendars, MAX_CALENDARS),
                (StorageQuota::MaxCalendarEvents, MAX_EVENTS),
                (StorageQuota::MaxAddressBooks, MAX_ADDRESS_BOOKS),
                (StorageQuota::MaxContactCards, MAX_CONTACTS),
                (StorageQuota::MaxFiles, MAX_FILES),
                (StorageQuota::MaxFolders, MAX_FOLDERS),
            ]),
            permissions: structs::Permissions::Merge(PermissionsList {
                enabled_permissions: Map::new(vec![
                    Permission::UnlimitedRequests,
                    Permission::UnlimitedUploads,
                ]),
                disabled_permissions: Default::default(),
            }),
            ..Default::default()
        }))
        .await;

    Account::new(NAME, SECRET, &[NAME], "Limits", account_id)
}

async fn email_limits(test: &TestServer, account: &Account) {
    println!("Running per-email limit tests...");
    let inbox_id = Id::from(INBOX_ID).to_string();
    let response = account
        .jmap_create(
            MethodObject::Mailbox,
            [json!({"name": "Box A"}), json!({"name": "Box B"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    let box_a = response.created(0).id().to_string();
    let box_b = response.created(1).id().to_string();

    // Mailbox and keyword limits on create
    let response = account
        .jmap_create(
            MethodObject::Email,
            [
                email(&[&inbox_id, &box_a, &box_b], &[]),
                email(&[&inbox_id], &["a", "b", "c", "d"]),
                email(&[&inbox_id], &["abcdefghijk"]),
                email(&[&inbox_id, &box_a], &["a", "b", "c"]),
            ],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "tooManyMailboxes");
    assert_eq!(response.not_created(1).typ(), "tooManyKeywords");
    assert_eq!(response.not_created(2).typ(), "invalidProperties");
    let email_id = response.created(3).id().to_string();

    // Mailbox and keyword limits on update
    let response = account
        .jmap_update(
            MethodObject::Email,
            [(&email_id, json!({"keywords/d": true}))],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_updated(&email_id).typ(), "tooManyKeywords");
    let response = account
        .jmap_update(
            MethodObject::Email,
            [(&email_id, json!({format!("mailboxIds/{box_b}"): true}))],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_updated(&email_id).typ(), "tooManyMailboxes");
    account
        .jmap_update(
            MethodObject::Email,
            [(&email_id, json!({"keywords/c": null, "keywords/d": true}))],
            Vec::<(&str, &str)>::new(),
        )
        .await
        .updated(&email_id);

    // IMAP flag and mailbox limits
    let mut imap = ImapConnection::connect(b"_x ").await;
    imap.authenticate(NAME, SECRET).await;
    imap.send_ok("SELECT INBOX").await;
    imap_expect_no(&mut imap, "STORE 1 +FLAGS (e)", "[LIMIT]").await;
    imap.send_ok("STORE 1 -FLAGS (d)").await;
    imap_expect_no(&mut imap, "STORE 1 +FLAGS (abcdefghijk)", "[LIMIT]").await;
    imap.send_ok("STORE 1 +FLAGS (abcdefghij)").await;
    imap_expect_no(&mut imap, "COPY 1 \"Box B\"", "[LIMIT]").await;

    // Duplicate flags count once
    imap.send_ok("STORE 1 -FLAGS (abcdefghij)").await;
    imap.send_ok("STORE 1 +FLAGS (x x)").await;
    let message = "Subject: append\r\n\r\ntest\r\n";
    imap_expect_no(
        &mut imap,
        &format!("APPEND INBOX (a b c d) {{{}+}}\r\n{message}", message.len()),
        "[LIMIT]",
    )
    .await;
    imap.send_ok(&format!(
        "APPEND INBOX (a a b c) {{{}+}}\r\n{message}",
        message.len()
    ))
    .await;
    assert_eq!(email_count(test, account).await, 2);

    // MULTIAPPEND is rejected as a whole when it does not fit in the quota
    imap_expect_no(
        &mut imap,
        &format!(
            "APPEND INBOX {{{len}+}}\r\n{message} {{{len}+}}\r\n{message}",
            len = message.len()
        ),
        "[OVERQUOTA]",
    )
    .await;
    assert_eq!(email_count(test, account).await, 2);

    // Email object quota
    let response = account
        .jmap_create(
            MethodObject::Email,
            [email(&[&inbox_id], &[]), email(&[&inbox_id], &[])],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    response.created(0);
    assert_eq!(response.not_created(1).typ(), "overQuota");
    imap_expect_no(
        &mut imap,
        &format!("APPEND INBOX {{{}+}}\r\n{message}", message.len()),
        "[OVERQUOTA]",
    )
    .await;

    // Delivery over quota
    let mut lmtp = SmtpConnection::connect().await;
    lmtp.ingest(
        "sender@example.org",
        &[NAME],
        "From: sender@example.org\r\nTo: limits@example.org\r\nSubject: over quota\r\n\r\ntest\r\n",
    )
    .await;
    assert_eq!(email_count(test, account).await, MAX_EMAILS as usize);
}

async fn email_count(test: &TestServer, account: &Account) -> usize {
    test.server
        .get_cached_messages(account.id().document_id())
        .await
        .unwrap()
        .emails
        .len()
}

async fn calendar_limits(account: &Account) {
    println!("Running calendar limit tests...");
    let dav = dav_client(account);
    let base = format!("{}/{DAV_NAME}", DavResourceName::Cal.base_path());

    let calendars = create_collections_until_quota(&dav, &base, "cal").await;
    assert!(calendars.len() >= 3, "created {calendars:?}");
    assert_eq!(
        jmap_count(account, MethodObject::Calendar).await,
        MAX_CALENDARS as usize
    );
    let events = put_until_quota(&dav, &format!("{}/", calendars[0]), DavResourceName::Cal).await;
    assert_eq!(events.len(), MAX_EVENTS as usize);

    // DAV linking an event into more calendars than allowed
    let event_name = events[0].rsplit_once('/').unwrap().1;
    for (calendar, status) in [
        (&calendars[1], StatusCode::CREATED),
        (&calendars[2], StatusCode::FORBIDDEN),
    ] {
        dav.request_with_headers(
            "COPY",
            &events[0],
            [("destination", format!("{calendar}/{event_name}").as_str())],
            "",
        )
        .await
        .with_status(status);
    }

    // JMAP rejects new objects once the quota is reached
    let calendar_ids = jmap_ids(account, MethodObject::Calendar).await;
    let response = account
        .jmap_create(
            MethodObject::Calendar,
            [json!({"name": "Over quota"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "overQuota");
    let response = account
        .jmap_create(
            MethodObject::CalendarEvent,
            [json!({
                "title": "Over quota",
                "start": "2006-01-22T10:00:00",
                "duration": "PT1H",
                "calendarIds": {&calendar_ids[0]: true},
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "overQuota");

    // JMAP calendarIds limit on update
    let event = jmap_list(account, MethodObject::CalendarEvent)
        .await
        .into_iter()
        .find(|event| event["calendarIds"].as_object().unwrap().len() == 2)
        .expect("linked event");
    let event_id = event.id().to_string();
    let extra_calendar = calendar_ids
        .iter()
        .find(|id| event["calendarIds"].get(id.as_str()).is_none())
        .unwrap();
    let response = account
        .jmap_update(
            MethodObject::CalendarEvent,
            [(
                &event_id,
                json!({format!("calendarIds/{extra_calendar}"): true}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_updated(&event_id).typ(), "invalidProperties");
}

async fn contact_limits(account: &Account) {
    println!("Running contact limit tests...");
    let dav = dav_client(account);
    let base = format!("{}/{DAV_NAME}", DavResourceName::Card.base_path());

    let books = create_collections_until_quota(&dav, &base, "book").await;
    assert!(books.len() >= 3, "created {books:?}");
    assert_eq!(
        jmap_count(account, MethodObject::AddressBook).await,
        MAX_ADDRESS_BOOKS as usize
    );
    let cards = put_until_quota(&dav, &format!("{}/", books[0]), DavResourceName::Card).await;
    assert_eq!(cards.len(), MAX_CONTACTS as usize);

    // DAV linking a card into more address books than allowed
    let card_name = cards[0].rsplit_once('/').unwrap().1;
    for (book, status) in [
        (&books[1], StatusCode::CREATED),
        (&books[2], StatusCode::FORBIDDEN),
    ] {
        dav.request_with_headers(
            "COPY",
            &cards[0],
            [("destination", format!("{book}/{card_name}").as_str())],
            "",
        )
        .await
        .with_status(status);
    }

    // JMAP rejects new objects once the quota is reached
    let book_ids = jmap_ids(account, MethodObject::AddressBook).await;
    let response = account
        .jmap_create(
            MethodObject::AddressBook,
            [json!({"name": "Over quota"})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "overQuota");
    let response = account
        .jmap_create(
            MethodObject::ContactCard,
            [json!({
                "name": {"full": "Over quota"},
                "addressBookIds": {&book_ids[0]: true},
            })],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "overQuota");

    // JMAP addressBookIds limit on update
    let card = jmap_list(account, MethodObject::ContactCard)
        .await
        .into_iter()
        .find(|card| card["addressBookIds"].as_object().unwrap().len() == 2)
        .expect("linked card");
    let card_id = card.id().to_string();
    let extra_book = book_ids
        .iter()
        .find(|id| card["addressBookIds"].get(id.as_str()).is_none())
        .unwrap();
    let response = account
        .jmap_update(
            MethodObject::ContactCard,
            [(
                &card_id,
                json!({format!("addressBookIds/{extra_book}"): true}),
            )],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_updated(&card_id).typ(), "invalidProperties");
}

async fn file_limits(account: &Account) {
    println!("Running file limit tests...");
    let dav = dav_client(account);
    let base = format!("{}/{DAV_NAME}", DavResourceName::File.base_path());

    let folders = create_collections_until_quota(&dav, &base, "folder").await;
    assert_eq!(folders.len(), MAX_FOLDERS as usize);
    let files = put_until_quota(&dav, &format!("{}/", folders[0]), DavResourceName::File).await;
    assert_eq!(files.len(), MAX_FILES as usize);

    let response = account
        .jmap_create(
            MethodObject::FileNode,
            [json!({"name": "Over quota folder", "parentId": null})],
            Vec::<(&str, &str)>::new(),
        )
        .await;
    assert_eq!(response.not_created(0).typ(), "overQuota");

    let response = account
        .jmap_method_calls(json!([
            [
                "Blob/upload",
                {
                    "accountId": account.id_string(),
                    "create": {"blob": {"data": [{"data:asText": "over quota"}]}}
                },
                "b0"
            ],
            [
                "FileNode/set",
                {
                    "accountId": account.id_string(),
                    "create": {
                        "i0": {"name": "over-quota.txt", "parentId": null, "blobId": "#blob"}
                    }
                },
                "f0"
            ]
        ]))
        .await;
    assert_eq!(
        response
            .pointer("/methodResponses/1/1/notCreated/i0/type")
            .and_then(Value::as_str),
        Some("overQuota"),
        "{response:?}"
    );
}

fn email(mailbox_ids: &[&str], keywords: &[&str]) -> Value {
    json!({
        "mailboxIds": mailbox_ids.iter().map(|id| (id.to_string(), Value::Bool(true))).collect::<serde_json::Map<_, _>>(),
        "keywords": keywords.iter().map(|keyword| (keyword.to_string(), Value::Bool(true))).collect::<serde_json::Map<_, _>>(),
        "subject": "Limits test",
    })
}

fn dav_client(account: &Account) -> DummyWebDavClient {
    DummyWebDavClient::new(account.id().document_id(), NAME, SECRET, NAME)
}

async fn imap_expect_no(imap: &mut ImapConnection, command: &str, code: &str) {
    imap.send(command).await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::No).await;
    assert!(
        lines.iter().any(|line| line.contains(code)),
        "expected {code} for {command:?}, got {lines:?}"
    );
}

async fn create_collections_until_quota(
    dav: &DummyWebDavClient,
    base: &str,
    prefix: &str,
) -> Vec<String> {
    let mut created = Vec::new();
    for idx in 0..10 {
        let path = format!("{base}/{prefix}-{idx}");
        let response = dav.mkcol("MKCOL", &path, [], []).await;
        if response.status == StatusCode::CREATED {
            created.push(path);
        } else {
            response
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_failed_precondition("D:quota-not-exceeded", "");
            return created;
        }
    }
    panic!("quota was never reached for {base}");
}

async fn put_until_quota(
    dav: &DummyWebDavClient,
    parent: &str,
    resource_type: DavResourceName,
) -> Vec<String> {
    let mut created = Vec::new();
    for idx in 0..10 {
        let path = format!("{parent}item-{idx}");
        let response = dav.request("PUT", &path, resource_type.generate()).await;
        if response.status == StatusCode::CREATED {
            created.push(path);
        } else {
            response
                .with_status(StatusCode::PRECONDITION_FAILED)
                .with_failed_precondition("D:quota-not-exceeded", "");
            return created;
        }
    }
    panic!("quota was never reached for {parent}");
}

async fn jmap_list(account: &Account, object: MethodObject) -> Vec<Value> {
    account
        .jmap_get(object, Vec::<&str>::new(), Vec::<&str>::new())
        .await
        .list()
        .to_vec()
}

async fn jmap_count(account: &Account, object: MethodObject) -> usize {
    jmap_list(account, object).await.len()
}

async fn jmap_ids(account: &Account, object: MethodObject) -> Vec<String> {
    jmap_list(account, object)
        .await
        .iter()
        .map(|item| item.id().to_string())
        .collect()
}
