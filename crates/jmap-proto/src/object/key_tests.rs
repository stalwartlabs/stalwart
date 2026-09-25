/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    object::{
        addressbook::{AddressBookProperty, AddressBookValue},
        blob::{BlobProperty, BlobValue},
        calendar::{CalendarProperty, CalendarValue},
        calendar_event_notification::{
            CalendarEventNotificationProperty, CalendarEventNotificationValue,
        },
        email::{EmailProperty, EmailValue, HeaderForm, HeaderProperty},
        email_submission::{EmailSubmissionProperty, EmailSubmissionValue},
        file_node::{FileNodeProperty, FileNodeValue},
        identity::{IdentityProperty, IdentityValue},
        mailbox::{MailboxProperty, MailboxValue},
        metadata::MetadataProperty,
        participant_identity::{ParticipantIdentityProperty, ParticipantIdentityValue},
        principal::{PrincipalProperty, PrincipalValue},
        push_subscription::{PushSubscriptionProperty, PushSubscriptionValue},
        quota::{QuotaProperty, QuotaValue},
        search_snippet::{SearchSnippetProperty, SearchSnippetValue},
        share_notification::{ShareNotificationProperty, ShareNotificationValue},
        sieve::{SieveProperty, SieveValue},
        thread::{ThreadProperty, ThreadValue},
        vacation_response::{VacationResponseProperty, VacationResponseValue},
    },
    types::date::UTCDate,
};
use calcard::jscalendar::JSCalendarType;
use jmap_tools::{
    Element, JsonPointer, JsonPointerItem, Key, Map, Null, PointerDepth, Property, Value,
};
use registry::{
    jmap::RegistryValue, schema::properties::Property as RegistryProperty, types::EnumImpl,
};
use std::{
    collections::{HashSet, hash_map::DefaultHasher},
    hash::{Hash, Hasher},
    iter::successors,
    str::FromStr,
    thread,
};
use types::{
    blob::{BlobClass, BlobId},
    blob_hash::BlobHash,
    id::Id,
    keyword::Keyword,
    special_use::SpecialUse,
    type_state::DataType,
};

const NAMES: &str = "
    @type GreaterThan GreaterThanOrEqual LessThan LessThanOrEqual accessed accessedAfter
    accessedBefore accountIds accounts action address addresses after all allInThreadHaveKeyword
    ancestorId asAddresses asDate asGroupedAddresses asMessageIds asText asURLs attachments
    attendee attending auth bcc before blobId body bodyProperties bodyStructure bodyValues
    calendarAddress calendarEventId calendarEventIds canceled capabilities cc changed changedBy
    charset cid color comment compareCaseInsensitively created createdAfter createdBefore data
    data:asBase64 data:asText defaultAlertsWithTime defaultAlertsWithoutTime delivered
    deliveryStatus descendantId description destroyed deviceClientId digest:sha digest:sha-256
    digest:sha-512 directory displayed disposition documents downloads dsnBlobIds email emailId
    emailIds emailPush envelope event eventPatch executable expandRecurrences expires
    fetchAllBodyValues fetchHTMLBodyValues fetchTextBodyValues file filterAsTree final from
    fromDate group hardLimit hasAnyRole hasAttachment hasKeyword hasMember header headers home
    htmlBody htmlSignature id identityId identityIds inAddressBook inCalendar inMailbox
    inMailboxOtherThan inReplyTo inThread includeInAvailability individual isActive isDefault
    isDraft isEnabled isEncodingProblem isExecutable isSubscribed isTopLevel isTruncated
    isVisible keys keywords kind language length location mailFrom mailboxIds maxBodyValueBytes
    maxSize mayAddChildren mayAddItems mayCreateChild mayDelete mayModifyContent mayRSVP mayRead
    mayReadFreeBusy mayReadItems mayRemoveItems mayRename maySetKeywords maySetSeen mayShare
    maySubmit mayUpdatePrivate mayWrite mayWriteAll mayWriteOwn mdnBlobIds messageId metadata
    metadataExists metadataTextContains metadataTextEquals minSize modified modifiedAfter
    modifiedBefore music myRights name name/given name/surname name/surname2 nameMatch newRights
    nickname no nodeType none noneInThreadHaveKeyword notKeyword note objectAccountId objectId
    objectType offset oldRights onDestroyRemoveChildren onDestroyRemoveContents
    onDestroyRemoveEvents onExists onSuccessActivateScript onSuccessDeactivateScript
    onSuccessDestroyEmail onSuccessSetIsDefault onSuccessUpdateEmail onlineService organization
    other owner p256dh parameters parentId partId pending phone pictures preview principalId
    privateMetadata privateMetadataExists privateMetadataTextContains privateMetadataTextEquals
    queued rcptTo receivedAt recurrenceId recurrenceOverridesAfter recurrenceOverridesBefore
    reduceParticipants references relativeTo replyTo resource resourceType role root scope
    sendAt sendSchedulingMessages sender sentAfter sentAt sentBefore shareWith size smtpReply
    softLimit someInThreadHaveKeyword sortAsTree sortOrder start subParts subject symlink target
    temp text textBody textSignature threadId threadIds timeZone title to toDate totalEmails
    totalThreads trash tree trigger type typeMatch types uid undoStatus unknown unreadEmails
    unreadThreads updated updatedAfter updatedBefore url urn:ietf:params:jmap:blob
    urn:ietf:params:jmap:calendars urn:ietf:params:jmap:calendars:parse
    urn:ietf:params:jmap:contacts urn:ietf:params:jmap:contacts:parse urn:ietf:params:jmap:core
    urn:ietf:params:jmap:emailpush urn:ietf:params:jmap:filenode urn:ietf:params:jmap:mail
    urn:ietf:params:jmap:mail:share urn:ietf:params:jmap:metadata
    urn:ietf:params:jmap:principals urn:ietf:params:jmap:principals:availability
    urn:ietf:params:jmap:principals:owner urn:ietf:params:jmap:quota urn:ietf:params:jmap:sieve
    urn:ietf:params:jmap:submission urn:ietf:params:jmap:vacationresponse
    urn:ietf:params:jmap:webpush-vapid urn:ietf:params:jmap:websocket urn:stalwart:jmap used
    value verificationCode videos warnLimit when yes
";

const IDS: &[&str] = &["a", "b", "id", "name", "cc", "to", "p333333333333"];

const POINTERS: &[&str] = &[
    "/id",
    "/name",
    "keywords/$seen",
    "mailboxIds/a",
    "a~1b/~0c",
    "shareWith/b/mayReadItems",
    "metadata/ns/key",
];

const REFERENCES: &[&str] = &["k1", "", "#", "é🎉"];

const SMALL_STACK: usize = 256 * 1024;
const NESTED_LEVELS: usize = 300;
const LEVELS_PAST_LIMIT: usize = 8;

fn hash_of<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn json<T: serde::Serialize + ?Sized>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|err| format!("error {err}"))
}

fn ids() -> impl Iterator<Item = Id> {
    IDS.iter()
        .map(|text| Id::from_str(text).expect("base32 id"))
        .chain([Id::from(0u64), Id::from(u64::MAX)])
}

fn references() -> impl Iterator<Item = String> {
    REFERENCES.iter().map(|reference| reference.to_string())
}

fn pointers<P: Property>() -> impl Iterator<Item = JsonPointer<P>> {
    POINTERS.iter().map(|text| JsonPointer::parse(text)).chain([
        JsonPointer::new(vec![JsonPointerItem::Root]),
        JsonPointer::new(vec![JsonPointerItem::Wildcard]),
        JsonPointer::new(vec![JsonPointerItem::Number(7)]),
        JsonPointer::new(vec![JsonPointerItem::Invalid("x~".into())]),
        JsonPointer::new(vec![
            JsonPointerItem::Key(Key::Owned("a/b".into())),
            JsonPointerItem::Number(0),
        ]),
    ])
}

fn dates() -> impl Iterator<Item = UTCDate> {
    [
        UTCDate::from_timestamp(0),
        UTCDate::from_timestamp(1_738_598_445),
        UTCDate::from_str("2021-01-01T09:55:06+02:00").expect("date"),
        UTCDate::from_str("1997-11-21T09:55:06-06:00").expect("date"),
        UTCDate {
            year: 65535,
            month: 255,
            day: 255,
            hour: 255,
            minute: 255,
            second: 255,
            tz_before_gmt: true,
            tz_hour: 255,
            tz_minute: 255,
        },
    ]
    .into_iter()
}

fn blob_ids() -> impl Iterator<Item = BlobId> {
    [
        BlobClass::Linked {
            account_id: 1,
            collection: 1,
            document_id: 5000,
        },
        BlobClass::Embedded {
            account_id: u32::MAX,
            collection: 0,
            document_id: 0,
        },
        BlobClass::Reserved {
            account_id: 7,
            expires: u64::MAX,
        },
    ]
    .into_iter()
    .map(|class| BlobId::new(BlobHash::generate(b"blob"), class))
}

fn keywords() -> impl Iterator<Item = Keyword> {
    [
        Keyword::Seen,
        Keyword::Other("$seen".into()),
        Keyword::Other("name".into()),
        Keyword::parse("custom"),
        Keyword::parse("$MailFlagBit0"),
    ]
    .into_iter()
}

fn headers() -> impl Iterator<Item = HeaderProperty> {
    [
        (HeaderForm::Text, "X-Foo", false),
        (HeaderForm::Raw, "X-Foo:asText", false),
        (HeaderForm::Raw, "a", true),
        (HeaderForm::Addresses, "From", true),
        (HeaderForm::Raw, "From:asAddresses", true),
        (HeaderForm::Date, "Date", false),
    ]
    .into_iter()
    .map(|(form, header, all)| HeaderProperty {
        form,
        header: header.to_string(),
        all,
    })
}

fn parsed<P: Property, E: Element<Property = P>>(cases: &[(P, &str)]) -> Vec<E> {
    cases
        .iter()
        .map(|(property, text)| {
            E::try_parse::<P>(&Key::Property(property.clone()), text)
                .unwrap_or_else(|| panic!("{property:?} {text}"))
        })
        .collect()
}

fn check_properties<P: Property>(extra: impl IntoIterator<Item = P>) {
    let mut pool: Vec<P> = Vec::new();
    for name in NAMES.split_whitespace() {
        if let Some(property) = P::try_parse(None, name) {
            assert_eq!(property.to_cow(), name, "{property:?}");
            pool.push(property);
        }
    }
    for property in extra {
        if !pool.contains(&property) {
            pool.push(property);
        }
    }
    let texts = pool.iter().map(Property::to_cow).collect::<Vec<_>>();
    for (a, text_a) in pool.iter().zip(&texts) {
        let key = Key::Property(a.clone());
        assert!(a.key_eq_str(text_a), "{a:?}");
        assert_eq!(hash_of(&key), hash_of(&Key::<P>::Borrowed(text_a)), "{a:?}");
        assert_eq!(json(&key), json(text_a.as_ref()), "{a:?}");
        let object: Value<'_, P, Null> = Value::Object(Map::from(vec![(key.clone(), Value::Null)]));
        assert_eq!(
            json(&object),
            format!("{{{}:null}}", json(text_a.as_ref())),
            "{a:?}"
        );
        for (b, text_b) in pool.iter().zip(&texts) {
            let equal = text_a == text_b;
            assert_eq!(a.key_eq(b), equal, "{a:?} {b:?}");
            assert_eq!(a.key_eq_str(text_b), equal, "{a:?} {text_b:?}");
            assert_eq!(
                key == Key::Borrowed(text_b.as_ref()),
                equal,
                "{a:?} {text_b:?}"
            );
        }
    }
}

fn check_elements<P: Property, E: Element<Property = P>>(elements: impl IntoIterator<Item = E>) {
    for element in elements {
        let text = element.to_cow();
        let value: Value<'_, P, E> = Value::Element(element);
        assert_eq!(json(&value), json(text.as_ref()), "{value:?}");
    }
}

#[test]
fn keys_with_equal_text_are_equal() {
    let named = |text| Id::from_str(text).expect("base32 id");
    let header = |form, header: &str| HeaderProperty {
        form,
        header: header.to_string(),
        all: false,
    };
    assert!(EmailProperty::IdValue(named("name")).key_eq(&EmailProperty::Name));
    assert!(MailboxProperty::IdValue(named("id")).key_eq(&MailboxProperty::Id));
    assert!(
        EmailProperty::Keyword(Keyword::Other("$seen".into()))
            .key_eq(&EmailProperty::Keyword(Keyword::Seen))
    );
    assert!(EmailProperty::Keyword(Keyword::Other("name".into())).key_eq(&EmailProperty::Name));
    assert!(
        EmailProperty::Header(header(HeaderForm::Text, "X-Foo")).key_eq(&EmailProperty::Header(
            header(HeaderForm::Raw, "X-Foo:asText")
        ))
    );
    assert!(MailboxProperty::Pointer(JsonPointer::parse("/name")).key_eq(&MailboxProperty::Name));
    assert!(SieveProperty::Pointer(JsonPointer::parse("/id")).key_eq(&SieveProperty::Id));
    assert!(ShareNotificationProperty::Name.key_eq(&ShareNotificationProperty::ChangedByName));
    assert!(EmailProperty::IdReference("k1".into()).key_eq_str("#k1"));
    assert!(
        !EmailProperty::IdValue(Id::from(1u64)).key_eq(&EmailProperty::IdValue(Id::from(2u64)))
    );
    assert!(
        !EmailProperty::Keyword(Keyword::Seen).key_eq(&EmailProperty::Keyword(Keyword::Flagged))
    );
}

#[test]
fn email_keys_follow_their_text() {
    check_properties(
        ids()
            .map(EmailProperty::IdValue)
            .chain(pointers().map(EmailProperty::Pointer))
            .chain(references().map(EmailProperty::IdReference))
            .chain(keywords().map(EmailProperty::Keyword))
            .chain(headers().map(EmailProperty::Header)),
    );
    check_elements::<EmailProperty, EmailValue>(
        ids()
            .map(EmailValue::Id)
            .chain(dates().map(EmailValue::Date))
            .chain(blob_ids().map(EmailValue::BlobId))
            .chain(references().map(EmailValue::IdReference)),
    );
}

#[test]
fn mailbox_keys_follow_their_text() {
    check_properties(
        ids()
            .map(MailboxProperty::IdValue)
            .chain(pointers().map(MailboxProperty::Pointer)),
    );
    check_elements::<MailboxProperty, MailboxValue>(
        ids()
            .map(MailboxValue::Id)
            .chain(references().map(MailboxValue::IdReference))
            .chain(
                [
                    SpecialUse::Inbox,
                    SpecialUse::Trash,
                    SpecialUse::None,
                    SpecialUse::Snoozed,
                ]
                .map(MailboxValue::Role),
            ),
    );
}

#[test]
fn addressbook_keys_follow_their_text() {
    check_properties(
        ids()
            .map(AddressBookProperty::IdValue)
            .chain(pointers().map(AddressBookProperty::Pointer)),
    );
    check_elements::<AddressBookProperty, AddressBookValue>(
        ids()
            .map(AddressBookValue::Id)
            .chain(references().map(AddressBookValue::IdReference))
            .chain([SpecialUse::Shared, SpecialUse::None].map(AddressBookValue::Role)),
    );
}

#[test]
fn calendar_keys_follow_their_text() {
    check_properties(
        ids()
            .map(CalendarProperty::IdValue)
            .chain(pointers().map(CalendarProperty::Pointer)),
    );
    check_elements::<CalendarProperty, CalendarValue>(
        ids()
            .map(CalendarValue::Id)
            .chain(references().map(CalendarValue::IdReference))
            .chain(dates().map(CalendarValue::Date))
            .chain([JSCalendarType::Alert, JSCalendarType::Event].map(CalendarValue::Type))
            .chain(parsed(&[
                (CalendarProperty::IncludeInAvailability, "attending"),
                (CalendarProperty::IncludeInAvailability, "none"),
                (CalendarProperty::Action, "display"),
                (CalendarProperty::Action, "email"),
                (CalendarProperty::RelativeTo, "end"),
                (CalendarProperty::TimeZone, "Europe/Berlin"),
                (CalendarProperty::TimeZone, "Etc/GMT+5"),
                (CalendarProperty::TimeZone, "UTC"),
                (CalendarProperty::Offset, "-PT15M"),
                (CalendarProperty::Offset, "P1DT2H"),
                (CalendarProperty::When, "2025-02-03T16:00:45Z"),
            ])),
    );
}

#[test]
fn file_node_keys_follow_their_text() {
    check_properties(
        ids()
            .map(FileNodeProperty::IdValue)
            .chain(pointers().map(FileNodeProperty::Pointer)),
    );
    check_elements::<FileNodeProperty, FileNodeValue>(
        ids()
            .map(FileNodeValue::Id)
            .chain(dates().map(FileNodeValue::Date))
            .chain(blob_ids().map(FileNodeValue::BlobId))
            .chain(references().map(FileNodeValue::IdReference)),
    );
}

#[test]
fn principal_keys_follow_their_text() {
    check_properties(ids().map(PrincipalProperty::IdValue));
    check_elements::<PrincipalProperty, PrincipalValue>(ids().map(PrincipalValue::Id).chain(
        parsed(&[
            (PrincipalProperty::Type, "individual"),
            (PrincipalProperty::Type, "group"),
            (PrincipalProperty::Type, "location"),
        ]),
    ));
}

#[test]
fn email_submission_keys_follow_their_text() {
    check_properties(pointers().map(EmailSubmissionProperty::Pointer));
    check_elements::<EmailSubmissionProperty, EmailSubmissionValue>(
        ids()
            .map(EmailSubmissionValue::Id)
            .chain(dates().map(EmailSubmissionValue::Date))
            .chain(blob_ids().map(EmailSubmissionValue::BlobId))
            .chain(references().map(EmailSubmissionValue::IdReference))
            .chain(parsed(&[
                (EmailSubmissionProperty::UndoStatus, "pending"),
                (EmailSubmissionProperty::UndoStatus, "canceled"),
                (EmailSubmissionProperty::Delivered, "queued"),
                (EmailSubmissionProperty::Delivered, "unknown"),
                (EmailSubmissionProperty::Displayed, "yes"),
            ])),
    );
}

#[test]
fn identity_keys_follow_their_text() {
    check_properties(pointers().map(IdentityProperty::Pointer));
    check_elements::<IdentityProperty, IdentityValue>(ids().map(IdentityValue::Id));
}

#[test]
fn push_subscription_keys_follow_their_text() {
    check_properties(pointers().map(PushSubscriptionProperty::Pointer));
    check_elements::<PushSubscriptionProperty, PushSubscriptionValue>(
        ids()
            .map(PushSubscriptionValue::Id)
            .chain(dates().map(PushSubscriptionValue::Date))
            .chain(parsed(&[
                (PushSubscriptionProperty::Types, "Email"),
                (PushSubscriptionProperty::Types, "Mailbox"),
            ])),
    );
}

#[test]
fn sieve_keys_follow_their_text() {
    check_properties(pointers().map(SieveProperty::Pointer));
    check_elements::<SieveProperty, SieveValue>(
        ids()
            .map(SieveValue::Id)
            .chain(blob_ids().map(SieveValue::BlobId))
            .chain(references().map(SieveValue::IdReference)),
    );
}

#[test]
fn static_keys_follow_their_text() {
    check_properties::<BlobProperty>([]);
    check_elements::<BlobProperty, BlobValue>(
        blob_ids()
            .map(BlobValue::BlobId)
            .chain(references().map(BlobValue::IdReference)),
    );
    check_properties::<CalendarEventNotificationProperty>([]);
    check_elements::<CalendarEventNotificationProperty, CalendarEventNotificationValue>(
        ids()
            .map(CalendarEventNotificationValue::Id)
            .chain(dates().map(CalendarEventNotificationValue::Date))
            .chain(parsed(&[
                (CalendarEventNotificationProperty::Type, "created"),
                (CalendarEventNotificationProperty::Type, "destroyed"),
            ])),
    );
    check_properties::<ParticipantIdentityProperty>([]);
    check_elements::<ParticipantIdentityProperty, ParticipantIdentityValue>(
        ids().map(ParticipantIdentityValue::Id),
    );
    check_properties::<QuotaProperty>([]);
    check_elements::<QuotaProperty, QuotaValue>(
        ids()
            .map(QuotaValue::Id)
            .chain(parsed(&[(QuotaProperty::Types, "Email")])),
    );
    check_properties::<SearchSnippetProperty>([]);
    check_elements::<SearchSnippetProperty, SearchSnippetValue>(ids().map(SearchSnippetValue::Id));
    check_properties([ShareNotificationProperty::Name]);
    check_elements::<ShareNotificationProperty, ShareNotificationValue>(
        ids()
            .map(ShareNotificationValue::Id)
            .chain(dates().map(ShareNotificationValue::Date))
            .chain([DataType::Email, DataType::Calendar].map(ShareNotificationValue::ObjectType)),
    );
    check_properties::<ThreadProperty>([]);
    check_elements::<ThreadProperty, ThreadValue>(ids().map(ThreadValue::Id));
    check_properties::<VacationResponseProperty>([]);
    check_elements::<VacationResponseProperty, VacationResponseValue>(
        ids()
            .map(VacationResponseValue::Id)
            .chain(dates().map(VacationResponseValue::Date)),
    );
}

#[test]
fn registry_keys_follow_their_text() {
    let properties = (0..=u16::MAX)
        .filter_map(RegistryProperty::from_id)
        .collect::<Vec<_>>();
    assert_eq!(properties.len(), RegistryProperty::COUNT);
    let names = properties
        .iter()
        .map(EnumImpl::as_str)
        .collect::<HashSet<_>>();
    assert_eq!(names.len(), properties.len());
    for property in &properties {
        assert_eq!(RegistryProperty::parse(property.as_str()), Some(*property));
    }
    for (a, b) in properties.iter().zip(properties.iter().skip(1)) {
        assert!(a.key_eq(a), "{a:?}");
        assert!(!a.key_eq(b), "{a:?} {b:?}");
        assert!(a.key_eq_str(a.as_str()), "{a:?}");
        assert!(!a.key_eq_str(b.as_str()), "{a:?} {b:?}");
        assert_eq!(json(&Key::Property(*a)), json(a.as_str()), "{a:?}");
    }
    check_elements::<RegistryProperty, RegistryValue>(
        ids()
            .map(RegistryValue::Id)
            .chain(blob_ids().map(RegistryValue::BlobId))
            .chain(references().map(RegistryValue::IdReference)),
    );
}

fn nested_keys() -> Vec<String> {
    successors(Some(String::from("a/b")), |key| {
        Some(JsonPointer::<Null>::encode([key.as_str(), "x"]))
    })
    .take(NESTED_LEVELS)
    .collect()
}

fn tested_levels(keys: &[String]) -> impl Iterator<Item = (usize, &String)> {
    let limit = usize::from(PointerDepth::LIMIT);
    (1..)
        .zip(keys)
        .filter(move |(levels, _)| *levels <= limit + LEVELS_PAST_LIMIT || *levels == keys.len())
}

fn innermost<P: Property>(
    property: &P,
    as_pointer: fn(&P) -> Option<&JsonPointer<P>>,
) -> (usize, String) {
    let mut levels = 0;
    let mut current = property;
    while let Some(pointer) = as_pointer(current) {
        levels += 1;
        match pointer.first() {
            Some(JsonPointerItem::Key(Key::Property(inner))) if as_pointer(inner).is_some() => {
                current = inner;
            }
            Some(JsonPointerItem::Key(key)) => return (levels, key.to_string().into_owned()),
            other => return (levels, format!("{other:?}")),
        }
    }
    (levels, String::new())
}

fn check_nesting<P: Property>(keys: &[String], as_pointer: fn(&P) -> Option<&JsonPointer<P>>) {
    let limit = usize::from(PointerDepth::LIMIT);
    for (levels, key) in tested_levels(keys) {
        let property = P::try_parse(None, key).expect("pointer key");
        let untyped = levels
            .checked_sub(limit + 1)
            .and_then(|untyped| keys.get(untyped))
            .map_or("a", String::as_str);
        assert_eq!(
            innermost(&property, as_pointer),
            (levels.min(limit), untyped.to_string()),
            "{levels} levels"
        );
        assert_eq!(property.to_cow(), key.as_str(), "{levels} levels");
    }
}

#[test]
fn nested_pointer_keys_stop_at_the_depth_limit() {
    thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(|| {
            let keys = nested_keys();
            check_nesting(&keys, <EmailProperty as MetadataProperty>::as_pointer);
            check_nesting(&keys, <MailboxProperty as MetadataProperty>::as_pointer);
            check_nesting(&keys, <AddressBookProperty as MetadataProperty>::as_pointer);
            check_nesting(&keys, <CalendarProperty as MetadataProperty>::as_pointer);
            check_nesting(&keys, <FileNodeProperty as MetadataProperty>::as_pointer);
            check_nesting(&keys, <SieveProperty as MetadataProperty>::as_pointer);
            check_nesting::<IdentityProperty>(&keys, |property| match property {
                IdentityProperty::Pointer(pointer) => Some(pointer),
                _ => None,
            });
            check_nesting::<EmailSubmissionProperty>(&keys, |property| match property {
                EmailSubmissionProperty::Pointer(pointer) => Some(pointer),
                _ => None,
            });
            check_nesting::<PushSubscriptionProperty>(&keys, |property| match property {
                PushSubscriptionProperty::Pointer(pointer) => Some(pointer),
                _ => None,
            });
            for (levels, key) in tested_levels(&keys) {
                let json = format!("{{\"{key}\":true}}");
                let update: Value<'_, EmailProperty, EmailValue> =
                    serde_json::from_str(&json).expect("parses");
                let parsed = update
                    .as_object()
                    .and_then(|object| object.keys().next())
                    .and_then(Key::as_property)
                    .expect("pointer key");
                assert_eq!(
                    innermost(parsed, <EmailProperty as MetadataProperty>::as_pointer).0,
                    levels.min(usize::from(PointerDepth::LIMIT)),
                    "{levels} levels"
                );
            }
        })
        .expect("spawns")
        .join()
        .expect("finishes");
}
