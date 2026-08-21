use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use calcard::icalendar::ICalendarDuration;
use common::config::smtp::queue::{DEFAULT_QUEUE_NAME, QueueExpiry};
use email::{
    identity::{EmailAddress, Identity},
    mailbox::Mailbox,
    push::{EmailPush, Keys, PushSubscription, PushSubscriptions, Urgency},
    submission::{Address, Delivered, DeliveryStatus, EmailSubmission, Envelope, UndoStatus},
};
use groupware::{
    calendar::{
        ALERT_EMAIL, ALERT_RELATIVE_TO_END, ALERT_WITH_TIME, Calendar, CalendarPreferences,
        DefaultAlert, ParticipantIdentities, ParticipantIdentity, Timezone,
    },
    contact::{AddressBook, AddressBookPreferences},
    file::{FileNode, FileProperties},
};
use smtp::queue::{
    Error as QueueError, ErrorDetails, HostResponse, Message, Metadata, Recipient, Schedule, Status,
    UnexpectedResponse,
};
use smtp_proto::Response;
use types::{
    acl::{Acl, AclGrant},
    blob_hash::BlobHash,
    dead_property::{DeadElementTag, DeadProperty, DeadPropertyTag},
    special_use::SpecialUse,
    type_state::DataType,
};
use utils::map::{bitmap::Bitmap, vec_map::VecMap};

use crate::corpus::{Corpus, Rng, Stats, archive};

const DEFAULT_FOLDERS: [(&str, SpecialUse); 11] = [
    ("Inbox", SpecialUse::Inbox),
    ("Deleted Items", SpecialUse::Trash),
    ("Junk Mail", SpecialUse::Junk),
    ("Drafts", SpecialUse::Drafts),
    ("Sent Items", SpecialUse::Sent),
    ("Archive", SpecialUse::Archive),
    ("Important", SpecialUse::Important),
    ("Memos", SpecialUse::Memos),
    ("Scheduled", SpecialUse::Scheduled),
    ("Snoozed", SpecialUse::Snoozed),
    ("Shared Folders", SpecialUse::Shared),
];

const CLIENT_FOLDERS: [&str; 14] = [
    "Trash",
    "Junk",
    "Sent",
    "Spam",
    "Notes",
    "Outbox",
    "Templates",
    "Starred",
    "All Mail",
    "Archives",
    "INBOX.Drafts",
    "INBOX.Sent",
    "INBOX.Trash",
    "Deleted Messages",
];

const MEDIA_TYPES: [&str; 18] = [
    "application/pdf",
    "application/zip",
    "application/json",
    "application/octet-stream",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.oasis.opendocument.text",
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/svg+xml",
    "image/heic",
    "text/plain",
    "text/html",
    "text/csv",
    "video/mp4",
    "audio/mpeg",
];

const FILE_EXTENSIONS: [&str; 12] = [
    "pdf", "zip", "json", "docx", "xlsx", "odt", "jpg", "png", "gif", "txt", "csv", "mp4",
];

const PUSH_HOSTS: [&str; 6] = [
    "fcm.googleapis.com",
    "updates.push.services.mozilla.com",
    "web.push.apple.com",
    "wns2-par02p.notify.windows.com",
    "push.services.mozilla.com",
    "android.googleapis.com",
];

const DEAD_PROPERTY_NAMESPACES: [&str; 6] = [
    "DAV:",
    "urn:ietf:params:xml:ns:caldav",
    "urn:ietf:params:xml:ns:carddav",
    "http://apple.com/ns/ical/",
    "http://calendarserver.org/ns/",
    "http://sabredav.org/ns",
];

const DEAD_PROPERTY_NAMES: [&str; 8] = [
    "calendar-color",
    "calendar-order",
    "getctag",
    "invite",
    "allowed-sharing-modes",
    "supported-report-set",
    "owner",
    "displayname",
];

const CALENDAR_COLORS: [&str; 10] = [
    "#0252D4FF", "#711A76FF", "#F64F00FF", "#711A76", "#0D47A1", "#43A047", "#E53935", "#FB8C00",
    "#8E24AA", "#00897B",
];

const SMTP_REPLIES: [&str; 10] = [
    "250 2.0.0 Ok: queued as 4bJ8Kz1QqYz3Xn",
    "250 2.0.0 Message accepted for delivery",
    "250 2.6.0 Message accepted",
    "421 4.7.0 Too many connections from this IP",
    "450 4.2.0 Mailbox busy, try again later",
    "451 4.3.0 Temporary system problem, try again later",
    "550 5.1.1 The email account that you tried to reach does not exist",
    "550 5.7.1 Message rejected due to local policy",
    "552 5.2.2 The recipient mailbox is over quota",
    "554 5.7.1 Service unavailable; client host blocked using Spamhaus",
];

const DSN_MESSAGES: [&str; 6] = [
    "Connection refused",
    "Connection timed out",
    "No MX record found for domain",
    "TLS handshake failed: certificate verify failed",
    "DANE TLSA record verification failed",
    "MTA-STS policy requires TLS but the connection was not secured",
];

pub fn build(count: usize, stats: &mut Stats) -> Corpus {
    let mut corpus = Corpus::new();

    for index in 0..count {
        let mut rng = Rng::new(index as u64 + 1);
        let sample = match rng.below(100) {
            0..=29 => archive(&mailbox(&mut rng)),
            30..=49 => archive(&queue_message(&mut rng)),
            50..=63 => archive(&file_node(&mut rng)),
            64..=73 => archive(&submission(&mut rng)),
            74..=81 => archive(&calendar(&mut rng)),
            82..=87 => archive(&address_book(&mut rng)),
            88..=93 => archive(&identity(&mut rng)),
            94..=97 => archive(&push_subscriptions(&mut rng)),
            _ => archive(&participant_identities(&mut rng)),
        };
        corpus.push_both(sample);
        stats.read += 1;
    }

    corpus
}

fn acls(rng: &mut Rng) -> Vec<AclGrant> {
    if !rng.chance(20) {
        return Vec::new();
    }
    (0..rng.range(1, 3))
        .map(|_| {
            let mut grants = Bitmap::default();
            for acl in [
                Acl::Read,
                Acl::ReadItems,
                Acl::AddItems,
                Acl::ModifyItems,
                Acl::RemoveItems,
                Acl::Modify,
                Acl::Share,
            ] {
                if rng.chance(45) {
                    grants.insert(acl);
                }
            }
            AclGrant {
                account_id: rng.below(4096) as u32,
                grants,
            }
        })
        .collect()
}

fn subscribers(rng: &mut Rng) -> Vec<u32> {
    (0..rng.below(4)).map(|_| rng.below(4096) as u32).collect()
}

fn dead_properties(rng: &mut Rng) -> DeadProperty {
    if !rng.chance(25) {
        return DeadProperty::default();
    }

    let mut tags = Vec::new();
    for _ in 0..rng.range(1, 3) {
        let namespace = *rng.pick(&DEAD_PROPERTY_NAMESPACES);
        let name = *rng.pick(&DEAD_PROPERTY_NAMES);
        let value_len = rng.range(4, 32);
        tags.push(DeadPropertyTag::ElementStart(Box::new(DeadElementTag {
            name: format!("{namespace}:{name}"),
            attrs: rng
                .chance(30)
                .then(|| format!("xmlns:x=\"{namespace}\" xmlns:d=\"DAV:\"")),
        })));
        tags.push(DeadPropertyTag::Text(rng.token(value_len)));
        tags.push(DeadPropertyTag::ElementEnd);
    }
    DeadProperty(tags)
}

fn mailbox(rng: &mut Rng) -> Mailbox {
    let (name, role) = if rng.chance(45) {
        let (name, role) = rng.pick(&DEFAULT_FOLDERS);
        ((*name).to_string(), *role)
    } else if rng.chance(25) {
        ((*rng.pick(&CLIENT_FOLDERS)).to_string(), SpecialUse::None)
    } else {
        let len = rng.range(3, 24);
        (rng.token(len), SpecialUse::None)
    };

    Mailbox {
        name,
        role,
        parent_id: if rng.chance(70) { 0 } else { rng.below(64) as u32 },
        sort_order: rng.chance(30).then(|| rng.below(1000) as u32),
        uid_validity: rng.next_u64() as u32,
        subscribers: subscribers(rng),
        acls: acls(rng),
    }
}

fn identity(rng: &mut Rng) -> Identity {
    let name_len = rng.range(5, 30);
    let signature_len = rng.range(20, 120);
    let email = rng.address();
    let name = rng.token(name_len);
    let signature = rng.token(signature_len);

    Identity {
        name: name.clone(),
        email: email.clone(),
        reply_to: rng.chance(20).then(|| {
            vec![EmailAddress {
                name: Some(name.clone()),
                email: rng.address(),
            }]
        }),
        bcc: rng.chance(10).then(|| {
            vec![EmailAddress {
                name: None,
                email: rng.address(),
            }]
        }),
        text_signature: format!("--\r\n{name}\r\n{signature}\r\n"),
        html_signature: format!(
            "<div dir=\"ltr\"><div class=\"gmail_signature\" data-smartmail=\"gmail_signature\">\
             <p><strong>{name}</strong><br><a href=\"mailto:{email}\">{email}</a></p>\
             <p>{signature}</p></div></div>"
        ),
    }
}

fn submission(rng: &mut Rng) -> EmailSubmission {
    let mut delivery_status = VecMap::new();
    for _ in 0..rng.range(1, 4) {
        delivery_status.append(
            rng.address(),
            DeliveryStatus {
                smtp_reply: (*rng.pick(&SMTP_REPLIES)).to_string(),
                delivered: match rng.below(4) {
                    0 => Delivered::Queued,
                    1 => Delivered::Yes,
                    2 => Delivered::No,
                    _ => Delivered::Unknown,
                },
                displayed: rng.chance(5),
            },
        );
    }

    EmailSubmission {
        email_id: rng.below(1 << 20) as u32,
        thread_id: rng.below(1 << 20) as u32,
        identity_id: rng.below(16) as u32,
        send_at: 1_750_000_000 + rng.below(86400 * 365) as u64,
        queue_id: rng.chance(70).then(|| rng.next_u64()),
        undo_status: match rng.below(3) {
            0 => UndoStatus::Pending,
            1 => UndoStatus::Final,
            _ => UndoStatus::Canceled,
        },
        envelope: Envelope {
            mail_from: Address {
                email: rng.address(),
                parameters: None,
            },
            rcpt_to: (0..rng.range(1, 4))
                .map(|_| Address {
                    email: rng.address(),
                    parameters: None,
                })
                .collect(),
        },
        delivery_status,
    }
}

fn push_subscriptions(rng: &mut Rng) -> PushSubscriptions {
    PushSubscriptions {
        subscriptions: (0..rng.range(1, 3))
            .map(|index| {
                let host = *rng.pick(&PUSH_HOSTS);
                let path_len = rng.range(40, 152);
                let mut types = Bitmap::default();
                for data_type in [
                    DataType::Email,
                    DataType::EmailDelivery,
                    DataType::Mailbox,
                    DataType::Thread,
                    DataType::CalendarEvent,
                ] {
                    if rng.chance(50) {
                        types.insert(data_type);
                    }
                }
                let device_len = rng.range(16, 40);
                let code_len = 32;

                PushSubscription {
                    id: index as u32,
                    url: format!("https://{host}/{}", rng.token(path_len)),
                    device_client_id: rng.token(device_len),
                    expires: 1_750_000_000 + rng.below(86400 * 90) as u64,
                    verification_code: rng.token(code_len),
                    verified: rng.chance(80),
                    types,
                    keys: rng.chance(70).then(|| Keys {
                        p256dh: rng.bytes(65),
                        auth: rng.bytes(16),
                    }),
                    email_push: if rng.chance(20) {
                        vec![EmailPush {
                            account_id: rng.below(4096) as u32,
                            properties: Vec::new(),
                            filter: Vec::new(),
                            urgency: match rng.below(4) {
                                0 => Urgency::VeryLow,
                                1 => Urgency::Low,
                                2 => Urgency::Normal,
                                _ => Urgency::High,
                            },
                        }]
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect(),
    }
}

fn participant_identities(rng: &mut Rng) -> ParticipantIdentities {
    let default_len = rng.range(5, 30);
    ParticipantIdentities {
        identities: (0..rng.range(1, 3))
            .map(|index| {
                let name_len = rng.range(5, 30);
                ParticipantIdentity {
                    id: index as u32,
                    name: rng.chance(70).then(|| rng.token(name_len)),
                    calendar_address: format!("mailto:{}", rng.address()),
                }
            })
            .collect(),
        default_name: rng.token(default_len),
        default: 0,
    }
}

fn calendar(rng: &mut Rng) -> Calendar {
    let is_default = rng.chance(60);
    let name_len = rng.range(4, 24);
    let description_len = rng.range(10, 80);
    let created = 1_750_000_000 + rng.below(86400 * 365) as i64;

    let preferences = (0..rng.range(1, 2))
        .map(|_| CalendarPreferences {
            account_id: rng.below(4096) as u32,
            name: if is_default {
                "Stalwart Calendar".to_string()
            } else {
                rng.token(name_len)
            },
            description: rng.chance(20).then(|| rng.token(description_len)),
            sort_order: rng.below(100) as u32,
            color: rng
                .chance(70)
                .then(|| (*rng.pick(&CALENDAR_COLORS)).to_string()),
            flags: rng.below(32) as u16,
            time_zone: if rng.chance(60) {
                Timezone::Default
            } else {
                Timezone::IANA(rng.below(600) as u16)
            },
            default_alerts: (0..rng.below(3))
                .map(|_| DefaultAlert {
                    id: format!("{}-{}", rng.token(8), rng.token(12)),
                    offset: ICalendarDuration {
                        neg: true,
                        weeks: 0,
                        days: 0,
                        hours: 0,
                        minutes: *rng.pick(&[5u32, 10, 15, 30, 60]),
                        seconds: 0,
                    },
                    flags: ALERT_WITH_TIME
                        | if rng.chance(30) { ALERT_EMAIL } else { 0 }
                        | if rng.chance(10) {
                            ALERT_RELATIVE_TO_END
                        } else {
                            0
                        },
                })
                .collect(),
        })
        .collect();

    Calendar {
        name: if is_default {
            "default".to_string()
        } else {
            rng.token(name_len)
        },
        preferences,
        acls: acls(rng),
        supported_components: 0,
        dead_properties: dead_properties(rng),
        created,
        modified: created + rng.below(86400 * 30) as i64,
    }
}

fn address_book(rng: &mut Rng) -> AddressBook {
    let is_default = rng.chance(70);
    let name_len = rng.range(4, 24);
    let description_len = rng.range(10, 80);
    let created = 1_750_000_000 + rng.below(86400 * 365) as i64;

    AddressBook {
        name: if is_default {
            "default".to_string()
        } else {
            rng.token(name_len)
        },
        preferences: vec![AddressBookPreferences {
            account_id: rng.below(4096) as u32,
            name: if is_default {
                "Stalwart Address Book".to_string()
            } else {
                rng.token(name_len)
            },
            description: rng.chance(20).then(|| rng.token(description_len)),
            sort_order: rng.below(100) as u32,
        }],
        subscribers: subscribers(rng),
        dead_properties: dead_properties(rng),
        acls: acls(rng),
        created,
        modified: created + rng.below(86400 * 30) as i64,
    }
}

fn file_node(rng: &mut Rng) -> FileNode {
    let is_folder = rng.chance(20);
    let stem_len = rng.range(4, 28);
    let stem = rng.token(stem_len);
    let created = 1_750_000_000 + rng.below(86400 * 365) as i64;

    FileNode {
        parent_id: if rng.chance(40) {
            u32::MAX
        } else {
            rng.below(256) as u32
        },
        name: if is_folder {
            stem.clone()
        } else {
            format!("{stem}.{}", rng.pick(&FILE_EXTENSIONS))
        },
        display_name: rng.chance(15).then(|| stem.clone()),
        file: (!is_folder).then(|| FileProperties {
            blob_hash: BlobHash::generate(stem.as_bytes()),
            size: rng.range(512, 4 << 20) as u32,
            media_type: rng
                .chance(90)
                .then(|| (*rng.pick(&MEDIA_TYPES)).to_string()),
            executable: rng.chance(2),
        }),
        created,
        modified: created + rng.below(86400 * 30) as i64,
        dead_properties: dead_properties(rng),
        acls: acls(rng),
    }
}

fn queue_message(rng: &mut Rng) -> Message {
    let created = 1_750_000_000 + rng.below(86400 * 365) as u64;
    let return_path = rng.address();
    let hostname = format!("mx{}.{}", rng.below(4) + 1, rng.domain());

    let recipients = (0..rng.range(1, 5))
        .map(|_| {
            let address = rng.address();
            let status = match rng.below(10) {
                0..=5 => Status::Completed(Box::new(HostResponse {
                    hostname: hostname.clone().into_boxed_str(),
                    response: response(rng, 250),
                })),
                6..=7 => Status::TemporaryFailure(Box::new(ErrorDetails {
                    entity: hostname.clone().into_boxed_str(),
                    details: QueueError::ConnectionError((*rng.pick(&DSN_MESSAGES)).into()),
                })),
                8 => Status::PermanentFailure(Box::new(ErrorDetails {
                    entity: address.clone().into_boxed_str(),
                    details: QueueError::UnexpectedResponse(Box::new(UnexpectedResponse {
                        command: format!("RCPT TO:<{address}>").into_boxed_str(),
                        response: response(rng, 550),
                    })),
                })),
                _ => Status::Scheduled,
            };

            Recipient {
                address: address.into_boxed_str(),
                retry: Schedule {
                    due: created + rng.below(3600) as u64,
                    inner: rng.below(5) as u32,
                },
                notify: Schedule {
                    due: created + rng.below(86400) as u64,
                    inner: rng.below(3) as u32,
                },
                expires: if rng.chance(70) {
                    QueueExpiry::Ttl(rng.range(3600, 5 * 86400) as u64)
                } else {
                    QueueExpiry::Attempts(rng.range(1, 25) as u32)
                },
                queue: DEFAULT_QUEUE_NAME,
                status,
                flags: 0,
                orcpt: rng.chance(10).then(|| {
                    let orcpt = rng.address();
                    format!("rfc822;{orcpt}").into_boxed_str()
                }),
            }
        })
        .collect();

    Message {
        created,
        blob_hash: BlobHash::generate(return_path.as_bytes()),
        return_path: return_path.into_boxed_str(),
        recipients,
        received_from_ip: if rng.chance(80) {
            IpAddr::V4(Ipv4Addr::new(
                rng.below(256) as u8,
                rng.below(256) as u8,
                rng.below(256) as u8,
                rng.below(256) as u8,
            ))
        } else {
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                rng.below(65536) as u16,
                rng.below(65536) as u16,
                0,
                0,
                0,
                rng.below(65536) as u16,
            ))
        },
        received_via_port: *rng.pick(&[25u16, 465, 587, 11200]),
        flags: 0,
        env_id: rng.chance(10).then(|| {
            let len = rng.range(8, 32);
            rng.token(len).into_boxed_str()
        }),
        priority: 0,
        size: rng.range(1024, 4 << 20) as u64,
        metadata: metadata(rng),
    }
}

fn response(rng: &mut Rng, code: u16) -> Response<Box<str>> {
    let message = *rng.pick(&SMTP_REPLIES);
    let message = message
        .split_once(' ')
        .and_then(|(_, rest)| rest.split_once(' '))
        .map(|(_, rest)| rest)
        .unwrap_or(message);

    Response {
        code,
        esc: if code < 300 { [2, 0, 0] } else { [5, 1, 1] },
        message: message.into(),
    }
}

fn metadata(rng: &mut Rng) -> Box<[Metadata]> {
    if !rng.chance(60) {
        return Box::new([]);
    }

    let host = rng.domain();
    let client = rng.domain();
    let ip = format!("{}.{}.{}.{}", rng.below(256), rng.below(256), rng.below(256), rng.below(256));
    let id_len = 24;
    let id = rng.token(id_len);
    let headers = format!(
        "Received: from {client} ([{ip}])\r\n\tby {host} (Stalwart SMTP) with ESMTPS id {id}\r\n\t\
         (version=TLS1.3 cipher=TLS_AES_256_GCM_SHA384);\r\n\tMon, 21 Aug 2026 09:48:55 +0000\r\n"
    );

    let mut entries = vec![Metadata::Headers {
        value: headers.into_bytes().into_boxed_slice(),
        id: rng.next_u64(),
    }];
    if rng.chance(50) {
        entries.push(Metadata::QueueSize {
            key: rng.domain().into_bytes().into_boxed_slice(),
            id: rng.next_u64(),
        });
        entries.push(Metadata::QueueCount {
            key: rng.domain().into_bytes().into_boxed_slice(),
            id: rng.next_u64(),
        });
    }
    entries.into_boxed_slice()
}
