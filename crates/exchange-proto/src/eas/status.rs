/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Status(pub u16);

macro_rules! status_type {
    ($name:ident { $( $konst:ident = $value:literal ),* $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub u16);

        impl $name {
            $( pub const $konst: $name = $name($value); )*

            pub const fn code(self) -> u16 {
                self.0
            }
        }

        impl From<$name> for Status {
            fn from(status: $name) -> Status {
                Status(status.0)
            }
        }

        impl From<CommonStatus> for $name {
            fn from(status: CommonStatus) -> $name {
                $name(status.0)
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommonStatus(pub u16);

impl CommonStatus {
    pub const INVALID_CONTENT: Self = Self(101);
    pub const INVALID_WBXML: Self = Self(102);
    pub const INVALID_XML: Self = Self(103);
    pub const INVALID_DATE_TIME: Self = Self(104);
    pub const INVALID_COMBINATION_OF_IDS: Self = Self(105);
    pub const INVALID_IDS: Self = Self(106);
    pub const INVALID_MIME: Self = Self(107);
    pub const DEVICE_ID_MISSING_OR_INVALID: Self = Self(108);
    pub const DEVICE_TYPE_MISSING_OR_INVALID: Self = Self(109);
    pub const SERVER_ERROR: Self = Self(110);
    pub const SERVER_ERROR_RETRY_LATER: Self = Self(111);
    pub const ACTIVE_DIRECTORY_ACCESS_DENIED: Self = Self(112);
    pub const MAILBOX_QUOTA_EXCEEDED: Self = Self(113);
    pub const MAILBOX_SERVER_OFFLINE: Self = Self(114);
    pub const SEND_QUOTA_EXCEEDED: Self = Self(115);
    pub const MESSAGE_RECIPIENT_UNRESOLVED: Self = Self(116);
    pub const MESSAGE_REPLY_NOT_ALLOWED: Self = Self(117);
    pub const MESSAGE_PREVIOUSLY_SENT: Self = Self(118);
    pub const MESSAGE_HAS_NO_RECIPIENT: Self = Self(119);
    pub const MAIL_SUBMISSION_FAILED: Self = Self(120);
    pub const MESSAGE_REPLY_FAILED: Self = Self(121);
    pub const ATTACHMENT_IS_TOO_LARGE: Self = Self(122);
    pub const USER_HAS_NO_MAILBOX: Self = Self(123);
    pub const USER_CANNOT_BE_ANONYMOUS: Self = Self(124);
    pub const USER_PRINCIPAL_COULD_NOT_BE_FOUND: Self = Self(125);
    pub const USER_DISABLED_FOR_SYNC: Self = Self(126);
    pub const USER_ON_NEW_MAILBOX_CANNOT_SYNC: Self = Self(127);
    pub const USER_ON_LEGACY_MAILBOX_CANNOT_SYNC: Self = Self(128);
    pub const DEVICE_IS_BLOCKED_FOR_THIS_USER: Self = Self(129);
    pub const ACCESS_DENIED: Self = Self(130);
    pub const ACCOUNT_DISABLED: Self = Self(131);
    pub const SYNC_STATE_NOT_FOUND: Self = Self(132);
    pub const SYNC_STATE_LOCKED: Self = Self(133);
    pub const SYNC_STATE_CORRUPT: Self = Self(134);
    pub const SYNC_STATE_ALREADY_EXISTS: Self = Self(135);
    pub const SYNC_STATE_VERSION_INVALID: Self = Self(136);
    pub const COMMAND_NOT_SUPPORTED: Self = Self(137);
    pub const VERSION_NOT_SUPPORTED: Self = Self(138);
    pub const DEVICE_NOT_FULLY_PROVISIONABLE: Self = Self(139);
    pub const REMOTE_WIPE_REQUESTED: Self = Self(140);
    pub const LEGACY_DEVICE_ON_STRICT_POLICY: Self = Self(141);
    pub const DEVICE_NOT_PROVISIONED: Self = Self(142);
    pub const POLICY_REFRESH: Self = Self(143);
    pub const INVALID_POLICY_KEY: Self = Self(144);
    pub const EXTERNALLY_MANAGED_DEVICES_NOT_ALLOWED: Self = Self(145);
    pub const NO_RECURRENCE_IN_CALENDAR: Self = Self(146);
    pub const UNEXPECTED_ITEM_CLASS: Self = Self(147);
    pub const REMOTE_SERVER_HAS_NO_SSL: Self = Self(148);
    pub const INVALID_STORED_REQUEST: Self = Self(149);
    pub const ITEM_NOT_FOUND: Self = Self(150);
    pub const TOO_MANY_FOLDERS: Self = Self(151);
    pub const NO_FOLDERS_FOUND: Self = Self(152);
    pub const ITEMS_LOST_AFTER_MOVE: Self = Self(153);
    pub const FAILURE_IN_MOVE_OPERATION: Self = Self(154);
    pub const MOVE_COMMAND_DISALLOWED_FOR_NON_PERSISTENT_MOVE_ACTION: Self = Self(155);
    pub const MOVE_COMMAND_INVALID_DESTINATION_FOLDER: Self = Self(156);
    pub const AVAILABILITY_TOO_MANY_RECIPIENTS: Self = Self(160);
    pub const AVAILABILITY_DL_LIMIT_REACHED: Self = Self(161);
    pub const AVAILABILITY_TRANSIENT_FAILURE: Self = Self(162);
    pub const AVAILABILITY_FAILURE: Self = Self(163);
    pub const BODY_PART_PREFERENCE_TYPE_NOT_SUPPORTED: Self = Self(164);
    pub const DEVICE_INFORMATION_REQUIRED: Self = Self(165);
    pub const INVALID_ACCOUNT_ID: Self = Self(166);
    pub const ACCOUNT_SEND_DISABLED: Self = Self(167);
    pub const IRM_FEATURE_DISABLED: Self = Self(168);
    pub const IRM_TRANSIENT_ERROR: Self = Self(169);
    pub const IRM_PERMANENT_ERROR: Self = Self(170);
    pub const IRM_INVALID_TEMPLATE_ID: Self = Self(171);
    pub const IRM_OPERATION_NOT_PERMITTED: Self = Self(172);
    pub const NO_PICTURE: Self = Self(173);
    pub const PICTURE_TOO_LARGE: Self = Self(174);
    pub const PICTURE_LIMIT_REACHED: Self = Self(175);
    pub const BODY_PART_CONVERSATION_TOO_LARGE: Self = Self(176);
    pub const MAXIMUM_DEVICES_REACHED: Self = Self(177);
    pub const INVALID_MIME_BODY_COMBINATION: Self = Self(178);
    pub const INVALID_SMART_FORWARD_PARAMETERS: Self = Self(179);
    pub const INVALID_RECIPIENTS: Self = Self(183);
    pub const ONE_OR_MORE_EXCEPTIONS_FAILED: Self = Self(184);

    pub const fn code(self) -> u16 {
        self.0
    }

    pub const fn is_provisioning(self) -> bool {
        matches!(self.0, 139..=145)
    }
}

impl From<CommonStatus> for Status {
    fn from(status: CommonStatus) -> Status {
        Status(status.0)
    }
}

status_type!(SyncStatus {
    SUCCESS = 1,
    INVALID_SYNC_KEY = 3,
    PROTOCOL_ERROR = 4,
    SERVER_ERROR = 5,
    CONVERSION_ERROR = 6,
    CONFLICT = 7,
    OBJECT_NOT_FOUND = 8,
    CANNOT_COMPLETE = 9,
    FOLDER_HIERARCHY_CHANGED = 12,
    INCOMPLETE_REQUEST = 13,
    INVALID_WAIT_OR_HEARTBEAT = 14,
    TOO_MANY_COLLECTIONS = 15,
    RETRY = 16,
});

status_type!(FolderStatus {
    SUCCESS = 1,
    ALREADY_EXISTS = 2,
    SPECIAL_FOLDER = 3,
    NOT_FOUND = 4,
    PARENT_NOT_FOUND = 5,
    SERVER_ERROR = 6,
    INVALID_SYNC_KEY = 9,
    MALFORMED_REQUEST = 10,
    UNKNOWN_ERROR = 11,
    CODE_UNKNOWN = 12,
});

status_type!(GetItemEstimateStatus {
    SUCCESS = 1,
    INVALID_COLLECTION = 2,
    NOT_PRIMED = 3,
    INVALID_SYNC_KEY = 4,
});

status_type!(ItemOperationsStatus {
    SUCCESS = 1,
    PROTOCOL_ERROR = 2,
    SERVER_ERROR = 3,
    BAD_URI = 4,
    DOCUMENT_ACCESS_DENIED = 5,
    NOT_FOUND = 6,
    CONNECTION_FAILED = 7,
    INVALID_RANGE = 8,
    UNKNOWN_STORE = 9,
    EMPTY_FILE = 10,
    TOO_LARGE = 11,
    IO_FAILURE = 12,
    CONVERSION_FAILED = 14,
    ATTACHMENT_FETCH_FAILED = 15,
    ACCESS_DENIED = 16,
    PARTIAL_SUCCESS = 17,
    CREDENTIALS_REQUIRED = 18,
});

status_type!(MeetingResponseStatus {
    SUCCESS = 1,
    INVALID_REQUEST = 2,
    MAILBOX_ERROR = 3,
    SERVER_ERROR = 4,
});

status_type!(MoveItemsStatus {
    INVALID_SOURCE = 1,
    INVALID_DESTINATION = 2,
    SUCCESS = 3,
    SAME_FOLDER = 4,
    MULTIPLE_DESTINATIONS_OR_LOCKED = 5,
    LOCKED = 7,
});

status_type!(PingStatus {
    EXPIRED = 1,
    CHANGES = 2,
    MISSING_PARAMETERS = 3,
    SYNTAX_ERROR = 4,
    INVALID_HEARTBEAT = 5,
    TOO_MANY_FOLDERS = 6,
    FOLDER_SYNC_REQUIRED = 7,
    SERVER_ERROR = 8,
});

status_type!(ProvisionStatus {
    SUCCESS = 1,
    PROTOCOL_ERROR = 2,
    SERVER_ERROR = 3,
});

status_type!(PolicyStatus {
    SUCCESS = 1,
    NO_POLICY = 2,
    UNKNOWN_POLICY_TYPE = 3,
    CORRUPT_POLICY = 4,
    WRONG_POLICY_KEY = 5,
});

status_type!(ResolveRecipientsStatus {
    SUCCESS = 1,
    AMBIGUOUS = 2,
    AMBIGUOUS_PARTIAL = 3,
    NOT_RESOLVED = 4,
    PROTOCOL_ERROR = 5,
    SERVER_ERROR = 6,
    CERTIFICATE_INVALID = 7,
    CERTIFICATE_LIMIT = 8,
    AVAILABILITY_TRANSIENT_FAILURE = 162,
    AVAILABILITY_FAILURE = 163,
});

status_type!(SearchStatus {
    SUCCESS = 1,
    INVALID_REQUEST = 2,
    SERVER_ERROR = 3,
    BAD_LINK = 4,
    ACCESS_DENIED = 5,
    NOT_FOUND = 6,
    CONNECTION_FAILED = 7,
    TOO_COMPLEX = 8,
    TIMED_OUT = 10,
    FOLDER_SYNC_REQUIRED = 11,
    END_OF_RANGE = 12,
    ACCESS_BLOCKED = 13,
    CREDENTIALS_REQUIRED = 14,
});

status_type!(PictureStatus {
    SUCCESS = 1,
    NO_PICTURE = 173,
    TOO_LARGE = 174,
    LIMIT_REACHED = 175,
});

status_type!(FindStatus {
    SUCCESS = 1,
    INVALID_REQUEST = 2,
    FOLDER_SYNC_REQUIRED = 3,
    START_WITH_RANGE_ZERO = 4,
});

status_type!(SettingsStatus {
    SUCCESS = 1,
    PROTOCOL_ERROR = 2,
    ACCESS_DENIED = 3,
    SERVER_UNAVAILABLE = 4,
    INVALID_ARGUMENTS = 5,
    CONFLICTING_ARGUMENTS = 6,
    DENIED_BY_POLICY = 7,
});

status_type!(ValidateCertStatus {
    SUCCESS = 1,
    PROTOCOL_ERROR = 2,
    INVALID_SIGNATURE = 3,
    UNTRUSTED_SOURCE = 4,
    INVALID_CHAIN = 5,
    NOT_FOR_EMAIL = 6,
    EXPIRED = 7,
    INCONSISTENT_TIMES = 8,
    MISUSED = 9,
    MISSING_INFORMATION = 10,
    MISUSED_END_ENTITY = 11,
    WRONG_ADDRESS = 12,
    REVOKED = 13,
    REVOCATION_UNKNOWN = 14,
    CHAIN_REVOKED = 15,
    CANNOT_VALIDATE = 16,
    SERVER_ERROR = 17,
});

status_type!(BodyPartStatus {
    SUCCESS = 1,
    TOO_LARGE = 176,
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpOutcome {
    BadRequest,
    Unauthorized,
    Forbidden,
    Redirect { location: Box<str> },
    Blocked,
    PasswordExpired { credential_service_url: Box<str> },
    ServerError,
    NotImplemented,
    ServiceUnavailable { retry_after: Option<u32> },
    MailboxFull,
}

impl HttpOutcome {
    pub fn status_code(&self) -> u16 {
        match self {
            HttpOutcome::BadRequest => 400,
            HttpOutcome::Unauthorized => 401,
            HttpOutcome::Forbidden => 403,
            HttpOutcome::Redirect { .. } => 451,
            HttpOutcome::Blocked => 456,
            HttpOutcome::PasswordExpired { .. } => 457,
            HttpOutcome::ServerError => 500,
            HttpOutcome::NotImplemented => 501,
            HttpOutcome::ServiceUnavailable { .. } => 503,
            HttpOutcome::MailboxFull => 507,
        }
    }

    pub fn header(&self) -> Option<(&'static str, HeaderValue<'_>)> {
        match self {
            HttpOutcome::Redirect { location } => {
                Some(("X-MS-Location", HeaderValue::Text(location)))
            }
            HttpOutcome::PasswordExpired {
                credential_service_url,
            } => Some((
                "X-MS-Credential-Service-Url",
                HeaderValue::Text(credential_service_url),
            )),
            HttpOutcome::ServiceUnavailable {
                retry_after: Some(seconds),
            } => Some(("Retry-After", HeaderValue::Seconds(*seconds))),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderValue<'x> {
    Text(&'x str),
    Seconds(u32),
}
