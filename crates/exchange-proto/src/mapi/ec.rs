/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub u32);

macro_rules! error_codes {
    ($($name:ident = $value:literal, $text:literal;)*) => {
        impl ErrorCode {
            $(pub const $name: Self = ErrorCode($value);)*

            pub fn name(self) -> Option<&'static str> {
                match self.0 {
                    $($value => Some($text),)*
                    _ => None,
                }
            }
        }
    };
}

error_codes! {
    SUCCESS = 0x0000_0000, "ecNone";
    UNBIND_FAILURE = 0x0000_0002, "UnbindFailure";
    SERVER_OOM = 0x0000_03F0, "ecServerOOM";
    UNKNOWN_USER = 0x0000_03EB, "ecUnknownUser";
    UNKNOWN_CODE_PAGE = 0x0000_03EF, "ecUnknownCodePage";
    LOGIN_PERM = 0x0000_03F2, "ecLoginPerm";
    PARAMETER_OVERFLOW = 0x0000_0450, "ecParameterOverflow";
    HAVE_MORE = 0x0000_0453, "ecHaveMore";
    SEARCH_FOLDER = 0x0000_0460, "ecSearchFolder";
    NOT_SEARCH_FOLDER = 0x0000_0461, "ecNotSearchFolder";
    NO_RECEIVE_FOLDER = 0x0000_0463, "ecNoReceiveFolder";
    WRONG_SERVER = 0x0000_0478, "ecWrongServer";
    BUFFER_TOO_SMALL = 0x0000_047D, "ecBufferTooSmall";
    SERVER_PAUSED = 0x0000_047F, "ecServerPaused";
    SERVER_BUSY = 0x0000_0480, "ecServerBusy";
    SEARCH_FOLDER_SCOPE_VIOLATION = 0x0000_0490, "ecSearchFolderScopeViolation";
    RPC_FORMAT = 0x0000_04B6, "ecRpcFormat";
    NULL_OBJECT = 0x0000_04B9, "ecNullObject";
    QUOTA_EXCEEDED = 0x0000_04D9, "ecQuotaExceeded";
    MAX_ATTACHMENT_EXCEEDED = 0x0000_04DB, "ecMaxAttachmentExceeded";
    TOO_MANY_OPEN_OBJECTS = 0x0000_04DE, "ecTooManyOpenObjects";
    CLIENT_VER_DISALLOWED = 0x0000_04DF, "ecClientVerDisallowed";
    RPC_HTTP_DISALLOWED = 0x0000_04E0, "ecRpcHttpDisallowed";
    CACHED_MODE_REQUIRED = 0x0000_04E1, "ecCachedModeRequired";
    FORMAT_ERROR = 0x0000_04ED, "ecFormatError";
    NOT_EXPANDED = 0x0000_04F7, "ecNotExpanded";
    NOT_COLLAPSED = 0x0000_04F8, "ecNotCollapsed";
    UNREGISTERED_NAME_PROP = 0x0000_04FA, "ecUnregisteredNameProp";
    DST_NULL_OBJECT = 0x0000_0503, "ecDstNullObject";
    MSG_CYCLE = 0x0000_0504, "ecMsgCycle";
    MAILBOX_IN_TRANSIT = 0x0000_050C, "ecMailboxInTransit";
    PROTOCOL_DISABLED = 0x0000_07D8, "ecProtocolDisabled";
    REJECTED = 0x0000_07EE, "ecRejected";
    NOT_ENCRYPTED = 0x0000_0970, "ecNotEncrypted";
    WARN_WITH_ERRORS = 0x0004_0380, "ecWarnWithErrors";
    POSITION_CHANGED = 0x0004_0481, "PositionChanged";
    STREAM_ACCESS_DENIED = 0x8003_0005, "StreamAccessDenied";
    STREAM_SEEK_ERROR = 0x8003_0019, "StreamSeekError";
    STREAM_INVALID_PARAM = 0x8003_0057, "StreamInvalidParam";
    ERROR = 0x8000_4005, "ecError";
    NOT_SUPPORTED = 0x8004_0102, "ecNotSupported";
    INVALID_OBJECT = 0x8004_0108, "ecInvalidObject";
    OBJECT_MODIFIED = 0x8004_0109, "ecObjectModified";
    OBJECT_DELETED = 0x8004_010A, "ecObjectDeleted";
    BUSY = 0x8004_010B, "ecBusy";
    NOT_FOUND = 0x8004_010F, "ecNotFound";
    VERSION_MISMATCH = 0x8004_0110, "ecVersionMismatch";
    LOGIN_FAILURE = 0x8004_0111, "ecLoginFailure";
    UNABLE_TO_ABORT = 0x8004_0114, "ecUnableToAbort";
    RPC_FAILED = 0x8004_0115, "ecRpcFailed";
    TOO_COMPLEX = 0x8004_0117, "ecTooComplex";
    COMPUTED = 0x8004_011A, "ecComputed";
    BAD_VALUE = 0x8004_0301, "ecBadValue";
    INVALID_TYPE = 0x8004_0302, "ecInvalidType";
    UNSUPPORTED_TYPE = 0x8004_0303, "ecUnsupportedType";
    UNEXPECTED_TYPE = 0x8004_0304, "ecUnexpectedType";
    TOO_BIG = 0x8004_0305, "ecTooBig";
    DECLINE_COPY = 0x8004_0306, "ecDeclineCopy";
    UNEXPECTED_ID = 0x8004_0307, "ecUnexpectedId";
    TABLE_EMPTY = 0x8004_0402, "ecTableEmpty";
    INVALID_BOOKMARK = 0x8004_0405, "ecInvalidBookmark";
    DUPLICATE_NAME = 0x8004_0604, "ecDuplicateName";
    NOT_INITIALIZED = 0x8004_0605, "ecNotInitialized";
    NO_RECIPIENTS = 0x8004_0607, "ecNoRecipients";
    HAS_FOLDERS = 0x8004_0609, "HasFolders";
    HAS_MESSAGES = 0x8004_060A, "HasMessages";
    FOLDER_CYCLE = 0x8004_060B, "FolderCycle";
    NAMED_PROPERTY_QUOTA = 0x8004_0900, "NamedPropertyQuota";
    NOT_IMPLEMENTED = 0x8004_0FFF, "NotImplemented";
    ACCESS_DENIED = 0x8007_0005, "ecAccessDenied";
    NOT_ENOUGH_MEMORY = 0x8007_000E, "ecNotEnoughMemory";
    INVALID_PARAM = 0x8007_0057, "ecInvalidParam";
    SYNC_CONFLICT = 0x8004_0802, "SyncConflict";
    SYNC_IGNORE = 0x8004_0801, "IgnoreFailure";
    SYNC_OBJECT_DELETED = 0x8004_0800, "SyncObjectDeleted";
    SYNC_NO_PARENT = 0x8004_0803, "NoParentFolder";
    SYNC_INCEST = 0x8004_0804, "CycleDetected";
    SYNC_PROGRESS = 0x0004_0820, "SyncProgress";
    SYNC_CLIENT_CHANGE_NEWER = 0x0004_0821, "NewerClientChange";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusCode(pub u32);

impl StatusCode {
    pub const OK: Self = StatusCode(0);
    pub const BUFFER_TOO_SMALL: Self = StatusCode(0x0000_047D);
    pub const SERVER_TOO_BUSY: Self = StatusCode(0x0000_06BB);
    pub const BAD_STUB_DATA: Self = StatusCode(0x0000_06F7);
}
