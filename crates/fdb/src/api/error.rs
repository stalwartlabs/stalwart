/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::wire::Dialect;
use std::{fmt, io, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ErrorCode(u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error {
    code: ErrorCode,
}

const _: () = assert!(size_of::<Error>() <= 4);

#[derive(Debug)]
pub enum OpenError {
    NoRuntime,
    ClusterFileNotFound,
    ClusterFileRead { path: PathBuf, kind: io::ErrorKind },
    ClusterFileInvalid { path: PathBuf, reason: Box<str> },
    Tls { reason: Box<str> },
    InvalidOption { reason: Box<str> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectError {
    pub phase: ConnectPhase,
    pub address: Option<Box<str>>,
    pub error: Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectPhase {
    Resolve,
    Connect,
    TlsHandshake,
    PeerVerification,
    Protocol,
    Coordinator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backoff {
    Growing,
    ResourceConstrained,
    FutureVersion,
    Immediate,
}

macro_rules! error_codes {
    ($($name:ident = $code:literal, $label:literal, $message:literal;)*) => {
        impl ErrorCode {
            $(pub const $name: ErrorCode = ErrorCode($code);)*

            pub fn name(self) -> &'static str {
                match self.0 {
                    $($code => $label,)*
                    _ => "unknown_error",
                }
            }

            pub fn message(self) -> &'static str {
                match self.0 {
                    $($code => $message,)*
                    _ => "An unknown error occurred",
                }
            }
        }
    };
}

error_codes! {
    OPERATION_FAILED = 1000, "operation_failed", "Operation failed";
    WRONG_SHARD_SERVER = 1001, "wrong_shard_server", "Shard is not available from this server";
    ALL_ALTERNATIVES_FAILED = 1006, "all_alternatives_failed", "All alternatives failed";
    TRANSACTION_TOO_OLD = 1007, "transaction_too_old", "Transaction is too old to perform reads or be committed";
    FUTURE_VERSION = 1009, "future_version", "Request for future version";
    NOT_COMMITTED = 1020, "not_committed", "Transaction not committed due to conflict with another transaction";
    COMMIT_UNKNOWN_RESULT = 1021, "commit_unknown_result", "Transaction may or may not have committed";
    TRANSACTION_CANCELLED = 1025, "transaction_cancelled", "Operation aborted because the transaction was cancelled";
    CONNECTION_FAILED = 1026, "connection_failed", "Network connection failed";
    REQUEST_MAYBE_DELIVERED = 1030, "request_maybe_delivered", "Request may or may not have been delivered";
    TRANSACTION_TIMED_OUT = 1031, "transaction_timed_out", "Operation aborted because the transaction timed out";
    PROCESS_BEHIND = 1037, "process_behind", "Storage process does not have recent mutations";
    DATABASE_LOCKED = 1038, "database_locked", "Database is locked";
    CLUSTER_VERSION_CHANGED = 1039, "cluster_version_changed", "The protocol version of the cluster has changed";
    COMMIT_PROXY_MEMORY_LIMIT_EXCEEDED = 1042, "commit_proxy_memory_limit_exceeded", "CommitProxy commit memory limit exceeded";
    BATCH_TRANSACTION_THROTTLED = 1051, "batch_transaction_throttled", "Batch GRV request rate limit exceeded";
    GRV_PROXY_MEMORY_LIMIT_EXCEEDED = 1078, "grv_proxy_memory_limit_exceeded", "GetReadVersion proxy memory limit exceeded";
    BROKEN_PROMISE = 1100, "broken_promise", "Broken promise";
    OPERATION_CANCELLED = 1101, "operation_cancelled", "Asynchronous operation cancelled";
    SERVER_OVERLOADED = 1211, "server_overloaded", "Server is under too much load and cannot respond";
    TAG_THROTTLED = 1213, "tag_throttled", "Transaction tag is being throttled";
    PROXY_TAG_THROTTLED = 1223, "proxy_tag_throttled", "Exceeded maximum proxy tag throttling duration";
    TRANSACTION_THROTTLED_HOT_SHARD = 1235, "transaction_throttled_hot_shard", "Transaction throttled due to hot shard";
    TRANSACTION_REJECTED_RANGE_LOCKED = 1242, "transaction_rejected_range_locked", "Transaction rejected due to range lock";
    FINISH_MOVE_KEYS_TOO_MANY_RETRIES = 1249, "finish_move_keys_too_many_retries", "finishMoveKeys exceeded retry limit";
    TRANSACTION_GRV_QUEUE_REJECTED = 1251, "transaction_grv_queue_rejected", "GRV request rejected because estimated queue wait exceeds transaction limit";
    PLATFORM_ERROR = 1500, "platform_error", "Platform error";
    IO_ERROR = 1510, "io_error", "Disk i/o operation failed";
    FILE_NOT_FOUND = 1511, "file_not_found", "File not found";
    NO_CLUSTER_FILE_FOUND = 1515, "no_cluster_file_found", "No cluster file found in current directory or default location";
    CLIENT_INVALID_OPERATION = 2000, "client_invalid_operation", "Invalid API call";
    KEY_OUTSIDE_LEGAL_RANGE = 2004, "key_outside_legal_range", "Key outside legal range";
    INVERTED_RANGE = 2005, "inverted_range", "Range begin key larger than end key";
    INVALID_OPTION_VALUE = 2006, "invalid_option_value", "Option set with an invalid value";
    VERSION_INVALID = 2011, "version_invalid", "Version not valid";
    INCOMPATIBLE_PROTOCOL_VERSION = 2100, "incompatible_protocol_version", "Incompatible protocol version";
    TRANSACTION_TOO_LARGE = 2101, "transaction_too_large", "Transaction exceeds byte limit";
    KEY_TOO_LARGE = 2102, "key_too_large", "Key length exceeds limit";
    VALUE_TOO_LARGE = 2103, "value_too_large", "Value length exceeds limit";
    CONNECTION_STRING_INVALID = 2104, "connection_string_invalid", "Connection string invalid";
    TLS_ERROR = 2107, "tls_error", "TLS error";
    UNKNOWN_ERROR = 4000, "unknown_error", "An unknown error occurred";
    INTERNAL_ERROR = 4100, "internal_error", "An internal error occurred";
    PERMISSION_DENIED = 6000, "permission_denied", "Client tried to access unauthorized data";
}

impl ErrorCode {
    pub const fn new(code: u16) -> Self {
        ErrorCode(code)
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    pub(crate) const fn from_wire(dialect: Dialect, code: u16) -> Self {
        match (dialect, code) {
            (Dialect::V73, 1235) => ErrorCode::FINISH_MOVE_KEYS_TOO_MANY_RETRIES,
            _ => ErrorCode(code),
        }
    }

    pub(crate) const fn from_grv_wire(dialect: Dialect, code: u16) -> Self {
        match (dialect, code) {
            (Dialect::V71, 1042) => ErrorCode::GRV_PROXY_MEMORY_LIMIT_EXCEEDED,
            _ => ErrorCode::from_wire(dialect, code),
        }
    }

    pub const fn is_maybe_committed(self) -> bool {
        matches!(self.0, 1021 | 1039)
    }

    pub const fn is_retryable_not_committed(self) -> bool {
        matches!(
            self.0,
            1020 | 1007 | 1009 | 1038 | 1078 | 1042 | 1235 | 1051 | 1037 | 1213 | 1223 | 1242
        )
    }

    pub const fn is_retryable(self) -> bool {
        self.is_maybe_committed() || self.is_retryable_not_committed()
    }

    pub(crate) const fn backoff(self) -> Option<Backoff> {
        match self.0 {
            1020 | 1021 | 1038 | 1037 | 1051 | 1213 | 1223 => Some(Backoff::Growing),
            1042 | 1078 | 1235 | 1242 => Some(Backoff::ResourceConstrained),
            1007 | 1009 => Some(Backoff::FutureVersion),
            1039 => Some(Backoff::Immediate),
            _ => None,
        }
    }
}

impl Error {
    pub const fn new(code: ErrorCode) -> Self {
        Error { code }
    }

    pub const fn from_code(code: i32) -> Self {
        Error {
            code: if code == 0 {
                ErrorCode::CLIENT_INVALID_OPERATION
            } else if code > 0 && code <= u16::MAX as i32 {
                ErrorCode(code as u16)
            } else {
                ErrorCode::UNKNOWN_ERROR
            },
        }
    }

    pub const fn error_code(&self) -> ErrorCode {
        self.code
    }

    pub const fn code(&self) -> i32 {
        self.code.0 as i32
    }

    pub fn name(&self) -> &'static str {
        self.code.name()
    }

    pub fn message(&self) -> &'static str {
        self.code.message()
    }

    pub const fn is_retryable(&self) -> bool {
        self.code.is_retryable()
    }

    pub const fn is_retryable_not_committed(&self) -> bool {
        self.code.is_retryable_not_committed()
    }

    pub const fn is_maybe_committed(&self) -> bool {
        self.code.is_maybe_committed()
    }
}

impl From<ErrorCode> for Error {
    fn from(code: ErrorCode) -> Self {
        Error { code }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code.message(), self.code.0)
    }
}

impl std::error::Error for Error {}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::NoRuntime => f.write_str("no Tokio runtime is running"),
            OpenError::ClusterFileNotFound => {
                f.write_str(ErrorCode::NO_CLUSTER_FILE_FOUND.message())
            }
            OpenError::ClusterFileRead { path, kind } => {
                write!(f, "failed to read cluster file {}: {kind}", path.display())
            }
            OpenError::ClusterFileInvalid { path, reason } => {
                write!(f, "invalid cluster file {}: {reason}", path.display())
            }
            OpenError::Tls { reason } => write!(f, "invalid TLS configuration: {reason}"),
            OpenError::InvalidOption { reason } => write!(f, "invalid option: {reason}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self.phase {
            ConnectPhase::Resolve => "resolving",
            ConnectPhase::Connect => "connecting to",
            ConnectPhase::TlsHandshake => "TLS handshake with",
            ConnectPhase::PeerVerification => "verifying",
            ConnectPhase::Protocol => "negotiating the protocol with",
            ConnectPhase::Coordinator => "waiting for cluster information from",
        };
        match &self.address {
            Some(address) => write!(f, "{phase} {address}: {}", self.error),
            None => write!(f, "{phase} the cluster: {}", self.error),
        }
    }
}

impl std::error::Error for ConnectError {}

pub type Result<T, E = Error> = std::result::Result<T, E>;
