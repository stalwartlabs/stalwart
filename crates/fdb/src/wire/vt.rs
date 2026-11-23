/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::layout::{
    acknowledgement_reply, commit_transaction_request, get_key_request,
    get_key_server_locations_request, get_key_values_request, get_key_values_stream_request,
    get_read_version_request, get_value_request, open_database_coord_request, ping_request,
    protocol_info_request,
};

pub(crate) static OPEN_DATABASE_COORD_REQUEST_V71: open_database_coord_request::VtA =
    open_database_coord_request::VtA {
        block: &[
            10, 0, 16, 0, 4, 0, 8, 0, 12, 0, 10, 0, 13, 0, 4, 0, 8, 0, 12, 0, 12, 0, 13, 0, 4, 0,
            8, 0, 10, 0, 12, 0, 22, 0, 49, 0, 20, 0, 24, 0, 28, 0, 4, 0, 32, 0, 36, 0, 40, 0, 44,
            0, 48, 0, 6, 0, 20, 0, 4, 0, 8, 0, 9, 0, 8, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        ipaddress: 60,
        network_address: 20,
        reply_promise: 54,
        hostname: 10,
        open_database_coord_request: 32,
        root: 68,
    };

pub(crate) static OPEN_DATABASE_COORD_REQUEST_V73: open_database_coord_request::VtA =
    open_database_coord_request::VtA {
        block: &[
            10, 0, 13, 0, 4, 0, 8, 0, 12, 0, 12, 0, 13, 0, 4, 0, 8, 0, 10, 0, 12, 0, 10, 0, 16, 0,
            4, 0, 8, 0, 12, 0, 22, 0, 49, 0, 20, 0, 24, 0, 28, 0, 4, 0, 32, 0, 36, 0, 40, 0, 44, 0,
            48, 0, 6, 0, 20, 0, 4, 0, 8, 0, 9, 0, 8, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        ipaddress: 60,
        network_address: 10,
        reply_promise: 54,
        hostname: 0,
        open_database_coord_request: 32,
        root: 68,
    };

pub(crate) static GET_READ_VERSION_REQUEST_V71: get_read_version_request::VtA =
    get_read_version_request::VtA {
        block: &[
            8, 0, 12, 0, 4, 0, 8, 0, 20, 0, 49, 0, 28, 0, 32, 0, 36, 0, 48, 0, 40, 0, 44, 0, 4, 0,
            20, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        reply_promise: 28,
        get_read_version_request: 8,
        root: 34,
    };

pub(crate) static GET_READ_VERSION_REQUEST_V72: get_read_version_request::VtB =
    get_read_version_request::VtB {
        block: &[
            8, 0, 12, 0, 4, 0, 8, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 20, 0, 37, 0, 12, 0, 16, 0,
            20, 0, 36, 0, 24, 0, 28, 0, 32, 0, 4, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        reply_promise: 38,
        span_context: 8,
        get_read_version_request: 18,
        root: 44,
    };

pub(crate) static GET_READ_VERSION_REQUEST_V80: get_read_version_request::VtB =
    get_read_version_request::VtB {
        block: &[
            8, 0, 12, 0, 4, 0, 8, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 24, 0, 42, 0, 12, 0, 16, 0,
            20, 0, 40, 0, 24, 0, 28, 0, 32, 0, 4, 0, 41, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0,
            4, 0,
        ],
        reply_promise: 42,
        span_context: 8,
        get_read_version_request: 18,
        root: 48,
    };

pub(crate) static GET_KEY_SERVER_LOCATIONS_REQUEST_V71: get_key_server_locations_request::VtA =
    get_key_server_locations_request::VtA {
        block: &[
            24, 0, 51, 0, 28, 0, 48, 0, 32, 0, 36, 0, 49, 0, 40, 0, 4, 0, 50, 0, 44, 0, 20, 0, 6,
            0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        reply_promise: 24,
        get_key_server_locations_request: 0,
        root: 30,
    };

pub(crate) static GET_KEY_SERVER_LOCATIONS_REQUEST_V72: get_key_server_locations_request::VtB =
    get_key_server_locations_request::VtB {
        block: &[
            14, 0, 22, 0, 20, 0, 12, 0, 4, 0, 21, 0, 16, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 22,
            0, 38, 0, 12, 0, 36, 0, 16, 0, 20, 0, 37, 0, 24, 0, 28, 0, 32, 0, 4, 0, 6, 0, 20, 0, 4,
            0, 6, 0, 8, 0, 4, 0,
        ],
        reply_promise: 46,
        span_context: 14,
        tenant_info: 0,
        get_key_server_locations_request: 24,
        root: 52,
    };

pub(crate) static GET_KEY_SERVER_LOCATIONS_REQUEST_V73: get_key_server_locations_request::VtB =
    get_key_server_locations_request::VtB {
        block: &[
            10, 0, 17, 0, 4, 0, 16, 0, 12, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 22, 0, 38, 0, 12,
            0, 36, 0, 16, 0, 20, 0, 37, 0, 24, 0, 28, 0, 32, 0, 4, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8,
            0, 4, 0,
        ],
        reply_promise: 42,
        span_context: 10,
        tenant_info: 0,
        get_key_server_locations_request: 20,
        root: 48,
    };

pub(crate) static GET_KEY_SERVER_LOCATIONS_REQUEST_V80: get_key_server_locations_request::VtC =
    get_key_server_locations_request::VtC {
        block: &[
            10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 20, 0, 34, 0, 12, 0, 32, 0, 16, 0, 20, 0, 33, 0, 24,
            0, 28, 0, 4, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        reply_promise: 30,
        span_context: 0,
        get_key_server_locations_request: 10,
        root: 36,
    };

pub(crate) static GET_VALUE_REQUEST_V71: get_value_request::VtA = get_value_request::VtA {
    block: &[
        8, 0, 16, 0, 12, 0, 4, 0, 8, 0, 16, 0, 12, 0, 4, 0, 10, 0, 17, 0, 16, 0, 12, 0, 4, 0, 24,
        0, 54, 0, 28, 0, 20, 0, 52, 0, 32, 0, 53, 0, 36, 0, 40, 0, 4, 0, 44, 0, 48, 0, 6, 0, 20, 0,
        4, 0, 6, 0, 8, 0, 4, 0,
    ],
    reply_promise: 50,
    tenant_info: 16,
    version_vector: 8,
    get_value_request: 26,
    root: 56,
};

pub(crate) static GET_VALUE_REQUEST_V72: get_value_request::VtB = get_value_request::VtB {
    block: &[
        16, 0, 19, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 14, 0, 22, 0, 20, 0, 12, 0, 4, 0, 21,
        0, 16, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 24, 0, 42, 0, 12, 0, 4, 0, 40, 0, 16, 0, 20, 0,
        24, 0, 28, 0, 41, 0, 32, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
    ],
    reply_promise: 64,
    span_context: 30,
    tenant_info: 16,
    get_value_request: 40,
    root: 70,
};

pub(crate) static GET_VALUE_REQUEST_V73: get_value_request::VtB = get_value_request::VtB {
    block: &[
        18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 17, 0, 4, 0, 16, 0, 12,
        0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 24, 0, 42, 0, 12, 0, 4, 0, 40, 0, 16, 0, 20, 0, 24, 0,
        28, 0, 41, 0, 32, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
    ],
    reply_promise: 62,
    span_context: 28,
    tenant_info: 18,
    get_value_request: 38,
    root: 68,
};

pub(crate) static GET_VALUE_REQUEST_V80: get_value_request::VtC = get_value_request::VtC {
    block: &[
        18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28,
        0, 22, 0, 38, 0, 12, 0, 4, 0, 36, 0, 16, 0, 20, 0, 24, 0, 37, 0, 28, 0, 32, 0, 6, 0, 20, 0,
        4, 0, 6, 0, 8, 0, 4, 0,
    ],
    reply_promise: 50,
    span_context: 18,
    get_value_request: 28,
    root: 56,
};

pub(crate) static GET_KEY_REQUEST_V71: get_key_request::VtA = get_key_request::VtA {
    block: &[
        8, 0, 16, 0, 12, 0, 4, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8, 0, 8, 0, 16, 0, 12, 0, 4, 0, 10, 0,
        17, 0, 16, 0, 12, 0, 4, 0, 24, 0, 54, 0, 28, 0, 20, 0, 52, 0, 32, 0, 53, 0, 36, 0, 40, 0,
        4, 0, 44, 0, 48, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
    ],
    key_selector_ref: 8,
    reply_promise: 60,
    tenant_info: 26,
    version_vector: 18,
    get_key_request: 36,
    root: 66,
};

pub(crate) static GET_KEY_REQUEST_V72: get_key_request::VtB = get_key_request::VtB {
    block: &[
        16, 0, 19, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8, 0, 14,
        0, 22, 0, 20, 0, 12, 0, 4, 0, 21, 0, 16, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 24, 0, 42, 0,
        12, 0, 4, 0, 40, 0, 16, 0, 20, 0, 24, 0, 28, 0, 41, 0, 32, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6,
        0, 8, 0, 4, 0,
    ],
    key_selector_ref: 16,
    reply_promise: 74,
    span_context: 40,
    tenant_info: 26,
    get_key_request: 50,
    root: 80,
};

pub(crate) static GET_KEY_REQUEST_V73: get_key_request::VtB = get_key_request::VtB {
    block: &[
        18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8,
        0, 10, 0, 17, 0, 4, 0, 16, 0, 12, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 24, 0, 42, 0, 12, 0,
        4, 0, 40, 0, 16, 0, 20, 0, 24, 0, 28, 0, 41, 0, 32, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8,
        0, 4, 0,
    ],
    key_selector_ref: 18,
    reply_promise: 72,
    span_context: 38,
    tenant_info: 28,
    get_key_request: 48,
    root: 78,
};

pub(crate) static GET_KEY_REQUEST_V80: get_key_request::VtC = get_key_request::VtC {
    block: &[
        18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8,
        0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 22, 0, 38, 0, 12, 0, 4, 0, 36, 0, 16, 0, 20, 0, 24, 0,
        37, 0, 28, 0, 32, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
    ],
    key_selector_ref: 18,
    reply_promise: 60,
    span_context: 28,
    get_key_request: 38,
    root: 66,
};

pub(crate) static GET_KEY_VALUES_REQUEST_V71: get_key_values_request::VtA =
    get_key_values_request::VtA {
        block: &[
            8, 0, 16, 0, 12, 0, 4, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8, 0, 8, 0, 16, 0, 12, 0, 4, 0,
            10, 0, 17, 0, 16, 0, 12, 0, 4, 0, 32, 0, 67, 0, 28, 0, 32, 0, 20, 0, 36, 0, 40, 0, 64,
            0, 65, 0, 44, 0, 66, 0, 48, 0, 52, 0, 4, 0, 56, 0, 60, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8,
            0, 4, 0,
        ],
        key_selector_ref: 8,
        reply_promise: 68,
        tenant_info: 26,
        version_vector: 18,
        get_key_values_request: 36,
        root: 74,
    };

pub(crate) static GET_KEY_VALUES_REQUEST_V72: get_key_values_request::VtB =
    get_key_values_request::VtB {
        block: &[
            16, 0, 19, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8, 0,
            14, 0, 22, 0, 20, 0, 12, 0, 4, 0, 21, 0, 16, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 30,
            0, 54, 0, 12, 0, 16, 0, 4, 0, 20, 0, 24, 0, 52, 0, 28, 0, 32, 0, 36, 0, 40, 0, 53, 0,
            44, 0, 48, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_selector_ref: 16,
        reply_promise: 80,
        span_context: 40,
        tenant_info: 26,
        get_key_values_request: 50,
        root: 86,
    };

pub(crate) static GET_KEY_VALUES_REQUEST_V73: get_key_values_request::VtB =
    get_key_values_request::VtB {
        block: &[
            18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 13, 0, 4, 0, 12, 0,
            8, 0, 10, 0, 17, 0, 4, 0, 16, 0, 12, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 30, 0, 54, 0,
            12, 0, 16, 0, 4, 0, 20, 0, 24, 0, 52, 0, 28, 0, 32, 0, 36, 0, 40, 0, 53, 0, 44, 0, 48,
            0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_selector_ref: 18,
        reply_promise: 78,
        span_context: 38,
        tenant_info: 28,
        get_key_values_request: 48,
        root: 84,
    };

pub(crate) static GET_KEY_VALUES_REQUEST_V80: get_key_values_request::VtC =
    get_key_values_request::VtC {
        block: &[
            18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 13, 0, 4, 0, 12, 0,
            8, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 32, 0, 55, 0, 12, 0, 16, 0, 4, 0, 20, 0, 24, 0,
            52, 0, 28, 0, 32, 0, 36, 0, 53, 0, 40, 0, 44, 0, 54, 0, 48, 0, 6, 0, 20, 0, 4, 0, 6, 0,
            8, 0, 4, 0,
        ],
        key_selector_ref: 18,
        reply_promise: 70,
        span_context: 28,
        get_key_values_request: 38,
        root: 76,
    };

pub(crate) static GET_KEY_VALUES_STREAM_REQUEST_V71: get_key_values_stream_request::VtA =
    get_key_values_stream_request::VtA {
        block: &[
            8, 0, 16, 0, 12, 0, 4, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8, 0, 8, 0, 16, 0, 12, 0, 4, 0,
            10, 0, 17, 0, 16, 0, 12, 0, 4, 0, 32, 0, 67, 0, 28, 0, 32, 0, 20, 0, 36, 0, 40, 0, 64,
            0, 65, 0, 44, 0, 66, 0, 48, 0, 52, 0, 4, 0, 56, 0, 60, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8,
            0, 4, 0,
        ],
        key_selector_ref: 8,
        reply_promise_stream: 68,
        tenant_info: 26,
        version_vector: 18,
        get_key_values_stream_request: 36,
        root: 74,
    };

pub(crate) static GET_KEY_VALUES_STREAM_REQUEST_V72: get_key_values_stream_request::VtB =
    get_key_values_stream_request::VtB {
        block: &[
            16, 0, 19, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 10, 0, 13, 0, 4, 0, 12, 0, 8, 0,
            14, 0, 22, 0, 20, 0, 12, 0, 4, 0, 21, 0, 16, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 30,
            0, 54, 0, 12, 0, 16, 0, 4, 0, 20, 0, 24, 0, 52, 0, 28, 0, 32, 0, 36, 0, 40, 0, 53, 0,
            44, 0, 48, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_selector_ref: 16,
        reply_promise_stream: 80,
        span_context: 40,
        tenant_info: 26,
        get_key_values_stream_request: 50,
        root: 86,
    };

pub(crate) static GET_KEY_VALUES_STREAM_REQUEST_V73: get_key_values_stream_request::VtB =
    get_key_values_stream_request::VtB {
        block: &[
            18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 13, 0, 4, 0, 12, 0,
            8, 0, 10, 0, 17, 0, 4, 0, 16, 0, 12, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 30, 0, 54, 0,
            12, 0, 16, 0, 4, 0, 20, 0, 24, 0, 52, 0, 28, 0, 32, 0, 36, 0, 40, 0, 53, 0, 44, 0, 48,
            0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_selector_ref: 18,
        reply_promise_stream: 78,
        span_context: 38,
        tenant_info: 28,
        get_key_values_stream_request: 48,
        root: 84,
    };

pub(crate) static GET_KEY_VALUES_STREAM_REQUEST_V80: get_key_values_stream_request::VtC =
    get_key_values_stream_request::VtC {
        block: &[
            18, 0, 20, 0, 4, 0, 16, 0, 17, 0, 8, 0, 18, 0, 12, 0, 19, 0, 10, 0, 13, 0, 4, 0, 12, 0,
            8, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 28, 0, 50, 0, 12, 0, 16, 0, 4, 0, 20, 0, 24, 0,
            48, 0, 28, 0, 32, 0, 36, 0, 49, 0, 40, 0, 44, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_selector_ref: 18,
        reply_promise_stream: 66,
        span_context: 28,
        get_key_values_stream_request: 38,
        root: 72,
    };

pub(crate) static COMMIT_TRANSACTION_REQUEST_V71: commit_transaction_request::VtA =
    commit_transaction_request::VtA {
        block: &[
            10, 0, 13, 0, 12, 0, 4, 0, 8, 0, 12, 0, 24, 0, 12, 0, 4, 0, 16, 0, 20, 0, 8, 0, 12, 0,
            4, 0, 8, 0, 20, 0, 31, 0, 12, 0, 16, 0, 20, 0, 4, 0, 28, 0, 29, 0, 30, 0, 24, 0, 8, 0,
            16, 0, 12, 0, 4, 0, 10, 0, 17, 0, 16, 0, 12, 0, 4, 0, 26, 0, 51, 0, 20, 0, 24, 0, 28,
            0, 48, 0, 32, 0, 49, 0, 36, 0, 50, 0, 40, 0, 4, 0, 44, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8,
            0, 4, 0,
        ],
        key_range_ref: 22,
        mutation_ref: 0,
        commit_transaction_ref: 30,
        reply_promise: 94,
        tenant_info: 58,
        commit_transaction_request: 68,
        root: 100,
    };

pub(crate) static COMMIT_TRANSACTION_REQUEST_V72: commit_transaction_request::VtB =
    commit_transaction_request::VtB {
        block: &[
            10, 0, 13, 0, 12, 0, 4, 0, 8, 0, 8, 0, 16, 0, 12, 0, 4, 0, 12, 0, 24, 0, 12, 0, 4, 0,
            16, 0, 20, 0, 8, 0, 12, 0, 4, 0, 8, 0, 20, 0, 31, 0, 12, 0, 16, 0, 20, 0, 4, 0, 28, 0,
            29, 0, 30, 0, 24, 0, 14, 0, 22, 0, 20, 0, 12, 0, 4, 0, 21, 0, 16, 0, 10, 0, 29, 0, 4,
            0, 20, 0, 28, 0, 28, 0, 43, 0, 4, 0, 8, 0, 12, 0, 40, 0, 16, 0, 41, 0, 20, 0, 42, 0,
            24, 0, 28, 0, 32, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_range_ref: 30,
        mutation_ref: 0,
        commit_transaction_ref: 38,
        reply_promise: 110,
        span_context: 72,
        tenant_info: 58,
        commit_transaction_request: 82,
        root: 116,
    };

pub(crate) static COMMIT_TRANSACTION_REQUEST_V73: commit_transaction_request::VtB =
    commit_transaction_request::VtB {
        block: &[
            10, 0, 13, 0, 12, 0, 4, 0, 8, 0, 8, 0, 16, 0, 12, 0, 4, 0, 12, 0, 24, 0, 12, 0, 4, 0,
            16, 0, 20, 0, 8, 0, 12, 0, 4, 0, 8, 0, 24, 0, 36, 0, 12, 0, 16, 0, 20, 0, 4, 0, 32, 0,
            33, 0, 34, 0, 24, 0, 35, 0, 28, 0, 10, 0, 17, 0, 4, 0, 16, 0, 12, 0, 10, 0, 29, 0, 4,
            0, 20, 0, 28, 0, 28, 0, 43, 0, 4, 0, 8, 0, 12, 0, 40, 0, 16, 0, 41, 0, 20, 0, 42, 0,
            24, 0, 28, 0, 32, 0, 36, 0, 6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0,
        ],
        key_range_ref: 30,
        mutation_ref: 0,
        commit_transaction_ref: 38,
        reply_promise: 110,
        span_context: 72,
        tenant_info: 62,
        commit_transaction_request: 82,
        root: 116,
    };

pub(crate) static COMMIT_TRANSACTION_REQUEST_V80: commit_transaction_request::VtC =
    commit_transaction_request::VtC {
        block: &[
            10, 0, 13, 0, 12, 0, 4, 0, 8, 0, 8, 0, 16, 0, 12, 0, 4, 0, 12, 0, 24, 0, 12, 0, 4, 0,
            16, 0, 20, 0, 8, 0, 12, 0, 4, 0, 8, 0, 24, 0, 36, 0, 12, 0, 16, 0, 20, 0, 4, 0, 32, 0,
            33, 0, 34, 0, 24, 0, 35, 0, 28, 0, 10, 0, 29, 0, 4, 0, 20, 0, 28, 0, 26, 0, 39, 0, 4,
            0, 8, 0, 12, 0, 36, 0, 16, 0, 37, 0, 20, 0, 38, 0, 24, 0, 28, 0, 32, 0, 6, 0, 20, 0, 4,
            0, 6, 0, 8, 0, 4, 0,
        ],
        key_range_ref: 30,
        mutation_ref: 0,
        commit_transaction_ref: 38,
        reply_promise: 98,
        span_context: 62,
        commit_transaction_request: 72,
        root: 104,
    };

pub(crate) static PING_REQUEST_V71: ping_request::VtA = ping_request::VtA {
    block: &[6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0],
    reply_promise: 0,
    ping_request: 6,
    root: 6,
};

pub(crate) static PROTOCOL_INFO_REQUEST_V71: protocol_info_request::VtA =
    protocol_info_request::VtA {
        block: &[6, 0, 20, 0, 4, 0, 6, 0, 8, 0, 4, 0],
        reply_promise: 0,
        protocol_info_request: 6,
        root: 6,
    };

pub(crate) static ACKNOWLEDGEMENT_REPLY_V71: acknowledgement_reply::VtA =
    acknowledgement_reply::VtA {
        block: &[6, 0, 12, 0, 4, 0, 6, 0, 6, 0, 4, 0, 8, 0, 9, 0, 8, 0, 4, 0],
        acknowledgement_reply: 0,
        root: 12,
    };
