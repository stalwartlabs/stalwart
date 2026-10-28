/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::value::ValueEncoder;
use crate::proto::writer::{LenHint, ProtoWriter};

const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const SDK_NAME: &str = "stalwart";
const SDK_LANGUAGE: &str = "rust";
const SCOPE_NAME: &str = "stalwart";

const ENVELOPE_RESOURCE: u32 = 1;
const RESOURCE_ATTRIBUTES: u32 = 1;
const ENVELOPE_SCOPE: u32 = 1;
const SCOPE_NAME_FIELD: u32 = 1;
const SCOPE_VERSION_FIELD: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    nonce: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct Resource {
    pub(crate) resource: Box<[u8]>,
    pub(crate) scope: Box<[u8]>,
    pub(crate) trace_prefix: [u8; 8],
}

impl ProcessIdentity {
    pub fn new(nonce: [u8; 16]) -> Self {
        Self { nonce }
    }

    pub fn trace_prefix(&self) -> [u8; 8] {
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&self.nonce[..8]);
        if prefix == [0u8; 8] {
            prefix[0] = 1;
        }
        prefix
    }

    pub fn write_instance_id(&self, out: &mut String) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut uuid = self.nonce;
        uuid[6] = (uuid[6] & 0x0f) | 0x40;
        uuid[8] = (uuid[8] & 0x3f) | 0x80;
        for (pos, byte) in uuid.iter().enumerate() {
            if matches!(pos, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}

impl Resource {
    pub fn new<'x>(
        identity: &ProcessIdentity,
        service_name: &str,
        service_namespace: Option<&str>,
        attributes: impl IntoIterator<Item = (&'x str, &'x str)>,
    ) -> Self {
        let mut values = ValueEncoder::default();
        let mut instance_id = String::with_capacity(36);
        identity.write_instance_id(&mut instance_id);

        let mut w = ProtoWriter::with_capacity(256);
        let resource = w.begin(ENVELOPE_RESOURCE, LenHint::Medium);
        values.string_key_value(&mut w, RESOURCE_ATTRIBUTES, "service.name", service_name);
        if let Some(namespace) = service_namespace.filter(|namespace| !namespace.is_empty()) {
            values.string_key_value(&mut w, RESOURCE_ATTRIBUTES, "service.namespace", namespace);
        }
        values.string_key_value(
            &mut w,
            RESOURCE_ATTRIBUTES,
            "service.version",
            SERVER_VERSION,
        );
        values.string_key_value(
            &mut w,
            RESOURCE_ATTRIBUTES,
            "service.instance.id",
            &instance_id,
        );
        values.string_key_value(&mut w, RESOURCE_ATTRIBUTES, "telemetry.sdk.name", SDK_NAME);
        values.string_key_value(
            &mut w,
            RESOURCE_ATTRIBUTES,
            "telemetry.sdk.language",
            SDK_LANGUAGE,
        );
        values.string_key_value(
            &mut w,
            RESOURCE_ATTRIBUTES,
            "telemetry.sdk.version",
            SERVER_VERSION,
        );
        for (key, value) in attributes {
            if !key.is_empty() && !is_reserved_key(key) {
                values.string_key_value(&mut w, RESOURCE_ATTRIBUTES, key, value);
            }
        }
        w.end(resource);
        let resource = Box::from(w.as_slice());

        let mut w = ProtoWriter::with_capacity(32);
        let scope = w.begin(ENVELOPE_SCOPE, LenHint::Small);
        w.bytes(SCOPE_NAME_FIELD, SCOPE_NAME.as_bytes());
        w.bytes(SCOPE_VERSION_FIELD, SERVER_VERSION.as_bytes());
        w.end(scope);
        let scope = Box::from(w.as_slice());

        Self {
            resource,
            scope,
            trace_prefix: identity.trace_prefix(),
        }
    }
}

fn is_reserved_key(key: &str) -> bool {
    hashify::set!(
        key.as_bytes(),
        "service.name",
        "service.namespace",
        "service.version",
        "service.instance.id",
        "telemetry.sdk.name",
        "telemetry.sdk.language",
        "telemetry.sdk.version",
    )
}
