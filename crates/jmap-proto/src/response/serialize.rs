/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::ResponseMethod;
use crate::request::Call;
use serde::{Serialize, ser::SerializeSeq};

impl Serialize for Call<ResponseMethod<'_>> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(3.into())?;
        seq.serialize_element(self.name.as_str().as_ref())?;
        seq.serialize_element(&self.method)?;
        seq.serialize_element(&self.id)?;
        seq.end()
    }
}

pub fn serialize_hex<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(&format_args!("{value:x}"))
}

#[cfg(test)]
mod tests {
    use crate::{
        request::{Call, method::MethodName},
        response::{Response, ResponseMethod},
        types::{date::UTCDate, state::State},
    };
    use jmap_tools::Value;
    use std::collections::HashMap;
    use types::{
        blob::{BlobClass, BlobId},
        blob_hash::BlobHash,
    };

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn small(&mut self) -> u64 {
            let bits = self.next();
            bits >> (self.next() % 64)
        }
    }

    fn json<T: serde::Serialize + ?Sized>(value: &T) -> String {
        serde_json::to_string(value).unwrap_or_default()
    }

    #[test]
    fn streamed_text_matches_display() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..500 {
            let date = UTCDate {
                year: rng.next() as u16,
                month: rng.next() as u8,
                day: rng.next() as u8,
                hour: rng.next() as u8,
                minute: rng.next() as u8,
                second: rng.next() as u8,
                tz_before_gmt: rng.next().is_multiple_of(2),
                tz_hour: if rng.next().is_multiple_of(3) {
                    0
                } else {
                    rng.next() as u8
                },
                tz_minute: if rng.next().is_multiple_of(3) {
                    0
                } else {
                    rng.next() as u8
                },
            };
            assert_eq!(json(&date), json(&date.to_string()));

            let from = rng.small();
            let state = match rng.next() % 3 {
                0 => State::Initial,
                1 => State::new_exact(rng.small()),
                _ => State::new_intermediate(
                    from,
                    from.saturating_add(rng.small()),
                    rng.small() as usize,
                ),
            };
            assert_eq!(json(&state), json(&state.to_string()));

            let blob_id = BlobId::new(
                BlobHash::generate(rng.next().to_le_bytes()),
                BlobClass::Linked {
                    account_id: rng.next() as u32,
                    collection: rng.next() as u8,
                    document_id: rng.next() as u32,
                },
            );
            assert_eq!(json(&blob_id), json(&blob_id.to_string()));

            let session = rng.next() as u32;
            assert_eq!(
                json(&Response::new(session, HashMap::new(), 0)),
                format!("{{\"methodResponses\":[],\"sessionState\":\"{session:x}\"}}")
            );
        }

        for name in [
            "Core/echo",
            "Email/get",
            "Email/set",
            "Email/query",
            "Email/queryChanges",
            "Email/changes",
            "Email/copy",
            "Email/import",
            "Email/parse",
            "Mailbox/get",
            "Thread/get",
            "SearchSnippet/get",
            "Identity/set",
            "EmailSubmission/set",
            "VacationResponse/get",
            "PushSubscription/set",
            "SieveScript/validate",
            "Principal/getAvailability",
            "Quota/get",
            "Blob/upload",
            "Blob/lookup",
            "AddressBook/get",
            "ContactCard/parse",
            "FileNode/set",
            "ParticipantIdentity/get",
            "Calendar/set",
            "CalendarEvent/copy",
            "CalendarEventNotification/get",
            "ShareNotification/query",
        ] {
            let name = MethodName::parse(name).expect("known method");
            let call = Call {
                id: "c1".to_string(),
                name,
                method: ResponseMethod::Echo(Value::Null),
            };
            assert_eq!(
                json(&call),
                format!("[{},null,\"c1\"]", json(&call.name.to_string()))
            );
        }
    }
}
