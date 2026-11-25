/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::TestResult;
use crate::{
    Context, Sieve,
    bytecode::ops,
    runtime::{
        RuntimeError,
        message::parts::{PartCursor, Scope},
        tests::test_header::{HeaderKeys, InvalidHeaderNames},
    },
};
use mail_parser::HeaderName;
use smallvec::{SmallVec, smallvec};

impl<'x> Context<'x> {
    pub(crate) fn test_exists(
        &mut self,
        script: &'x Sieve<'x>,
        test: &ops::TestExists,
    ) -> Result<TestResult, RuntimeError> {
        let Some(header_names) =
            self.parse_header_names(script, test.header_names, InvalidHeaderNames::Fail)?
        else {
            return Ok(TestResult::Bool(test.is_not));
        };
        let Some(part) = self.current_part() else {
            return Ok(TestResult::Bool(test.is_not));
        };
        if !test.mime_anychild {
            let result = self.edits.hidden_end(part.id()).is_none()
                && header_names
                    .iter()
                    .all(|name| self.named_headers(part, name).next().is_some());
            return Ok(TestResult::Bool(result ^ test.is_not));
        }
        let keys: HeaderKeys<'_> = header_names.iter().map(HeaderName::key).collect();
        let mut header_exists: SmallVec<[bool; 8]> = smallvec![false; header_names.len()];
        let mut result = false;
        let mut parts = PartCursor::subtree(part, true, Scope::Message);
        let mut meter = self.scan_meter(header_names.len());

        while let Some(part) = self.advance(&mut parts) {
            if !meter.charge_headers(part) {
                break;
            }
            for ((exists, header_name), key) in header_exists
                .iter_mut()
                .zip(header_names.iter())
                .zip(keys.iter())
            {
                if !*exists && self.keyed_headers(part, header_name, *key).next().is_some() {
                    *exists = true;
                }
            }

            if header_exists.iter().all(|v| *v) {
                result = true;
                break;
            }
        }
        self.settle_scan(meter)?;

        Ok(TestResult::Bool(result ^ test.is_not))
    }
}
