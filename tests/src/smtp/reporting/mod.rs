/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod analyze;
pub mod dmarc;
pub mod scheduler;
pub mod tls;

use mail_auth::report::dmarc::{
    Disposition, DmarcStatus, Identifiers, PolicyEvaluated, Record, Row,
};

pub trait TestRecord: Sized {
    fn evaluated(
        source_ip: &str,
        disposition: Disposition,
        dkim: DmarcStatus,
        spf: DmarcStatus,
    ) -> Self;

    fn with_identifiers(self, envelope_from: &str, envelope_to: &str, header_from: &str) -> Self;
}

impl TestRecord for Record {
    fn evaluated(
        source_ip: &str,
        disposition: Disposition,
        dkim: DmarcStatus,
        spf: DmarcStatus,
    ) -> Self {
        Record {
            row: Row {
                source_ip: Some(source_ip.parse().unwrap()),
                policy_evaluated: PolicyEvaluated {
                    disposition,
                    dkim,
                    spf,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn with_identifiers(
        mut self,
        envelope_from: &str,
        envelope_to: &str,
        header_from: &str,
    ) -> Self {
        self.identifiers = Identifiers {
            envelope_to: Some(envelope_to.into()),
            envelope_from: envelope_from.into(),
            header_from: header_from.into(),
        };
        self
    }
}
