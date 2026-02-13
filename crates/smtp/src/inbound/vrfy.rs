/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::core::Session;
use common::network::{RcptResolution, SessionStream};
use std::{borrow::Cow, fmt::Write};
use trc::SmtpEvent;

impl<T: SessionStream> Session<T> {
    pub async fn handle_vrfy(&mut self, address: Cow<'_, str>) -> Result<(), ()> {
        if self.params.can_vrfy {
            match self
                .server
                .rcpt_resolve(&address.to_lowercase(), self.data.session_id)
                .await
            {
                Ok(
                    RcptResolution::Accept | RcptResolution::Rewrite(_) | RcptResolution::Expand(_),
                ) => {
                    trc::event!(
                        Smtp(SmtpEvent::Vrfy),
                        SpanId = self.data.session_id,
                        To = address.as_ref().to_string(),
                    );

                    self.write(format!("250 {}\r\n", address.as_ref()).as_bytes())
                        .await
                }
                Ok(RcptResolution::UnknownRecipient) | Ok(RcptResolution::UnknownDomain) => {
                    trc::event!(
                        Smtp(SmtpEvent::VrfyNotFound),
                        SpanId = self.data.session_id,
                        To = address.as_ref().to_string(),
                    );

                    self.write(b"550 5.1.2 Address not found.\r\n").await
                }
                Err(err) => {
                    trc::error!(
                        err.span_id(self.data.session_id)
                            .caused_by(trc::location!())
                            .details("Failed to verify address.")
                    );

                    self.write(b"252 2.4.3 Unable to verify address at this time.\r\n")
                        .await
                }
            }
        } else {
            trc::event!(
                Smtp(SmtpEvent::VrfyDisabled),
                SpanId = self.data.session_id,
                To = address.as_ref().to_string(),
            );

            self.write(b"252 2.5.1 VRFY is disabled.\r\n").await
        }
    }

    pub async fn handle_expn(&mut self, address: Cow<'_, str>) -> Result<(), ()> {
        if self.params.can_expn {
            match self
                .server
                .rcpt_resolve(&address.to_lowercase(), self.data.session_id)
                .await
            {
                Ok(RcptResolution::Expand(addresses)) => {
                    let mut result = String::with_capacity(32);
                    for (pos, value) in addresses.iter().enumerate() {
                        let _ = write!(
                            result,
                            "250{}{}\r\n",
                            if pos == addresses.len() - 1 { " " } else { "-" },
                            value
                        );
                    }

                    trc::event!(
                        Smtp(SmtpEvent::Expn),
                        SpanId = self.data.session_id,
                        To = address.as_ref().to_string(),
                    );

                    self.write(result.as_bytes()).await
                }
                Ok(_) => {
                    trc::event!(
                        Smtp(SmtpEvent::ExpnNotFound),
                        SpanId = self.data.session_id,
                        To = address.as_ref().to_string(),
                    );

                    self.write(b"550 5.1.2 Mailing list not found.\r\n").await
                }
                Err(err) => {
                    trc::error!(
                        err.span_id(self.data.session_id)
                            .caused_by(trc::location!())
                            .details("Failed to verify address.")
                    );

                    self.write(b"252 2.4.3 Unable to expand mailing list at this time.\r\n")
                        .await
                }
            }
        } else {
            trc::event!(
                Smtp(SmtpEvent::ExpnDisabled),
                SpanId = self.data.session_id,
                To = address.as_ref().to_string(),
            );

            self.write(b"252 2.5.1 EXPN is disabled.\r\n").await
        }
    }
}
