/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod negotiate;
pub mod number;
pub mod text;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromFormat {
    Text004,
    Text100,
    OpenMetrics100,
}

impl PromFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            PromFormat::Text004 => "text/plain; version=0.0.4; charset=utf-8",
            PromFormat::Text100 => "text/plain; version=1.0.0; charset=utf-8; escaping=underscores",
            PromFormat::OpenMetrics100 => {
                "application/openmetrics-text; version=1.0.0; charset=utf-8; escaping=underscores"
            }
        }
    }

    #[inline(always)]
    pub fn is_open_metrics(self) -> bool {
        self == PromFormat::OpenMetrics100
    }
}
