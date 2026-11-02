/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod acme;
pub mod alarm;
pub mod destroy_account;
pub mod dkim;
pub mod dns;
pub mod external_public_keys;
pub mod grantee_cleanup;
pub mod imip;
pub mod maintenance;
pub mod merge_threads;
pub mod rebuild_shares;
pub mod report;
// SPDX-SnippetBegin
// SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
// SPDX-License-Identifier: LicenseRef-SEL
#[cfg(feature = "enterprise")]
pub mod restore_item;
// SPDX-SnippetEnd
pub mod spam_classifier;

use std::fmt::Write;

pub(crate) struct SmtpRejection {
    reason: String,
    is_temporary: bool,
}

impl SmtpRejection {
    pub(crate) fn new(stage: &str, response: &str) -> Self {
        let response = response.trim();
        SmtpRejection {
            reason: format!("Server rejected {stage}: {response}"),
            is_temporary: response.starts_with('4'),
        }
    }
}

pub(crate) fn append_error(errors: &mut String, error: std::fmt::Arguments<'_>) {
    if !errors.is_empty() {
        errors.push_str("; ");
    }
    let _ = errors.write_fmt(error);
}
