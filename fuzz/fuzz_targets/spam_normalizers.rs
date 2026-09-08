/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use libfuzzer_sys::fuzz_target;
use spam_filter::{Email, Hostname, IpParts, analysis::url::UrlParts};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let host = Hostname::new(text);
    if let Some(sld) = &host.sld {
        assert!(host.fqdn.ends_with(sld.as_str()), "{text:?}: {sld:?} is not a suffix of {:?}", host.fqdn);
    }
    let email = Email::new(text);
    let _ = email.is_valid();
    let _ = email.classifier_parts();
    let url = UrlParts::new(text);
    let _ = url.to_owned();
    let _ = UrlParts::no_scheme(text);
    let _ = IpParts::new(text);
});
