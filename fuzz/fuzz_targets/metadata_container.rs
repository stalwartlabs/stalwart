/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use jmap_tools::Null;
use libfuzzer_sys::fuzz_target;
use types::metadata::{DavValueView, MetadataBuilder, MetadataView};

fuzz_target!(|data: &[u8]| {
    if let Some(view) = MetadataView::new(data) {
        for (namespace, value) in view.jmap() {
            let _ = namespace.name();
            let _ = value.to_value::<Null, Null>();
            assert!(view.jmap_namespace(&namespace).is_some());
            for (key, member) in value.members() {
                assert!(value.get(key).is_some());
                let _ = (member.kind(), member.len(), member.is_empty_object());
                let _ = (member.as_str(), member.as_bool(), member.as_u64());
                let _ = (member.as_i64(), member.as_f64(), member.items().count());
            }
        }
        for (name, value) in view.dav() {
            let _ = value.to_value();
            let mut out = String::new();
            let _ = value.write_property(&name, &mut out);
        }
        for (name, value) in view.imap() {
            assert!(view.imap_entry(name).is_some());
            let _ = value.len();
        }

        if let Some(encoded) = MetadataBuilder::from_view(&view).encode() {
            let rebuilt = MetadataView::new(encoded.as_bytes())
                .expect("a container rebuilt from a valid one validates");
            assert!(rebuilt.len() <= view.len());
            assert_eq!(rebuilt.kinds(), view.kinds());
        }
    }

    if let Some(value) = DavValueView::parse(data) {
        let _ = value.to_value();
        let mut out = String::new();
        let _ = value.write_property(&types::metadata::XmlName::borrowed(None, "p"), &mut out);
    }
});
