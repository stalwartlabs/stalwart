/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![no_main]

use dav_proto::{
    parser::{DavParser, tokenizer::Tokenizer},
    schema::{
        property::{DavProperty, DavValue, LockScope, LockType},
        request::{DavPropertyValue, LockInfo, MkCol, PropertyUpdate},
    },
};
use libfuzzer_sys::fuzz_target;
use types::metadata::{DavValueView, XmlName, XmlValue};

fuzz_target!(|data: &[u8]| {
    if let Ok(update) = PropertyUpdate::parse(&mut Tokenizer::new(data)) {
        update.set.into_iter().for_each(check_property);
    }
    if let Ok(mkcol) = MkCol::parse(&mut Tokenizer::new(data)) {
        mkcol.props.into_iter().for_each(check_property);
    }
    if let Ok(LockInfo {
        owner: Some(owner), ..
    }) = LockInfo::parse(&mut Tokenizer::new(data))
    {
        check_owner(owner);
    }
});

fn check_property(property: DavPropertyValue) {
    let (DavProperty::Dead(name), DavValue::Dead(value)) = (property.property, property.value)
    else {
        return;
    };
    check_encoding(&value);

    let written = DavPropertyValue::new(
        DavProperty::Dead(name.clone()),
        value.to_encoded().expect("a parsed value encodes"),
    )
    .to_string();
    let request = format!(
        "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop>{written}</D:prop></D:set></D:propertyupdate>"
    );
    let reparsed = PropertyUpdate::parse(&mut Tokenizer::new(request.as_bytes()))
        .unwrap_or_else(|err| panic!("written value does not parse: {err} {written}"));
    match reparsed.set.as_slice() {
        [
            DavPropertyValue {
                property: DavProperty::Dead(reparsed_name),
                value: DavValue::Dead(reparsed_value),
            },
        ] => {
            assert_eq!(reparsed_name, &name, "{written}");
            assert_eq!(reparsed_value, &value, "{written}");
        }
        other => panic!("written value parses differently: {other:?} {written}"),
    }
}

fn check_owner(owner: XmlValue<'static>) {
    check_encoding(&owner);

    let written = LockInfo {
        lock_scope: LockScope::Exclusive,
        lock_type: LockType::Write,
        owner: Some(owner.clone()),
    }
    .to_string()
    .replacen("<D:lockinfo>", "<D:lockinfo xmlns:D=\"DAV:\">", 1);
    let reparsed = LockInfo::parse(&mut Tokenizer::new(written.as_bytes()))
        .unwrap_or_else(|err| panic!("written owner does not parse: {err} {written}"));
    assert_eq!(reparsed.owner.as_ref(), Some(&owner), "{written}");
}

fn check_encoding(value: &XmlValue<'_>) {
    let encoded = value.encode().expect("a parsed value encodes");
    assert_eq!(Ok(encoded.len()), value.encoded_len());
    let view = DavValueView::parse(&encoded).expect("an encoded value validates");
    assert_eq!(view.to_value().as_ref(), Some(value));
    let mut out = String::new();
    view.write_property(&XmlName::borrowed(Some("urn:fuzz"), "p"), &mut out)
        .expect("an encoded value writes");
}
