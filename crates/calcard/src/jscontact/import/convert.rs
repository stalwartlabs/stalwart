/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        blob::{BlobIdGenerator, BlobIds, NoBlobIds},
        export::ImportError,
        jsprop::{JSPropPointer, text::PointerString},
    },
    jscontact::{
        JSContact, JSContactId, JSContactKind, JSContactProperty, JSContactValue,
        import::{EntryState, ExtractedParams, ImportOptions, State, props::NamedKey},
    },
    vcard::{
        Jscomp, VCard, VCardParameter, VCardParameterName, VCardParameterValue, VCardProperty,
        VCardValue, VCardValueType,
    },
};
use jmap_tools::{JsonPointer, Key, Map, Property, Value};
use smallvec::smallvec;
use std::mem;

impl VCard {
    pub fn into_jscontact<I, B>(self) -> JSContact<'static, I, B>
    where
        I: JSContactId,
        B: JSContactId,
    {
        self.convert_jscontact::<I, B, NoBlobIds>(ImportOptions::default())
            .0
    }

    pub fn into_jscontact_with<I, B, G>(
        self,
        options: ImportOptions<G>,
    ) -> Result<JSContact<'static, I, B>, ImportError>
    where
        I: JSContactId,
        B: JSContactId,
        G: BlobIdGenerator<B>,
    {
        match self.convert_jscontact(options) {
            (js_contact, false) => Ok(js_contact),
            (_, true) => Err(ImportError::BlobIdFailed),
        }
    }

    fn convert_jscontact<I, B, G>(
        self,
        mut options: ImportOptions<G>,
    ) -> (JSContact<'static, I, B>, bool)
    where
        I: JSContactId,
        B: JSContactId,
        G: BlobIdGenerator<B>,
    {
        let include_vcard_parameters = options.include_vcard_parameters;
        let mut blob_ids = options.blob_ids::<B>();
        if let Some(blob_ids) = &mut blob_ids {
            blob_ids.expect_sizes(self.blob_binaries().map(<[u8]>::len));
        }
        let js_contact = self.build_jscontact(include_vcard_parameters, &mut blob_ids);
        let has_failed = blob_ids.is_some_and(|blob_ids| blob_ids.has_failed());

        (js_contact, has_failed)
    }

    fn build_jscontact<I, B>(
        mut self,
        include_vcard_parameters: bool,
        blob_ids: &mut Option<BlobIds<'_, B>>,
    ) -> JSContact<'static, I, B>
    where
        I: JSContactId,
        B: JSContactId,
    {
        let mut state = State::new(&mut self, include_vcard_parameters);

        for entry in self.entries {
            let mut entry = EntryState::new(entry, state.include_vcard_converted);

            match &entry.entry.name {
                VCardProperty::Kind => {
                    if !state.has_property(JSContactProperty::Kind)
                        && let Some(kind) = entry.to_kind()
                    {
                        state.entries.insert(JSContactProperty::Kind, kind);
                        entry.set_converted_to(|| {
                            String::from_pointer([JSContactProperty::Kind::<I>.to_cow().as_ref()])
                        });
                    }
                }
                VCardProperty::Source => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::PropId,
                            VCardParameterName::Pref,
                            VCardParameterName::Mediatype,
                            VCardParameterName::Label,
                        ],
                        JSContactProperty::Directories,
                        JSContactProperty::Uri,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(JSContactKind::Entry)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::OrgDirectory => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::PropId,
                            VCardParameterName::Pref,
                            VCardParameterName::Index,
                            VCardParameterName::Label,
                            VCardParameterName::Type,
                        ],
                        JSContactProperty::Directories,
                        JSContactProperty::Uri,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(JSContactKind::Directory)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Anniversary | VCardProperty::Bday | VCardProperty::Deathdate => {
                    let kind = match &entry.entry.name {
                        VCardProperty::Anniversary => JSContactKind::Wedding,
                        VCardProperty::Bday => JSContactKind::Birth,
                        VCardProperty::Deathdate => JSContactKind::Death,
                        _ => unreachable!(),
                    };

                    state.map_named_entry(
                        &mut entry,
                        &[VCardParameterName::PropId, VCardParameterName::Calscale],
                        JSContactProperty::Anniversaries,
                        JSContactProperty::Date,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(kind)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Birthplace | VCardProperty::Deathplace => {
                    // Only text and GEO can be mapped
                    let is_geo = matches!(entry.entry.values.first(), Some(VCardValue::Text(uri)) if uri.starts_with("geo:"));
                    if (is_geo || !entry.entry.is_type(&VCardValueType::Uri))
                        && let Some(text) = entry.to_text()
                    {
                        // Extract language and value type
                        let mut params = ExtractedParams::default();
                        params.extract(
                            &mut entry.entry.params,
                            &[VCardParameterName::Language, VCardParameterName::PropId],
                            state.default_language.as_deref(),
                        );

                        let prop_id = params.prop_id();
                        let alt_id = params.alt_id();

                        let kind = Value::Element(JSContactValue::Kind(
                            if entry.entry.name == VCardProperty::Birthplace {
                                JSContactKind::Birth
                            } else {
                                JSContactKind::Death
                            },
                        ));

                        let patch_prop = if params.language.is_some() {
                            &entry.entry.name
                        } else if entry.entry.name == VCardProperty::Birthplace {
                            &VCardProperty::Bday
                        } else {
                            &VCardProperty::Deathdate
                        };
                        let mut patch_id = prop_id
                            .as_deref()
                            .filter(|prop_id| state.has_prop_id(patch_prop, prop_id))
                            .or_else(|| {
                                state.find_prop_id(
                                    patch_prop,
                                    entry.entry.group.as_deref(),
                                    alt_id.as_deref(),
                                )
                            })
                            .map(|prop_id| prop_id.to_string());

                        if patch_id.is_none() && params.language.is_some() {
                            entry
                                .entry
                                .params
                                .push(VCardParameter::language(params.language.take().unwrap()));
                        }

                        let entries =
                            state.get_mut_object_or_insert(JSContactProperty::Anniversaries);

                        if let Some(lang) = params.language() {
                            let path = format!(
                                "{}/{}/{}/{}",
                                JSContactProperty::Anniversaries::<I>.to_cow().as_ref(),
                                patch_id.unwrap(),
                                JSContactProperty::Place::<I>.to_cow().as_ref(),
                                JSContactProperty::Full::<I>.to_cow().as_ref()
                            );

                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Localizations::<I>.to_cow().as_ref(),
                                    lang.as_str(),
                                    path.as_str(),
                                ])
                            });

                            state.localize(lang, |locale| locale.push((path, text)));
                        } else {
                            // Place needs to be wrapped in an option to dance around the borrow checker
                            let prop_name = if !is_geo {
                                JSContactProperty::Full
                            } else {
                                JSContactProperty::Coordinates
                            };
                            let mut place =
                                Some(Map::from(vec![(Key::Property(prop_name.clone()), text)]));

                            if let Some(anniversary) = patch_id.clone().and_then(|patch_id| {
                                entries
                                    .get_mut(&Key::Owned(patch_id))
                                    .and_then(|v| v.as_object_mut())
                            }) {
                                anniversary.insert(
                                    Key::Property(JSContactProperty::Place),
                                    Value::Object(place.take().unwrap()),
                                );
                            }

                            if place.is_some()
                                && let Some((key, anniversary)) =
                                    entries.iter_mut().find_map(|(k, v)| {
                                        let obj = v.as_object_mut()?;
                                        if obj.iter().any(|(k, v)| {
                                            k == &Key::Property(JSContactProperty::Kind)
                                                && v == &kind
                                        }) && !obj
                                            .contains_key(&Key::Property(JSContactProperty::Place))
                                        {
                                            Some((k, obj))
                                        } else {
                                            None
                                        }
                                    })
                            {
                                anniversary.insert(
                                    Key::Property(JSContactProperty::Place),
                                    Value::Object(place.take().unwrap()),
                                );
                                patch_id = Some(key.to_string().into_owned());
                            }

                            if let Some(place) = place {
                                let key = entries.named_key(prop_id);
                                entries.insert_unchecked(
                                    Key::Owned(key.clone()),
                                    Value::Object(Map::from(vec![
                                        (Key::Property(JSContactProperty::Kind), kind),
                                        (
                                            Key::Property(JSContactProperty::Place),
                                            Value::Object(place),
                                        ),
                                    ])),
                                );
                                patch_id = Some(key);
                            }

                            let patch_id = patch_id.unwrap();

                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Anniversaries::<I>.to_cow().as_ref(),
                                    patch_id.as_ref(),
                                    JSContactProperty::Place::<I>.to_cow().as_ref(),
                                    prop_name.to_cow().as_ref(),
                                ])
                            });

                            state.prop_ids.track(
                                &entry.entry,
                                JSContactProperty::Anniversaries,
                                alt_id,
                                &patch_id,
                            );
                        }
                    }
                }
                VCardProperty::Fn => {
                    if (!state.has_fn
                        || (entry
                            .non_default_language(state.default_language.as_deref())
                            .is_some()
                            && !state.has_fn_localization))
                        && let Some(text) = entry.to_text()
                    {
                        let mut params = ExtractedParams::default();
                        params.extract(
                            &mut entry.entry.params,
                            &[VCardParameterName::Language],
                            state.default_language.as_deref(),
                        );
                        if let Some(lang) = params.language {
                            let path = format!(
                                "{}/{}",
                                JSContactProperty::Name::<I>.to_cow().as_ref(),
                                JSContactProperty::Full::<I>.to_cow().as_ref()
                            );

                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Localizations::<I>.to_cow().as_ref(),
                                    lang.as_str(),
                                    path.as_str(),
                                ])
                            });
                            state.has_fn_localization = true;
                            state.localize(lang, |locale| locale.push((path, text)));
                        } else {
                            state.has_fn = true;
                            state
                                .get_mut_object_or_insert(JSContactProperty::Name)
                                .insert(Key::Property(JSContactProperty::Full), text);
                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Name::<I>.to_cow().as_ref(),
                                    JSContactProperty::Full::<I>.to_cow().as_ref(),
                                ])
                            });
                        }
                    }
                }
                VCardProperty::N => {
                    /*
                      Only process this N component if it matches the main ALTID and:
                      - It is the first N component
                      - Or it has a language that has not been processed yet
                    */
                    if state.name_alt_id.as_deref() == entry.entry.alt_id()
                        && (!state.has_n
                            || (entry
                                .non_default_language(state.default_language.as_deref())
                                .is_some()
                                && !state.has_n_localization))
                    {
                        let mut params = ExtractedParams::default();
                        params.extract(
                            &mut entry.entry.params,
                            &[
                                VCardParameterName::Language,
                                VCardParameterName::Phonetic,
                                VCardParameterName::Script,
                                VCardParameterName::SortAs,
                                VCardParameterName::Jscomps,
                            ],
                            state.default_language.as_deref(),
                        );

                        if params.language.is_some() && !state.has_n {
                            entry
                                .entry
                                .params
                                .push(VCardParameter::language(params.language.take().unwrap()));
                        }

                        /*

                           0 = family names (also known as surnames);
                           1 = given names;
                           2 = additional names;
                           3 = honorific prefixes;
                           4 = honorific suffixes;
                           5 = secondary surname;
                           6 = generation

                        */

                        let mut default_separator = None;
                        let mut is_ordered = false;
                        let mut components = Vec::new();

                        if !params.jscomps.is_empty() {
                            let mut is_valid = true;
                            let mut has_entry = false;

                            for (pos, jscomp) in
                                std::mem::take(&mut params.jscomps).into_iter().enumerate()
                            {
                                match jscomp {
                                    Jscomp::Entry { position, value } => {
                                        if let Some(kind) =
                                            JSContactKind::from_vcard_n_pos(position as usize)
                                        {
                                            let value =
                                                match entry.entry.values.get(position as usize) {
                                                    Some(VCardValue::Text(text)) if value == 0 => {
                                                        Some(text.as_str())
                                                    }
                                                    Some(VCardValue::Component(values)) => values
                                                        .get(value as usize)
                                                        .map(|v| v.as_str()),
                                                    _ => None,
                                                };

                                            if let Some(value) = value {
                                                components.push(Value::Object(Map::from(vec![
                                                    (
                                                        Key::Property(JSContactProperty::Kind),
                                                        Value::Element(JSContactValue::Kind(kind)),
                                                    ),
                                                    (
                                                        Key::Property(JSContactProperty::Value),
                                                        Value::Str(value.to_string().into()),
                                                    ),
                                                ])));
                                                has_entry = true;
                                                continue;
                                            }
                                        }

                                        is_valid = false;
                                        break;
                                    }
                                    Jscomp::Separator(sep) => {
                                        if !sep.is_empty() {
                                            if pos > 0 {
                                                components.push(Value::Object(Map::from(vec![
                                                    (
                                                        Key::Property(JSContactProperty::Kind),
                                                        Value::Element(JSContactValue::Kind(
                                                            JSContactKind::Separator,
                                                        )),
                                                    ),
                                                    (
                                                        Key::Property(JSContactProperty::Value),
                                                        Value::Str(sep.into()),
                                                    ),
                                                ])));
                                            } else {
                                                default_separator = sep.into();
                                            }
                                        }
                                    }
                                }
                            }

                            if is_valid && has_entry {
                                is_ordered = true;
                                entry.entry.values.clear();
                            }
                        }

                        if !is_ordered {
                            let has_secondary_parts =
                                entry
                                    .entry
                                    .values
                                    .iter()
                                    .enumerate()
                                    .any(|(comp_id, value)| {
                                        matches!(
                                            JSContactKind::from_vcard_n_pos(comp_id),
                                            Some(
                                                JSContactKind::Surname2 | JSContactKind::Generation
                                            )
                                        ) && match value {
                                            VCardValue::Text(text) => !text.is_empty(),
                                            VCardValue::Component(text_list) => {
                                                !text_list.is_empty()
                                            }
                                            _ => false,
                                        }
                                    });

                            components = if has_secondary_parts {
                                let mut components_ = Vec::with_capacity(7);
                                for (comp_id, value) in entry.entry.values.iter().enumerate() {
                                    if let Some(kind) = JSContactKind::from_vcard_n_pos(comp_id) {
                                        match value {
                                            VCardValue::Text(text) if !text.is_empty() => {
                                                components_.push((kind, text.as_str()));
                                            }
                                            VCardValue::Component(text_list) => {
                                                for text in text_list {
                                                    components_.push((kind, text.as_str()));
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }

                                components_
                                    .iter()
                                    .filter(|(kind, value)| match kind {
                                        JSContactKind::Credential => !components_
                                            .contains(&(JSContactKind::Generation, value)),
                                        JSContactKind::Surname => {
                                            !components_.contains(&(JSContactKind::Surname2, value))
                                        }
                                        _ => true,
                                    })
                                    .map(|(kind, value)| {
                                        Value::Object(Map::from(vec![
                                            (
                                                Key::Property(JSContactProperty::Kind),
                                                Value::Element(JSContactValue::Kind(*kind)),
                                            ),
                                            (
                                                Key::Property(JSContactProperty::Value),
                                                Value::Str(value.to_string().into()),
                                            ),
                                        ]))
                                    })
                                    .collect::<Vec<_>>()
                            } else {
                                let mut parts = Vec::with_capacity(entry.entry.values.len());
                                for (comp_id, value) in
                                    mem::take(&mut entry.entry.values).into_iter().enumerate()
                                {
                                    if let Some(kind) = JSContactKind::from_vcard_n_pos(comp_id) {
                                        match value {
                                            VCardValue::Text(text) if !text.is_empty() => {
                                                parts.push((kind, text));
                                            }
                                            VCardValue::Component(text_list) => {
                                                parts.extend(
                                                    text_list.into_iter().map(|text| (kind, text)),
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                parts
                                    .into_iter()
                                    .map(|(kind, value)| {
                                        Value::Object(Map::from(vec![
                                            (
                                                Key::Property(JSContactProperty::Kind),
                                                Value::Element(JSContactValue::Kind(kind)),
                                            ),
                                            (
                                                Key::Property(JSContactProperty::Value),
                                                Value::Str(value.into()),
                                            ),
                                        ]))
                                    })
                                    .collect()
                            };
                        }

                        if let Some(lang) = params.language() {
                            let path = format!(
                                "{}/{}",
                                JSContactProperty::Name::<I>.to_cow().as_ref(),
                                JSContactProperty::Components::<I>.to_cow().as_ref(),
                            );

                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Localizations::<I>.to_cow().as_ref(),
                                    lang.as_str(),
                                    path.as_str(),
                                ])
                            });

                            state.has_n_localization = true;
                            state.localize(lang, |locale| {
                                if !components.is_empty() {
                                    locale.push((path, Value::Array(components)));
                                }

                                params.members::<I, B>(&entry.entry.name).for_each(
                                    |prop, value| {
                                        locale.push((
                                            format!(
                                                "{}/{}",
                                                JSContactProperty::Name::<I>.to_cow().as_ref(),
                                                prop.to_string()
                                            ),
                                            value,
                                        ));
                                    },
                                );
                            });
                        } else {
                            state.has_n = true;
                            {
                                let members = params.members::<I, B>(&entry.entry.name);

                                if !members.is_empty() || !components.is_empty() {
                                    let name = state
                                        .entries
                                        .get_mut_object_or_insert(JSContactProperty::Name);
                                    members.append_to(name.as_mut_vec());
                                    if !components.is_empty() {
                                        name.insert(
                                            Key::Property(JSContactProperty::Components),
                                            Value::Array(components),
                                        );
                                    }
                                    if is_ordered {
                                        if let Some(default_separator) = default_separator {
                                            name.insert_unchecked(
                                                Key::Property(JSContactProperty::DefaultSeparator),
                                                Value::Str(default_separator.into()),
                                            );
                                        }
                                        name.insert_unchecked(
                                            Key::Property(JSContactProperty::IsOrdered),
                                            Value::Bool(true),
                                        );
                                    }
                                }
                            }
                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Name::<I>.to_cow().as_ref(),
                                    JSContactProperty::Components::<I>.to_cow().as_ref(),
                                ])
                            });
                        }
                    }
                }
                VCardProperty::Gramgender => {
                    if !state.has_gram_gender
                        && let Some(gram_gender) = entry.to_gram_gender()
                    {
                        ExtractedParams::default().extract(
                            &mut entry.entry.params,
                            &[],
                            state.default_language.as_deref(),
                        );
                        state
                            .get_mut_object_or_insert(JSContactProperty::SpeakToAs)
                            .insert(JSContactProperty::GrammaticalGender, gram_gender);
                        state.has_gram_gender = true;
                        entry.set_converted_to(|| {
                            String::from_pointer([
                                JSContactProperty::SpeakToAs::<I>.to_cow().as_ref(),
                                JSContactProperty::GrammaticalGender::<I>.to_cow().as_ref(),
                            ])
                        });
                    }
                }
                VCardProperty::Pronouns => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Language,
                            VCardParameterName::PropId,
                            VCardParameterName::Altid,
                            VCardParameterName::Pref,
                        ],
                        JSContactProperty::SpeakToAs,
                        JSContactProperty::Pronouns,
                        [None, None],
                    );
                }
                VCardProperty::Nickname => {
                    for value in std::mem::take(&mut entry.entry.values) {
                        let mut value_entry = entry.clone();
                        value_entry.entry.values = smallvec![value];

                        state.map_named_entry(
                            &mut value_entry,
                            &[
                                VCardParameterName::Type,
                                VCardParameterName::Pref,
                                VCardParameterName::PropId,
                                VCardParameterName::Altid,
                                VCardParameterName::Language,
                            ],
                            JSContactProperty::Nicknames,
                            JSContactProperty::Name,
                            [None, None],
                        );
                        state.add_conversion_props(value_entry);
                    }
                    continue;
                }
                VCardProperty::Photo | VCardProperty::Logo | VCardProperty::Sound => {
                    let kind = match &entry.entry.name {
                        VCardProperty::Photo => JSContactKind::Photo,
                        VCardProperty::Logo => JSContactKind::Logo,
                        VCardProperty::Sound => JSContactKind::Sound,
                        _ => unreachable!(),
                    };
                    if !blob_ids
                        .as_mut()
                        .is_some_and(|blob_ids| state.map_blob_media(&mut entry, kind, blob_ids))
                    {
                        state.map_named_entry(
                            &mut entry,
                            &[
                                VCardParameterName::Mediatype,
                                VCardParameterName::Pref,
                                VCardParameterName::PropId,
                                VCardParameterName::Label,
                            ],
                            JSContactProperty::Media,
                            JSContactProperty::Uri,
                            [
                                Some((
                                    Key::Property(JSContactProperty::Kind),
                                    Value::Element(JSContactValue::Kind(kind)),
                                )),
                                None,
                            ],
                        );
                    }
                }
                VCardProperty::Adr => {
                    let mut params = ExtractedParams::default();
                    params.extract(
                        &mut entry.entry.params,
                        &[
                            VCardParameterName::Language,
                            VCardParameterName::Phonetic,
                            VCardParameterName::Script,
                            VCardParameterName::Label,
                            VCardParameterName::Geo,
                            VCardParameterName::Tz,
                            VCardParameterName::Cc,
                            VCardParameterName::PropId,
                            VCardParameterName::Altid,
                            VCardParameterName::Pref,
                            VCardParameterName::Type,
                            VCardParameterName::Jscomps,
                        ],
                        state.default_language.as_deref(),
                    );

                    let prop_id = params.prop_id();
                    let alt_id = params.alt_id();

                    // Locate the address to patch or reset language
                    let addr_patch = if params.language.is_some() {
                        let addr_patch = prop_id
                            .as_deref()
                            .filter(|prop_id| state.has_prop_id(&entry.entry.name, prop_id))
                            .or_else(|| {
                                state.find_prop_id(
                                    &entry.entry.name,
                                    entry.entry.group.as_deref(),
                                    alt_id.as_deref(),
                                )
                            });

                        if addr_patch.is_none() {
                            entry
                                .entry
                                .params
                                .push(VCardParameter::language(params.language().unwrap()));
                        }
                        addr_patch
                    } else {
                        None
                    };

                    /*

                    0 = ADR-component-pobox ";"
                    1 = ADR-component-ext ";"
                    2 = ADR-component-street ";"
                    3 = ADR-component-locality ";"
                    4 = ADR-component-region ";"
                    5 = ADR-component-code ";"
                    6 = ADR-component-country ";"
                    7 = ADR-component-room ";"
                    8 = ADR-component-apartment ";"
                    9 = ADR-component-floor ";"
                    10 = ADR-component-streetnumber ";"
                    11 = ADR-component-streetname ";"
                    12 = ADR-component-building ";"
                    13 = ADR-component-block ";"
                    14 = ADR-component-subdistrict ";"
                    15 = ADR-component-district ";"
                    16 = ADR-component-landmark ";"
                    17 = ADR-component-direction ";"

                    */

                    let mut default_separator = None;
                    let mut is_ordered = false;
                    let mut components = Vec::new();

                    if !params.jscomps.is_empty() {
                        let mut is_valid = true;
                        let mut has_entry = false;

                        for (pos, jscomp) in
                            std::mem::take(&mut params.jscomps).into_iter().enumerate()
                        {
                            match jscomp {
                                Jscomp::Entry { position, value } => {
                                    if let Some(kind) =
                                        JSContactKind::from_vcard_adr_pos(position as usize)
                                    {
                                        let value = match entry.entry.values.get(position as usize)
                                        {
                                            Some(VCardValue::Text(text)) if value == 0 => {
                                                Some(text.as_str())
                                            }
                                            Some(VCardValue::Component(values)) => {
                                                values.get(value as usize).map(|v| v.as_str())
                                            }
                                            _ => None,
                                        };

                                        if let Some(value) = value {
                                            components.push(Value::Object(Map::from(vec![
                                                (
                                                    Key::Property(JSContactProperty::Kind),
                                                    Value::Element(JSContactValue::Kind(kind)),
                                                ),
                                                (
                                                    Key::Property(JSContactProperty::Value),
                                                    Value::Str(value.to_string().into()),
                                                ),
                                            ])));
                                            has_entry = true;
                                            continue;
                                        }
                                    }

                                    is_valid = false;
                                    break;
                                }
                                Jscomp::Separator(sep) => {
                                    if !sep.is_empty() {
                                        if pos > 0 {
                                            components.push(Value::Object(Map::from(vec![
                                                (
                                                    Key::Property(JSContactProperty::Kind),
                                                    Value::Element(JSContactValue::Kind(
                                                        JSContactKind::Separator,
                                                    )),
                                                ),
                                                (
                                                    Key::Property(JSContactProperty::Value),
                                                    Value::Str(sep.into()),
                                                ),
                                            ])));
                                        } else {
                                            default_separator = sep.into();
                                        }
                                    }
                                }
                            }
                        }

                        if is_valid && has_entry {
                            is_ordered = true;
                            entry.entry.values.clear();
                        }
                    }

                    if !is_ordered {
                        components.clear();

                        let is_rfc9554_adr = entry.entry.values.iter().skip(7).any(|v| match v {
                            VCardValue::Text(text) => !text.is_empty(),
                            VCardValue::Component(text_list) => !text_list.is_empty(),
                            _ => false,
                        });

                        for (pos, value) in entry.entry.values.drain(..).enumerate() {
                            if is_rfc9554_adr && (pos == 1 || pos == 2) {
                                // From vCard: ignore if the ADR structured value is of the format defined in [RFC9554]. Otherwise, convert to "apartment".
                                // From vCard: ignore if the ADR structured value is of the format defined in [RFC9554]. Otherwise, convert to "name".
                                continue;
                            }

                            if let Some(kind) = JSContactKind::from_vcard_adr_pos(pos) {
                                match value {
                                    VCardValue::Text(text) if !text.is_empty() => {
                                        components.push(Value::Object(Map::from(vec![
                                            (
                                                Key::Property(JSContactProperty::Kind),
                                                Value::Element(JSContactValue::Kind(kind)),
                                            ),
                                            (
                                                Key::Property(JSContactProperty::Value),
                                                Value::Str(text.into()),
                                            ),
                                        ])));
                                    }
                                    VCardValue::Component(text_list) => {
                                        for text in text_list {
                                            components.push(Value::Object(Map::from(vec![
                                                (
                                                    Key::Property(JSContactProperty::Kind),
                                                    Value::Element(JSContactValue::Kind(kind)),
                                                ),
                                                (
                                                    Key::Property(JSContactProperty::Value),
                                                    Value::Str(text.into()),
                                                ),
                                            ])));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }

                    if let Some(lang) = params.language() {
                        let path = format!(
                            "{}/{}/{}",
                            JSContactProperty::Addresses::<I>.to_cow().as_ref(),
                            addr_patch.unwrap(),
                            JSContactProperty::Components::<I>.to_cow().as_ref(),
                        );
                        entry.set_converted_to(|| {
                            String::from_pointer([
                                JSContactProperty::Localizations::<I>.to_cow().as_ref(),
                                lang.as_str(),
                                path.as_str(),
                            ])
                        });

                        state.localize(lang, |locale| {
                            let base_path = path
                                .rsplit_once('/')
                                .map_or(path.as_str(), |(base, _)| base);
                            params.members::<I, B>(&entry.entry.name).for_each(
                                |prop_name, value| {
                                    locale.push((
                                        format!("{}/{}", base_path, prop_name.to_string()),
                                        value,
                                    ));
                                },
                            );

                            if !components.is_empty() {
                                locale.push((path, Value::Array(components)));
                            }
                        });
                    } else {
                        let entries = state
                            .entries
                            .get_mut_object_or_insert(JSContactProperty::Addresses);
                        let members = params.members::<I, B>(&entry.entry.name);
                        let mut addr = Vec::with_capacity(
                            members.len()
                                + usize::from(!components.is_empty())
                                + usize::from(is_ordered)
                                + usize::from(is_ordered && default_separator.is_some()),
                        );
                        members.append_to(&mut addr);
                        let mut addr = Map::from(addr);
                        if !components.is_empty() {
                            addr.insert_unchecked(
                                Key::Property(JSContactProperty::Components),
                                Value::Array(components),
                            );
                        }
                        if is_ordered {
                            if let Some(default_separator) = default_separator {
                                addr.insert_unchecked(
                                    Key::Property(JSContactProperty::DefaultSeparator),
                                    Value::Str(default_separator.into()),
                                );
                            }
                            addr.insert_unchecked(
                                Key::Property(JSContactProperty::IsOrdered),
                                Value::Bool(true),
                            );
                        }

                        let prop_id = entries.named_key(prop_id);

                        entry.set_converted_to(|| {
                            String::from_pointer([
                                JSContactProperty::Addresses::<I>.to_cow().as_ref(),
                                prop_id.as_str(),
                                JSContactProperty::Components::<I>.to_cow().as_ref(),
                            ])
                        });

                        state.prop_ids.track(
                            &entry.entry,
                            JSContactProperty::Addresses,
                            alt_id,
                            &prop_id,
                        );
                        entries.insert_unchecked(Key::Owned(prop_id), Value::Object(addr));
                    }
                }
                VCardProperty::Email => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                        ],
                        JSContactProperty::Emails,
                        JSContactProperty::Address,
                        [None, None],
                    );
                }
                VCardProperty::Impp => {
                    entry.set_map_name();
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                            VCardParameterName::ServiceType,
                            VCardParameterName::Username,
                        ],
                        JSContactProperty::OnlineServices,
                        JSContactProperty::Uri,
                        [None, None],
                    );
                }
                VCardProperty::Lang => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                        ],
                        JSContactProperty::PreferredLanguages,
                        JSContactProperty::Language,
                        [None, None],
                    );
                }
                VCardProperty::Language | VCardProperty::Prodid | VCardProperty::Uid => {
                    let property = match &entry.entry.name {
                        VCardProperty::Language => JSContactProperty::Language,
                        VCardProperty::Prodid => JSContactProperty::ProdId,
                        VCardProperty::Uid => JSContactProperty::Uid,
                        _ => unreachable!(),
                    };

                    if !state.entries.contains(&property)
                        && let Some(text) = entry.to_text()
                    {
                        entry.set_converted_to(|| {
                            String::from_pointer([property.to_cow().as_ref()])
                        });
                        state.entries.insert(property, text);
                    }
                }
                VCardProperty::Socialprofile => {
                    let is_text = entry.take_text_value_type() || entry.move_username_to_value();
                    state.map_named_entry(
                        &mut entry,
                        if is_text {
                            &[
                                VCardParameterName::Type,
                                VCardParameterName::Pref,
                                VCardParameterName::PropId,
                                VCardParameterName::Label,
                                VCardParameterName::ServiceType,
                            ]
                        } else {
                            &[
                                VCardParameterName::Type,
                                VCardParameterName::Pref,
                                VCardParameterName::PropId,
                                VCardParameterName::Label,
                                VCardParameterName::ServiceType,
                                VCardParameterName::Username,
                            ]
                        },
                        JSContactProperty::OnlineServices,
                        if is_text {
                            JSContactProperty::User
                        } else {
                            JSContactProperty::Uri
                        },
                        [None, None],
                    );
                }
                VCardProperty::Tel => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                        ],
                        JSContactProperty::Phones,
                        JSContactProperty::Number,
                        [None, None],
                    );
                }
                VCardProperty::ContactUri => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                            VCardParameterName::Mediatype,
                        ],
                        JSContactProperty::Links,
                        JSContactProperty::Uri,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(JSContactKind::Contact)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Title => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::PropId,
                            VCardParameterName::Altid,
                            VCardParameterName::Language,
                        ],
                        JSContactProperty::Titles,
                        JSContactProperty::Name,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(JSContactKind::Title)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Role => {
                    let prop_id = state
                        .find_prop_id(
                            &VCardProperty::Org,
                            entry.entry.group.as_deref(),
                            entry.entry.alt_id(),
                        )
                        .map(|s| s.to_string());
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::PropId,
                            VCardParameterName::Altid,
                            VCardParameterName::Language,
                        ],
                        JSContactProperty::Titles,
                        JSContactProperty::Name,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(JSContactKind::Role)),
                            )),
                            prop_id.map(|prop_id| {
                                (
                                    Key::Property(JSContactProperty::OrganizationId),
                                    Value::Str(prop_id.into()),
                                )
                            }),
                        ],
                    );
                }
                VCardProperty::Hobby | VCardProperty::Interest | VCardProperty::Expertise => {
                    let kind = match &entry.entry.name {
                        VCardProperty::Expertise => JSContactKind::Expertise,
                        VCardProperty::Hobby => JSContactKind::Hobby,
                        VCardProperty::Interest => JSContactKind::Interest,
                        _ => unreachable!(),
                    };
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Level,
                            VCardParameterName::Index,
                            VCardParameterName::Label,
                            VCardParameterName::PropId,
                            VCardParameterName::Altid,
                            VCardParameterName::Language,
                        ],
                        JSContactProperty::PersonalInfo,
                        JSContactProperty::Value,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(kind)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Org => {
                    let units = entry
                        .text_parts_borrowed()
                        .skip(1)
                        .map(|unit| {
                            Value::Object(Map::from(vec![(
                                Key::Property(JSContactProperty::Name),
                                Value::Str(unit.to_string().into()),
                            )]))
                        })
                        .collect::<Vec<_>>();

                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::PropId,
                            VCardParameterName::SortAs,
                        ],
                        JSContactProperty::Organizations,
                        JSContactProperty::Name,
                        [
                            (!units.is_empty()).then_some((
                                Key::Property(JSContactProperty::Units),
                                Value::Array(units),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Member | VCardProperty::Categories => {
                    let key = if entry.entry.name == VCardProperty::Member {
                        JSContactProperty::Members
                    } else {
                        JSContactProperty::Keywords
                    };

                    entry.set_converted_to(|| String::from_pointer([key.to_cow().as_ref()]));

                    let obj = state.get_mut_object_or_insert(key);

                    for key in entry.entry.values.drain(..).filter_map(|v| v.into_text()) {
                        obj.insert(Key::from(key), Value::Bool(true));
                    }
                }
                VCardProperty::Created | VCardProperty::Rev => {
                    let property = match &entry.entry.name {
                        VCardProperty::Created => JSContactProperty::Created,
                        VCardProperty::Rev => JSContactProperty::Updated,
                        _ => unreachable!(),
                    };

                    if !state.entries.contains(&property)
                        && let Some(text) = entry.to_timestamp()
                    {
                        entry.set_converted_to(|| {
                            String::from_pointer([property.to_cow().as_ref()])
                        });
                        state.entries.insert(property, text);
                    }
                }
                VCardProperty::Note => {
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Author,
                            VCardParameterName::AuthorName,
                            VCardParameterName::Created,
                            VCardParameterName::Language,
                            VCardParameterName::PropId,
                        ],
                        JSContactProperty::Notes,
                        JSContactProperty::Note,
                        [None, None],
                    );
                }
                VCardProperty::Url | VCardProperty::Key | VCardProperty::Caladruri => {
                    let prop = match &entry.entry.name {
                        VCardProperty::Url => JSContactProperty::Links,
                        VCardProperty::Key => JSContactProperty::CryptoKeys,
                        VCardProperty::Caladruri => JSContactProperty::SchedulingAddresses,
                        _ => unreachable!(),
                    };
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                            VCardParameterName::Mediatype,
                        ],
                        prop,
                        JSContactProperty::Uri,
                        [None, None],
                    );
                }
                VCardProperty::Fburl | VCardProperty::Caluri => {
                    let kind = match &entry.entry.name {
                        VCardProperty::Fburl => JSContactKind::FreeBusy,
                        VCardProperty::Caluri => JSContactKind::Calendar,
                        _ => unreachable!(),
                    };
                    state.map_named_entry(
                        &mut entry,
                        &[
                            VCardParameterName::Type,
                            VCardParameterName::Pref,
                            VCardParameterName::PropId,
                            VCardParameterName::Label,
                            VCardParameterName::Mediatype,
                        ],
                        JSContactProperty::Calendars,
                        JSContactProperty::Uri,
                        [
                            Some((
                                Key::Property(JSContactProperty::Kind),
                                Value::Element(JSContactValue::Kind(kind)),
                            )),
                            None,
                        ],
                    );
                }
                VCardProperty::Related => {
                    if let Some(text) = entry.to_string() {
                        let mut params = ExtractedParams::default();
                        params.extract(
                            &mut entry.entry.params,
                            &[VCardParameterName::Type],
                            state.default_language.as_deref(),
                        );
                        entry.set_converted_to(|| {
                            String::from_pointer([
                                JSContactProperty::RelatedTo::<I>.to_cow().as_ref(),
                                text.as_ref(),
                            ])
                        });
                        state
                            .get_mut_object_or_insert(JSContactProperty::RelatedTo)
                            .insert(
                                Key::from(text),
                                Value::Object(Map::from(vec![(
                                    Key::Property(JSContactProperty::Relation),
                                    Value::Object(params.types().into_iter().fold(
                                        Map::new(),
                                        |mut relation, typ| {
                                            relation.insert(
                                                Key::Owned(typ.into_string().to_ascii_lowercase()),
                                                Value::Bool(true),
                                            );
                                            relation
                                        },
                                    )),
                                )])),
                            );
                    }
                }
                VCardProperty::Tz | VCardProperty::Geo => {
                    let (key, value) = match &entry.entry.name {
                        VCardProperty::Tz => {
                            (Key::Property(JSContactProperty::TimeZone), entry.to_tz())
                        }
                        VCardProperty::Geo => (
                            Key::Property(JSContactProperty::Coordinates),
                            entry.to_text(),
                        ),
                        _ => unreachable!(),
                    };

                    if let Some(value) = value {
                        let prop_id = state
                            .find_prop_id(
                                &VCardProperty::Adr,
                                entry.entry.group.as_deref(),
                                entry.entry.alt_id(),
                            )
                            .map(|s| s.to_string());

                        entry.set_map_name();

                        let addresses =
                            state.get_mut_object_or_insert(JSContactProperty::Addresses);
                        if let Some(addr) = prop_id
                            .as_deref()
                            .and_then(|prop_id| {
                                addresses
                                    .as_mut_vec()
                                    .iter_mut()
                                    .find_map(|(member, value)| {
                                        (*member == prop_id).then_some(value)
                                    })
                            })
                            .and_then(|v| v.as_object_mut())
                            .filter(|v| !v.contains_key(&key))
                        {
                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Addresses::<I>.to_cow().as_ref(),
                                    prop_id.as_deref().unwrap_or_default(),
                                    key.to_string().as_ref(),
                                ])
                            });
                            addr.insert(key, value);
                        } else {
                            let prop_id = addresses.named_key(None);
                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    JSContactProperty::Addresses::<I>.to_cow().as_ref(),
                                    prop_id.as_str(),
                                    key.to_string().as_ref(),
                                ])
                            });
                            addresses.insert_unchecked(
                                Key::Owned(prop_id),
                                Value::Object(Map::from(vec![(key, value)])),
                            );
                        }
                    }
                }
                VCardProperty::Other(name)
                    if name.eq_ignore_ascii_case("X-ABLabel") && entry.entry.group.is_some() =>
                {
                    if let Some(prop) = state.find_entry_by_group(entry.entry.group.as_deref()) {
                        let prop_id = prop.prop_id.to_string();
                        let prop_js = prop.prop_js.clone();

                        if let Some(obj) = state
                            .entries
                            .get_mut(&prop_js)
                            .and_then(|v| v.as_object_mut())
                            .and_then(|v| v.get_mut(&Key::Owned(prop_id.clone())))
                            .and_then(|v| v.as_object_mut())
                            .filter(|v| !v.contains_key(&Key::Property(JSContactProperty::Label)))
                            && let Some(value) = entry.to_text()
                        {
                            obj.insert_unchecked(Key::Property(JSContactProperty::Label), value);
                            entry.set_map_name();
                            entry.set_converted_to(|| {
                                String::from_pointer([
                                    prop_js.to_cow().as_ref(),
                                    prop_id.as_str(),
                                    JSContactProperty::Label::<I>.to_cow().as_ref(),
                                ])
                            });
                        }
                    }
                }
                VCardProperty::Jsprop => {
                    if let Some(VCardParameter {
                        name: VCardParameterName::Jsptr,
                        value: VCardParameterValue::Text(ptr),
                    }) = entry.entry.params.first()
                    {
                        let ptr = JsonPointer::<JSContactProperty<I>>::parse(ptr);

                        if JSContactProperty::is_metadata_pointer(&ptr) {
                            continue;
                        }
                        if let Some(VCardValue::Text(text)) = entry.entry.values.first()
                            && let Some(patch) = ptr.parse_jsprop_value(text)
                        {
                            state.patch_objects.push((ptr, patch));
                            continue;
                        }
                    }
                }
                VCardProperty::Version
                | VCardProperty::Xml
                | VCardProperty::Gender
                | VCardProperty::Clientpidmap
                | VCardProperty::Other(_) => (),
                VCardProperty::Begin | VCardProperty::End => {
                    continue;
                }
            }

            state.add_conversion_props(entry);
        }

        state.into_jscontact()
    }
}
