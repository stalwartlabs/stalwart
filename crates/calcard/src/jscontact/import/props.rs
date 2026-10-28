/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    common::{
        Data, IanaString, IanaType,
        blob::{BlobIds, sniff_media_type},
        format::AsciiPush,
        jsprop::{
            ordered::OrderedMap,
            text::{AsciiString, PointerString},
        },
    },
    jscontact::{
        JSCONTACT_VERSION, JSContact, JSContactId, JSContactKind, JSContactProperty, JSContactType,
        JSContactValue,
        import::{
            CardProperties, EntryState, ExtractedParams, Localization, Member, PropIdKey, PropIds,
            State, VCardConvertedProperty, VCardParams,
        },
    },
    vcard::{
        VCard, VCardEntry, VCardParameter, VCardParameterName, VCardParameterValue, VCardProperty,
        VCardValue, VCardValueType,
    },
};
use jmap_tools::{JsonPointerHandler, JsonPointerItem, Key, Map, Property, Value};
use std::{
    borrow::Cow,
    hash::{Hash, Hasher},
    iter::once,
    mem,
};

const NUMBERED_KEY_CAPACITY: usize = 8;

#[derive(Clone, Copy)]
struct LanguageTag<'x>(&'x str);

impl<I, B> State<I, B>
where
    I: JSContactId,
    B: JSContactId,
{
    pub(super) fn new(vcard: &mut VCard, include_vcard_converted: bool) -> Self {
        let mut entries = CardProperties::with_capacity(vcard.entries.len().min(20) + 4);

        entries.insert(
            JSContactProperty::Type,
            Value::Element(JSContactValue::Type(JSContactType::Card)),
        );
        entries.insert(
            JSContactProperty::Version,
            Value::Str(JSCONTACT_VERSION.into()),
        );

        let mut default_language = None;
        let mut language_counts: OrderedMap<LanguageTag<'_>, usize> = OrderedMap::default();
        let mut language_count = 0;
        let mut language_first_found = None;
        let mut langful_names: OrderedMap<&VCardProperty, ()> = OrderedMap::default();
        let mut name_alt_ids: OrderedMap<&str, usize> = OrderedMap::default();
        let mut has_prop_id_lookups = false;
        for entry in &vcard.entries {
            has_prop_id_lookups |= entry.looks_up_prop_ids();
            if let Some(lang) = entry.language() {
                language_counts.upsert(LanguageTag(lang), || 0, |count| *count += 1);
                if language_first_found.is_none() {
                    language_first_found = Some(lang);
                }
                language_count += 1;
                langful_names.insert_if_absent(&entry.name, ());
            }

            match &entry.name {
                VCardProperty::Language => {
                    if let Some(VCardValue::Text(lang)) = entry.values.first() {
                        default_language = Some(lang.to_ascii_lowercase());
                    }
                }
                VCardProperty::N => {
                    if let Some(alt_id) = entry.alt_id() {
                        name_alt_ids.upsert(alt_id, || 0, |count| *count += 1);
                    }
                }
                _ => (),
            }
        }

        let mut name_alt_id = None;
        let mut name_alt_id_count = 0;
        for (&alt_id, &count) in name_alt_ids.iter() {
            if count > name_alt_id_count {
                name_alt_id = Some(alt_id);
                name_alt_id_count = count;
            }
        }
        let name_alt_id = name_alt_id.map(str::to_string);

        if default_language.is_none()
            && language_count > 1
            && let Some(min_count) = language_counts.iter().map(|(_, &count)| count).min()
            && let Some((LanguageTag(most_used), max_count)) =
                language_counts.into_iter().max_by_key(|&(_, count)| count)
            && max_count
                > vcard
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.language().is_none() && langful_names.contains_key(&entry.name)
                    })
                    .count()
        {
            let lang = if max_count == min_count
                && let Some(first) = language_first_found
            {
                first
            } else {
                most_used
            }
            .to_ascii_lowercase();

            default_language = Some(lang.clone());
            vcard
                .entries
                .push(VCardEntry::new(VCardProperty::Language).with_value(lang));
        }

        let sort_key = |entry: &VCardEntry| {
            let lang = entry.language();
            let weight = u32::from(lang.is_some() && default_language.as_deref() != lang);

            match &entry.name {
                VCardProperty::Birthplace | VCardProperty::Deathplace | VCardProperty::Role => {
                    weight + 2
                }
                VCardProperty::Other(name) if name.eq_ignore_ascii_case("X-ABLabel") => weight + 3,
                _ => weight,
            }
        };
        if !vcard.entries.is_sorted_by_key(sort_key) {
            vcard.entries.sort_by_key(sort_key);
        }

        Self {
            entries,
            default_language,
            localizations: Default::default(),
            prop_ids: PropIds::new(has_prop_id_lookups, &vcard.entries),
            vcard_converted_properties: Default::default(),
            vcard_properties: Default::default(),
            patch_objects: Default::default(),
            name_alt_id,
            has_fn: false,
            has_n: false,
            has_n_localization: false,
            has_fn_localization: false,
            has_gram_gender: false,
            include_vcard_converted,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn map_named_entry(
        &mut self,
        entry: &mut EntryState,
        extract: &[VCardParameterName],
        top_property_name: JSContactProperty<I>,
        value_property_name: JSContactProperty<I>,
        extra_properties: [Option<Member<I, B>>; 2],
    ) {
        let value = if !matches!(
            entry.entry.name,
            VCardProperty::Anniversary | VCardProperty::Bday | VCardProperty::Deathdate
        ) {
            entry.to_text()
        } else {
            entry.to_anniversary()
        };

        if let Some(value) = value {
            self.map_named_value(
                entry,
                extract,
                top_property_name,
                value_property_name,
                value,
                extra_properties,
            );
        }
    }

    pub(super) fn map_blob_media(
        &mut self,
        entry: &mut EntryState,
        kind: JSContactKind,
        blob_ids: &mut BlobIds<'_, B>,
    ) -> bool {
        if !matches!(
            entry.entry.values.first(),
            Some(VCardValue::Binary(data)) if !data.data.is_empty()
        ) {
            return false;
        }
        let mut values = mem::take(&mut entry.entry.values).into_iter();
        let Some(VCardValue::Binary(data)) = values.next() else {
            return false;
        };
        let media_type_param = entry
            .entry
            .params
            .iter()
            .find_map(|param| param.as_media_type());
        let media_type = match media_type_param.or(data
            .content_type
            .as_deref()
            .filter(|media_type| !media_type.is_empty()))
        {
            Some(media_type) => Cow::Owned(media_type.to_string()),
            None => Cow::Borrowed(sniff_media_type(&data.data)),
        };
        let has_media_type_param = media_type_param.is_some();

        match blob_ids.blob_id(data.data, Some(media_type.as_ref())) {
            Ok(generated) => {
                entry.entry.params.retain(|param| {
                    param.name != VCardParameterName::Mediatype || param.as_media_type().is_some()
                });
                self.map_named_value(
                    entry,
                    &[
                        VCardParameterName::Mediatype,
                        VCardParameterName::Pref,
                        VCardParameterName::PropId,
                        VCardParameterName::Label,
                    ],
                    JSContactProperty::Media,
                    JSContactProperty::BlobId,
                    Value::Element(JSContactValue::BlobId(generated.blob_id)),
                    [
                        Some((
                            Key::Property(JSContactProperty::Kind),
                            Value::Element(JSContactValue::Kind(kind)),
                        )),
                        (!has_media_type_param).then(|| {
                            (
                                Key::Property(JSContactProperty::MediaType),
                                Value::Str(media_type.into_owned().into()),
                            )
                        }),
                    ],
                );
                true
            }
            Err(bytes) => {
                entry.entry.values = once(VCardValue::Binary(Box::new(Data {
                    content_type: data.content_type,
                    data: bytes,
                })))
                .chain(values)
                .collect();
                false
            }
        }
    }

    fn map_named_value(
        &mut self,
        entry: &mut EntryState,
        extract: &[VCardParameterName],
        top_property_name: JSContactProperty<I>,
        value_property_name: JSContactProperty<I>,
        value: Value<'static, JSContactProperty<I>, JSContactValue<I, B>>,
        extra_properties: [Option<Member<I, B>>; 2],
    ) {
        let mut params = ExtractedParams::default();
        params.extract(
            &mut entry.entry.params,
            extract,
            self.default_language.as_deref(),
        );
        let prop_id = params.prop_id();
        let alt_id = params.alt_id();
        let sub_property = top_property_name.sub_property();

        if let Some(language) = params.language() {
            if let Some(patch) = prop_id
                .as_deref()
                .filter(|prop_id| self.has_prop_id(&entry.entry.name, prop_id))
                .or_else(|| {
                    self.find_prop_id(
                        &entry.entry.name,
                        entry.entry.group.as_deref(),
                        alt_id.as_deref(),
                    )
                })
                .map(|prop_id| {
                    if let Some(sub_property) = sub_property.as_ref() {
                        format!(
                            "{}/{}/{}/{}",
                            top_property_name.to_cow().as_ref(),
                            sub_property.to_cow().as_ref(),
                            prop_id,
                            value_property_name.to_cow().as_ref()
                        )
                    } else {
                        format!(
                            "{}/{}/{}",
                            top_property_name.to_cow().as_ref(),
                            prop_id,
                            value_property_name.to_cow().as_ref()
                        )
                    }
                })
            {
                entry.set_converted_to(|| {
                    String::from_pointer([
                        JSContactProperty::Localizations::<I>.to_cow().as_ref(),
                        language.as_str(),
                        patch.as_str(),
                    ])
                });

                self.localize(language, |localizations| {
                    let base_path = patch
                        .rsplit_once('/')
                        .map_or(patch.as_str(), |(base, _)| base);

                    params
                        .members::<I, B>(&entry.entry.name)
                        .for_each(|prop, value| {
                            localizations
                                .push((format!("{}/{}", base_path, prop.to_string()), value));
                        });

                    localizations.push((patch, value));
                });
                return;
            } else {
                entry.entry.params.push(VCardParameter::language(language));
            }
        }

        let mut entries = self
            .entries
            .get_mut_object_or_insert(top_property_name.clone());
        if let Some(sub_property) = sub_property.clone() {
            let Some(sub_entries) = entries
                .insert_or_get_mut(sub_property, Value::Object(Map::from(vec![])))
                .as_object_mut()
            else {
                return;
            };
            entries = sub_entries;
        }

        let members = params.members::<I, B>(&entry.entry.name);
        let mut obj =
            Vec::with_capacity(1 + extra_properties.iter().flatten().count() + members.len());
        obj.push((Key::Property(value_property_name.clone()), value));
        obj.extend(extra_properties.into_iter().flatten());
        members.append_to(&mut obj);
        let prop_id = entries.named_key(prop_id);

        if let Some(sub_property) = sub_property {
            entry.set_converted_to(|| {
                String::from_pointer([
                    top_property_name.to_cow().as_ref(),
                    sub_property.to_cow().as_ref(),
                    prop_id.as_str(),
                    value_property_name.to_cow().as_ref(),
                ])
            });
        } else {
            entry.set_converted_to(|| {
                String::from_pointer([
                    top_property_name.to_cow().as_ref(),
                    prop_id.as_str(),
                    value_property_name.to_cow().as_ref(),
                ])
            });
        }

        self.prop_ids
            .track(&entry.entry, top_property_name, alt_id, &prop_id);
        entries.insert_unchecked(Key::Owned(prop_id), Value::Object(Map::from(obj)));
    }

    #[inline]
    pub(super) fn get_mut_object_or_insert(
        &mut self,
        key: JSContactProperty<I>,
    ) -> &mut Map<'static, JSContactProperty<I>, JSContactValue<I, B>> {
        self.entries.get_mut_object_or_insert(key)
    }

    #[inline]
    pub(super) fn has_property(&self, key: JSContactProperty<I>) -> bool {
        self.entries.contains(&key)
    }

    pub(super) fn localize(
        &mut self,
        language: String,
        update: impl FnOnce(&mut Localization<I, B>),
    ) {
        self.localizations.upsert(language, Vec::new, update);
    }

    pub(super) fn add_conversion_props(&mut self, mut entry: EntryState) {
        if self.include_vcard_converted {
            if let Some(converted_to) = entry.converted_to.take() {
                if entry.has_conversion_params() {
                    let mut value_type = None;

                    match self.vcard_converted_properties.get_mut(&converted_to) {
                        Some(conv_prop) => {
                            entry.jcal_parameters(&mut conv_prop.params, &mut value_type);
                        }
                        None => {
                            let mut params = VCardParams::default();
                            entry.jcal_parameters(&mut params, &mut value_type);
                            if let Some(value_type) = value_type {
                                params.set(
                                    VCardParameterName::Value,
                                    vec![Value::Str(value_type.into_string())],
                                );
                            }
                            if !params.0.is_empty() || entry.map_name {
                                self.vcard_converted_properties.push(
                                    converted_to,
                                    VCardConvertedProperty {
                                        name: if entry.map_name {
                                            Some(entry.entry.name)
                                        } else {
                                            None
                                        },
                                        params,
                                    },
                                );
                            }
                        }
                    }
                }
            } else {
                let mut value_type = None;
                let mut params = VCardParams::default();

                entry.jcal_parameters(&mut params, &mut value_type);

                let mut values = entry.entry.values.into_iter();
                let values = match (values.next(), values.len()) {
                    (Some(value), 0) => value.into_jscontact_value(value_type.as_ref()),
                    (first, _) => Value::Array(
                        first
                            .into_iter()
                            .chain(values)
                            .map(|value| value.into_jscontact_value(value_type.as_ref()))
                            .collect(),
                    ),
                };
                let name = match entry.entry.name {
                    VCardProperty::Other(mut name) => {
                        name.make_ascii_lowercase();
                        name
                    }
                    name => name.as_str().to_ascii_lowercase(),
                };
                self.vcard_properties.push(Value::Array(vec![
                    Value::Str(name.into()),
                    Value::Object(
                        params
                            .into_jscontact_value()
                            .unwrap_or(Map::from(Vec::new())),
                    ),
                    Value::Str(
                        value_type
                            .map(|v| v.into_string())
                            .unwrap_or(Cow::Borrowed("unknown")),
                    ),
                    values,
                ]));
            }
        }
    }

    pub(super) fn find_prop_id(
        &self,
        prop: &VCardProperty,
        group: Option<&str>,
        alt_id: Option<&str>,
    ) -> Option<&str> {
        self.prop_ids
            .keys
            .iter()
            .find(|p| {
                p.prop == *prop && p.group.as_deref() == group && p.alt_id.as_deref() == alt_id
            })
            .map(|p| p.prop_id.as_str())
    }

    pub(super) fn find_entry_by_group(&self, group: Option<&str>) -> Option<&PropIdKey<I>> {
        self.prop_ids
            .keys
            .iter()
            .find(|p| p.group.as_deref() == group)
    }

    pub(super) fn has_prop_id(&self, prop: &VCardProperty, prop_id: &str) -> bool {
        self.prop_ids
            .keys
            .iter()
            .any(|p| p.prop == *prop && p.prop_id == prop_id)
    }

    pub(super) fn into_jscontact(mut self) -> JSContact<'static, I, B> {
        if !self.localizations.is_empty() {
            self.entries.insert(
                JSContactProperty::Localizations,
                Value::Object(
                    self.localizations
                        .into_iter()
                        .map(|(lang, locals)| {
                            (
                                Key::Owned(lang),
                                Value::Object(
                                    locals
                                        .into_iter()
                                        .map(|(key, value)| (Key::Owned(key), value))
                                        .collect(),
                                ),
                            )
                        })
                        .collect(),
                ),
            );
        }

        let mut vcard_obj = Map::from(Vec::new());
        if !self.vcard_converted_properties.is_empty() {
            let mut converted_properties =
                Map::from(Vec::with_capacity(self.vcard_converted_properties.len()));

            for (converted_to, props) in self.vcard_converted_properties {
                let mut obj = Map::from(Vec::with_capacity(2));
                if let Some(params) = props.params.into_jscontact_value() {
                    obj.insert(
                        Key::Property(JSContactProperty::Parameters),
                        Value::Object(params),
                    );
                }
                if let Some(name) = props.name {
                    obj.insert(
                        Key::Property(JSContactProperty::Name),
                        Value::Str(name.as_str().to_ascii_lowercase().into()),
                    );
                }

                converted_properties.insert_unchecked(Key::Owned(converted_to), Value::Object(obj));
            }

            vcard_obj.insert_unchecked(
                Key::Property(JSContactProperty::ConvertedProperties),
                Value::Object(converted_properties),
            );
        }

        if !self.vcard_properties.is_empty() {
            vcard_obj.insert_unchecked(
                Key::Property(JSContactProperty::Properties),
                Value::Array(self.vcard_properties),
            );
        }

        if !vcard_obj.is_empty() {
            self.entries
                .insert(JSContactProperty::VCard, Value::Object(vcard_obj));
        }

        let mut obj = Value::Object(self.entries.into_map());
        if !self.patch_objects.is_empty() {
            for (ptr, patch) in self.patch_objects {
                patch_card(&mut obj, ptr.as_slice(), patch);
            }
        }

        JSContact(obj)
    }
}

impl PartialEq for LanguageTag<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

impl Eq for LanguageTag<'_> {}

impl Hash for LanguageTag<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.0.bytes() {
            state.write_u8(byte.to_ascii_lowercase());
        }
        state.write_usize(self.0.len());
    }
}

impl<I> JSContactProperty<I>
where
    I: JSContactId,
{
    pub(super) fn sub_property(&self) -> Option<JSContactProperty<I>> {
        match self {
            JSContactProperty::SpeakToAs => Some(JSContactProperty::Pronouns),
            _ => None,
        }
    }
}

impl VCardValue {
    pub(super) fn into_jscontact_value<I: JSContactId, B: JSContactId>(
        self,
        value_type: Option<&IanaType<VCardValueType, String>>,
    ) -> Value<'static, JSContactProperty<I>, JSContactValue<I, B>> {
        match self {
            VCardValue::Text(v) => Value::Str(v.into()),
            VCardValue::Component(v) => Value::Str(v.join(",").into()),
            VCardValue::Integer(v) => Value::Number(v.into()),
            VCardValue::Float(v) => Value::Number(v.into()),
            VCardValue::Boolean(v) => Value::Bool(v),
            VCardValue::PartialDateTime(v) => {
                let mut out = String::new();
                let _ = v.format_as_vcard(
                    &mut out,
                    value_type
                        .and_then(|v| v.iana())
                        .unwrap_or(if v.has_date() && v.has_time() {
                            &VCardValueType::Timestamp
                        } else {
                            &VCardValueType::DateAndOrTime
                        }),
                );
                Value::Str(out.into())
            }
            VCardValue::Binary(v) => Value::Str(v.to_unwrapped_string().into()),
            VCardValue::Sex(v) => Value::Str(v.as_str().into()),
            VCardValue::GramGender(v) => Value::Str(v.as_str().into()),
            VCardValue::Kind(v) => Value::Str(v.as_str().into()),
        }
    }
}

impl ExtractedParams {
    pub(super) fn extract(
        &mut self,
        params: &mut Vec<VCardParameter>,
        extract: &[VCardParameterName],
        default_language: Option<&str>,
    ) {
        let p = self;

        params.retain_mut(|param| match &param.name {
            VCardParameterName::Language => {
                let v = param.take_value().into_text().to_ascii_lowercase();
                if p.language.is_none()
                    && default_language.is_none_or(|lang| lang != v)
                    && extract.contains(&VCardParameterName::Language)
                {
                    p.language = Some(v);
                    false
                } else {
                    param.value = VCardParameterValue::Text(v);
                    true
                }
            }
            VCardParameterName::Pref
                if p.pref.is_none() && extract.contains(&VCardParameterName::Pref) =>
            {
                p.pref = param.value.as_integer().and_then(|v| v.into_iana());
                false
            }
            VCardParameterName::Author
                if p.author.is_none() && extract.contains(&VCardParameterName::Author) =>
            {
                p.author = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::AuthorName
                if p.author_name.is_none() && extract.contains(&VCardParameterName::AuthorName) =>
            {
                p.author_name = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Mediatype
                if p.media_type.is_none() && extract.contains(&VCardParameterName::Mediatype) =>
            {
                p.media_type = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Calscale
                if p.calscale.is_none() && extract.contains(&VCardParameterName::Calscale) =>
            {
                p.calscale = param.take_value().into_calscale();
                false
            }
            VCardParameterName::SortAs
                if p.sort_as.is_none() && extract.contains(&VCardParameterName::SortAs) =>
            {
                p.sort_as = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Geo
                if p.geo.is_none() && extract.contains(&VCardParameterName::Geo) =>
            {
                p.geo = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Tz
                if p.tz.is_none() && extract.contains(&VCardParameterName::Tz) =>
            {
                p.tz = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Index
                if p.index.is_none() && extract.contains(&VCardParameterName::Index) =>
            {
                p.index = param.value.as_integer().and_then(|v| v.into_iana());
                false
            }
            VCardParameterName::Level
                if p.level.is_none() && extract.contains(&VCardParameterName::Level) =>
            {
                p.level = param.take_value().into_level();
                false
            }
            VCardParameterName::Cc
                if p.country_code.is_none() && extract.contains(&VCardParameterName::Cc) =>
            {
                p.country_code = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Created
                if p.created.is_none() && extract.contains(&VCardParameterName::Created) =>
            {
                p.created = param
                    .take_value()
                    .into_timestamp()
                    .and_then(|v| v.into_iana());
                false
            }
            VCardParameterName::Label
                if p.label.is_none() && extract.contains(&VCardParameterName::Label) =>
            {
                p.label = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Phonetic
                if p.phonetic_system.is_none()
                    && extract.contains(&VCardParameterName::Phonetic) =>
            {
                p.phonetic_system = param.take_value().into_phonetic();
                false
            }
            VCardParameterName::Script
                if p.phonetic_script.is_none() && extract.contains(&VCardParameterName::Script) =>
            {
                p.phonetic_script = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::ServiceType
                if p.service_type.is_none()
                    && extract.contains(&VCardParameterName::ServiceType) =>
            {
                p.service_type = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Username
                if p.username.is_none() && extract.contains(&VCardParameterName::Username) =>
            {
                p.username = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::PropId
                if p.prop_id.is_none() && extract.contains(&VCardParameterName::PropId) =>
            {
                p.prop_id = Some(param.take_value().into_text().into_owned());
                false
            }
            VCardParameterName::Altid if p.alt_id.is_none() => {
                p.alt_id = param.value.as_text().map(|v| v.to_string());
                true
            }
            VCardParameterName::Type if extract.contains(&VCardParameterName::Type) => {
                if let Some(typ) = param.take_value().into_type() {
                    p.types.push(typ);
                }
                false
            }
            VCardParameterName::Jscomps if extract.contains(&VCardParameterName::Jscomps) => {
                if let Some(jscomps) = param.take_value().into_jscomps() {
                    p.jscomps = jscomps;
                }
                false
            }
            _ => true,
        });
    }
}

pub(super) trait NamedKey {
    fn named_key(&self, key: Option<String>) -> String;
}

impl<I: JSContactId, B: JSContactId> NamedKey
    for Map<'static, JSContactProperty<I>, JSContactValue<I, B>>
{
    fn named_key(&self, key: Option<String>) -> String {
        let number = self.len() as u64 + 1;
        let key = key.unwrap_or_else(|| {
            let mut key = AsciiString::with_capacity(NUMBERED_KEY_CAPACITY);
            let _ = key.push_byte(b'k').and_then(|()| key.push_u64(number));
            key.into_string()
        });
        if self.contains_key(&Key::Borrowed(key.as_str())) {
            let mut key = AsciiString::from(key);
            let _ = key.push_byte(b'-').and_then(|()| key.push_u64(number));
            key.into_string()
        } else {
            key
        }
    }
}

impl<I: JSContactId> PropIds<I> {
    fn new(is_enabled: bool, entries: &[VCardEntry]) -> Self {
        Self {
            keys: if is_enabled {
                Vec::with_capacity(
                    entries
                        .iter()
                        .filter(|entry| entry.name.is_named_property())
                        .count(),
                )
            } else {
                Vec::new()
            },
            is_enabled,
        }
    }

    pub(super) fn track(
        &mut self,
        entry: &VCardEntry,
        prop_js: JSContactProperty<I>,
        alt_id: Option<String>,
        prop_id: &str,
    ) {
        if self.is_enabled {
            self.keys.push(PropIdKey {
                prop_id: prop_id.to_string(),
                prop_js,
                prop: entry.name.clone(),
                group: entry.group.clone(),
                alt_id,
            });
        }
    }
}

impl VCardEntry {
    fn looks_up_prop_ids(&self) -> bool {
        match &self.name {
            VCardProperty::Birthplace
            | VCardProperty::Deathplace
            | VCardProperty::Role
            | VCardProperty::Tz
            | VCardProperty::Geo => true,
            VCardProperty::Other(name)
                if self.group.is_some() && name.eq_ignore_ascii_case("X-ABLabel") =>
            {
                true
            }
            _ => self
                .params
                .iter()
                .any(|param| param.name == VCardParameterName::Language),
        }
    }
}

impl VCardProperty {
    fn is_named_property(&self) -> bool {
        matches!(
            self,
            VCardProperty::Source
                | VCardProperty::OrgDirectory
                | VCardProperty::Anniversary
                | VCardProperty::Bday
                | VCardProperty::Deathdate
                | VCardProperty::Birthplace
                | VCardProperty::Deathplace
                | VCardProperty::Pronouns
                | VCardProperty::Nickname
                | VCardProperty::Photo
                | VCardProperty::Logo
                | VCardProperty::Sound
                | VCardProperty::Adr
                | VCardProperty::Email
                | VCardProperty::Impp
                | VCardProperty::Lang
                | VCardProperty::Socialprofile
                | VCardProperty::Tel
                | VCardProperty::ContactUri
                | VCardProperty::Title
                | VCardProperty::Role
                | VCardProperty::Hobby
                | VCardProperty::Interest
                | VCardProperty::Expertise
                | VCardProperty::Org
                | VCardProperty::Note
                | VCardProperty::Url
                | VCardProperty::Key
                | VCardProperty::Caladruri
                | VCardProperty::Fburl
                | VCardProperty::Caluri
        )
    }
}

fn patch_card<I: JSContactId, B: JSContactId>(
    value: &mut Value<'static, JSContactProperty<I>, JSContactValue<I, B>>,
    pointer: &[JsonPointerItem<JSContactProperty<I>>],
    patch: Value<'static, JSContactProperty<I>, JSContactValue<I, B>>,
) -> bool {
    match (pointer.split_first(), value) {
        (Some((JsonPointerItem::Root, rest)), value) => patch_card(value, rest, patch),
        (Some((JsonPointerItem::Number(index), rest)), Value::Array(items)) => {
            match (items.get_mut(*index as usize), rest.is_empty()) {
                (Some(item), false) => patch_card(item, rest, patch),
                (Some(item), true) if !patch.is_null() => {
                    *item = patch;
                    true
                }
                _ => false,
            }
        }
        (Some((JsonPointerItem::Key(_) | JsonPointerItem::Number(_), rest)), value)
            if rest
                .iter()
                .all(|item| !matches!(item, JsonPointerItem::Number(_))) =>
        {
            value.patch_jptr(pointer.iter().peekable(), patch)
        }
        (Some((JsonPointerItem::Key(key), rest)), Value::Object(obj)) => obj
            .get_mut(key)
            .is_some_and(|item| patch_card(item, rest, patch)),
        (Some((JsonPointerItem::Number(index), rest)), Value::Object(obj)) => {
            let index = index.to_string();
            obj.iter_mut()
                .find(|(key, _)| key.to_string() == index)
                .is_some_and(|(_, item)| patch_card(item, rest, patch))
        }
        _ => false,
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../../stalwart-tests/unit/calcard/src/jscontact/import/props/tests.rs"]
mod tests;
