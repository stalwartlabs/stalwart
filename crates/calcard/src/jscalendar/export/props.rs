/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Parser,
    common::{
        CalendarScale, IanaParse, IanaType, PartialDateTime, jsprop::text::ConvertedKeys,
        parser::Integer,
    },
    icalendar::*,
    jscalendar::{JSCalendarId, JSCalendarProperty, JSCalendarValue, export::ConvertedComponent},
};
use jmap_tools::{Key, Map, Value};
use smallvec::{SmallVec, smallvec};

impl<I: JSCalendarId, B: JSCalendarId> ConvertedComponent<'_, I, B> {
    pub(super) fn apply_conversions(
        self,
        mut component: ICalendarComponent,
        ical: &mut ICalendar,
    ) -> ICalendarComponent {
        if !self.properties.is_empty() {
            component.import_properties(self.properties);
        }
        if !self.components.is_empty() {
            let mut jcal_components = self.components.into_iter();
            let mut stack = Vec::new();

            loop {
                if let Some(jcal_component) = jcal_components.next() {
                    let Some(items) = jcal_component.into_array() else {
                        continue;
                    };
                    let mut items = items.into_iter();

                    if let (
                        Some(Value::Str(name)),
                        Some(Value::Array(properties)),
                        Some(Value::Array(child_components)),
                    ) = (items.next(), items.next(), items.next())
                    {
                        // Process the component
                        let mut sub_component = ICalendarComponent::new(
                            ICalendarComponentType::parse(name.as_bytes()).unwrap_or_else(|| {
                                ICalendarComponentType::Other(name.to_ascii_uppercase())
                            }),
                        );
                        sub_component.import_properties(properties);
                        if !child_components.is_empty() {
                            stack.push((jcal_components, component));
                            jcal_components = child_components.into_iter();
                            component = sub_component;
                        } else {
                            component
                                .component_ids
                                .push(ical.push_component(sub_component));
                        }
                    }
                } else if let Some((next_components, mut parent_component)) = stack.pop() {
                    parent_component
                        .component_ids
                        .push(ical.push_component(component));
                    jcal_components = next_components;
                    component = parent_component;
                } else {
                    break;
                }
            }
        }

        component
    }

    pub(super) fn retain_class_property(&mut self, keep_unknown: bool) -> bool {
        let mut has_class = false;
        self.properties.retain(|property| {
            let Some([Value::Str(name), _, _, value, ..]) = property.as_array() else {
                return true;
            };
            if ICalendarProperty::parse(name.as_bytes()) != Some(ICalendarProperty::Class) {
                return true;
            }
            let keep = keep_unknown
                && !has_class
                && matches!(value, Value::Str(value)
                    if ICalendarClassification::parse(value.as_bytes()).is_none());
            has_class |= keep;
            keep
        });
        has_class
    }
}

impl ICalendarComponent {
    pub(super) fn import_properties<I: JSCalendarId, B: JSCalendarId>(
        &mut self,
        props: Vec<Value<'_, JSCalendarProperty<I>, JSCalendarValue<I, B>>>,
    ) {
        for prop in props.into_iter().flat_map(|prop| prop.into_array()) {
            let mut prop = prop.into_iter();
            let Some(name) = prop
                .next()
                .and_then(|v| v.into_string())
                .map(|name| {
                    ICalendarProperty::parse(name.as_bytes())
                        .unwrap_or(ICalendarProperty::Other(name.to_ascii_uppercase()))
                })
                .filter(|name| !matches!(name, ICalendarProperty::Begin | ICalendarProperty::End))
            else {
                continue;
            };
            let Some(params) = prop.next() else {
                continue;
            };
            let Some(value_type) =
                prop.next()
                    .and_then(|v| v.into_string())
                    .map(|v| match ICalendarValueType::parse(v.as_bytes()) {
                        Some(v) => IanaType::Iana(v),
                        None => IanaType::Other(v.to_ascii_uppercase()),
                    })
            else {
                continue;
            };

            let (default_type, _) = name.default_types();
            let convert_type = value_type
                .iana()
                .filter(|&v| v != &ICalendarValueType::Unknown)
                .map(|v| ValueType::Ical(*v))
                .unwrap_or(default_type);
            let Some(values) = prop.next().and_then(|v| match v {
                Value::Array(arr) => Some(
                    arr.into_iter()
                        .filter_map(|v| convert_value(v, &convert_type).ok())
                        .collect::<SmallVec<_>>(),
                ),
                v => convert_value(v, &convert_type).ok().map(|v| smallvec![v]),
            }) else {
                continue;
            };

            let mut entry = ICalendarEntry::new(name);
            entry.import_jcal_params(params);
            entry.values = values;
            if convert_type != default_type {
                entry.params.push(ICalendarParameter::value(value_type));
            }
            self.entries.push(entry);
        }
    }
}

pub(super) fn convert_value<'x, I: JSCalendarId, B: JSCalendarId>(
    value: Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    value_type: &'_ ValueType,
) -> Result<ICalendarValue, Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>> {
    match value {
        Value::Element(e) => match e {
            JSCalendarValue::CalendarScale(v) => Ok(ICalendarValue::CalendarScale(v)),
            JSCalendarValue::DateTime(v) => Ok(ICalendarValue::PartialDateTime(v.into())),
            JSCalendarValue::Duration(v) => Ok(ICalendarValue::Duration(v)),
            JSCalendarValue::Method(v) => Ok(ICalendarValue::Method(v)),
            JSCalendarValue::AlertAction(_)
            | JSCalendarValue::FreeBusyStatus(_)
            | JSCalendarValue::ParticipantKind(_)
            | JSCalendarValue::ParticipationStatus(_)
            | JSCalendarValue::Privacy(_)
            | JSCalendarValue::Progress(_)
            | JSCalendarValue::RelativeTo(_)
            | JSCalendarValue::ScheduleAgent(_)
            | JSCalendarValue::EventStatus(_)
            | JSCalendarValue::Frequency(_)
            | JSCalendarValue::Skip(_)
            | JSCalendarValue::Weekday(_)
            | JSCalendarValue::Month(_)
            | JSCalendarValue::LinkRelation(_)
            | JSCalendarValue::Type(_)
            | JSCalendarValue::Id(_)
            | JSCalendarValue::BlobId(_)
            | JSCalendarValue::IdReference(_) => Err(Value::Element(e)),
        },
        Value::Str(s) => {
            match value_type {
                ValueType::CalendarScale => {
                    if let Some(value) = CalendarScale::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::CalendarScale(value));
                    }
                }
                ValueType::Method => {
                    if let Some(value) = ICalendarMethod::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::Method(value));
                    }
                }
                ValueType::Classification => {
                    if let Some(value) = ICalendarClassification::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::Classification(value));
                    }
                }
                ValueType::Status => {
                    if let Some(value) = ICalendarStatus::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::Status(value));
                    }
                }
                ValueType::Transparency => {
                    if let Some(value) = ICalendarTransparency::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::Transparency(value));
                    }
                }
                ValueType::Action => {
                    if let Some(value) = ICalendarAction::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::Action(value));
                    }
                }
                ValueType::BusyType => {
                    if let Some(value) = ICalendarFreeBusyType::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::BusyType(value));
                    }
                }
                ValueType::ParticipantType => {
                    if let Some(value) = ICalendarParticipantType::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::ParticipantType(value));
                    }
                }
                ValueType::ResourceType => {
                    if let Some(value) = ICalendarResourceType::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::ResourceType(value));
                    }
                }
                ValueType::Proximity => {
                    if let Some(value) = ICalendarProximityValue::parse(s.as_ref().as_bytes()) {
                        return Ok(ICalendarValue::Proximity(value));
                    }
                }
                ValueType::Ical(typ) => match typ {
                    ICalendarValueType::Uri | ICalendarValueType::CalAddress => {
                        return Ok(ICalendarValue::Uri(Uri::parse(s)));
                    }
                    ICalendarValueType::Date => {
                        let mut dt = PartialDateTime::default();
                        if dt.parse_ical_date(&mut s.as_ref().as_bytes().iter().peekable()) {
                            return Ok(ICalendarValue::PartialDateTime(dt));
                        }
                    }
                    ICalendarValueType::Time => {
                        let mut dt = PartialDateTime::default();
                        if dt.parse_ical_time(&mut s.as_ref().as_bytes().iter().peekable()) {
                            return Ok(ICalendarValue::PartialDateTime(dt));
                        }
                    }
                    ICalendarValueType::DateTime => {
                        let mut dt = PartialDateTime::default();
                        if dt.parse_timestamp(&mut s.as_ref().as_bytes().iter().peekable(), false) {
                            return Ok(ICalendarValue::PartialDateTime(dt));
                        }
                    }
                    ICalendarValueType::UtcOffset => {
                        let mut dt = PartialDateTime::default();
                        if dt.parse_zone(&mut s.as_ref().as_bytes().iter().peekable()) {
                            return Ok(ICalendarValue::PartialDateTime(dt));
                        }
                    }
                    ICalendarValueType::Duration => {
                        if let Some(duration) = ICalendarDuration::parse(s.as_ref().as_bytes()) {
                            return Ok(ICalendarValue::Duration(duration));
                        }
                    }
                    ICalendarValueType::Float => {
                        if let Ok(float) = s.as_ref().parse::<f64>()
                            && float.is_finite()
                        {
                            return Ok(ICalendarValue::Float(float));
                        }
                    }
                    ICalendarValueType::Integer => {
                        if let Some(integer) = Integer::parse(s.as_ref().as_bytes()) {
                            return Ok(ICalendarValue::Integer(integer.0));
                        }
                    }
                    ICalendarValueType::Period => {
                        if let Some(period) = ICalendarPeriod::parse(s.as_ref().as_bytes()) {
                            return Ok(ICalendarValue::Period(Box::new(period)));
                        }
                    }
                    ICalendarValueType::Recur => {
                        let mut parser = Parser::new(s.as_ref());
                        if let Ok(recur) = parser.rrule() {
                            return Ok(ICalendarValue::RecurrenceRule(Box::new(recur)));
                        }
                    }
                    ICalendarValueType::Boolean => {
                        if s.eq_ignore_ascii_case("true") {
                            return Ok(ICalendarValue::Boolean(true));
                        } else if s.eq_ignore_ascii_case("false") {
                            return Ok(ICalendarValue::Boolean(false));
                        }
                    }
                    ICalendarValueType::Binary => {
                        return Ok(match Uri::parse(s) {
                            Uri::Data(data) => ICalendarValue::Binary(data.data),
                            Uri::Location(text) => ICalendarValue::Text(text),
                        });
                    }
                    ICalendarValueType::Text
                    | ICalendarValueType::Unknown
                    | ICalendarValueType::XmlReference
                    | ICalendarValueType::Uid => (),
                },
            }

            Ok(ICalendarValue::Text(s.into_owned()))
        }
        Value::Bool(b) => Ok(ICalendarValue::Boolean(b)),
        Value::Number(n) => {
            if let Some(integer) = n.as_i64() {
                Ok(ICalendarValue::Integer(integer))
            } else if let Some(integer) = n.as_u64() {
                Ok(ICalendarValue::Text(integer.to_string()))
            } else {
                n.as_f64()
                    .filter(|float| float.is_finite())
                    .map(ICalendarValue::Float)
                    .ok_or(Value::Number(n))
            }
        }
        value => Err(value),
    }
}

impl<'x, I: JSCalendarId, B: JSCalendarId> ConvertedComponent<'x, I, B> {
    #[allow(clippy::type_complexity)]
    pub(super) fn try_from_object(
        obj: Vec<(
            Key<'x, JSCalendarProperty<I>>,
            Value<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
        )>,
    ) -> Option<Self> {
        let mut converted = ConvertedComponent {
            name: ICalendarComponentType::Other(String::new()),
            converted_props: Vec::new(),
            converted_props_count: 0,
            properties: Vec::new(),
            components: Vec::new(),
        };
        let mut has_name = false;
        for (sub_property, value) in obj {
            match (sub_property, value) {
                (Key::Property(JSCalendarProperty::ConvertedProperties), Value::Object(obj)) => {
                    let obj = obj.into_vec();
                    converted.converted_props.reserve(obj.len());
                    for (key, value) in obj {
                        converted
                            .converted_props
                            .push((key.into_converted_keys(), value));
                    }
                }
                (Key::Property(JSCalendarProperty::Properties), Value::Array(array)) => {
                    converted.properties = array;
                }
                (Key::Property(JSCalendarProperty::Components), Value::Array(array)) => {
                    converted.components = array;
                }
                (Key::Property(JSCalendarProperty::Name), Value::Str(text)) => {
                    converted.name =
                        ICalendarComponentType::parse(text.as_bytes()).unwrap_or_else(|| {
                            ICalendarComponentType::Other(text.to_ascii_uppercase())
                        });
                    has_name = true;
                }
                _ => {}
            }
        }

        if !converted.converted_props.is_empty() {
            converted
                .converted_props
                .sort_unstable_by(|a, b| a.0.cmp(&b.0));
        }

        (!converted.properties.is_empty()
            || !converted.components.is_empty()
            || has_name
            || !converted.converted_props.is_empty())
        .then_some(converted)
    }

    pub(super) fn has_date_value(&self, property: &JSCalendarProperty<I>) -> bool {
        self.converted_props.iter().any(|(keys, value)| {
            matches!(keys.as_slice(), [Key::Property(converted)] if converted == property)
                && value
                    .as_object_and_get(&Key::Property(JSCalendarProperty::Parameters))
                    .and_then(Value::as_object)
                    .is_some_and(|params| {
                        params.iter().any(|(name, value)| {
                            matches!(
                                ICalendarParameterName::try_parse(name.to_string().as_bytes()),
                                Some(ICalendarParameterName::Value)
                            ) && value
                                .as_str()
                                .is_some_and(|value| value.eq_ignore_ascii_case("DATE"))
                        })
                    })
        })
    }

    pub(super) fn build(
        entries: &mut Map<'x, JSCalendarProperty<I>, JSCalendarValue<I, B>>,
    ) -> Option<Self> {
        for (property, value) in entries.as_mut_vec() {
            if let (Key::Property(JSCalendarProperty::ICalendar), Value::Object(obj)) =
                (property, value)
            {
                return Self::try_from_object(std::mem::take(obj.as_mut_vec()));
            }
        }

        None
    }
}
