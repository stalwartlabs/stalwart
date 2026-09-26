/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    parser::{
        Error, FilterError, RawElement, Token, property::TimeRangeFromRaw, tokenizer::Tokenizer,
    },
    schema::{
        Attribute, AttributeValue, Collation, Element, MatchType, Namespace,
        request::{
            CalendarPropFilter, CalendarPropMatch, CardFilter, CardPropFilter, CardPropMatch,
            CompFilter, CompFilterMatch, FilterTest, ParamFilter, Presence, PropValueMatch,
            TextMatch, VCardPropertyWithGroup,
        },
    },
};
use calcard::{
    icalendar::{ICalendarComponentType, ICalendarParameterName, ICalendarProperty},
    vcard::VCardParameterName,
};
use types::TimeRange;

pub const MAX_FILTER_ELEMENTS: usize = 256;
pub const MAX_FILTER_DEPTH: usize = 16;

struct Frame<N, T> {
    name: N,
    is_not_defined: bool,
    filter: T,
}

enum CalendarFrame {
    Comp(Frame<ICalendarComponentType, CompFilterMatch>),
    Prop(Frame<ICalendarProperty, CalendarPropMatch>),
    Param(Frame<ICalendarParameterName, Option<TextMatch>>),
}

enum CardFrame {
    Prop(Frame<VCardPropertyWithGroup, CardPropMatch>),
    Param(Frame<VCardParameterName, Option<TextMatch>>),
}

trait FilterConditions {
    fn has_conditions(&self) -> bool;
}

trait ComponentNesting {
    fn can_contain(&self, child: &Self) -> bool;
}

trait DateProperty {
    fn has_date_value(&self) -> bool;
}

struct TextMatchOptions {
    match_type: MatchType,
    collation: Collation,
    negate: bool,
}

struct ElementBudget {
    elements: usize,
    namespace: Namespace,
}

impl CompFilter {
    pub(crate) fn parse_filter(stream: &mut Tokenizer<'_>) -> crate::parser::Result<Option<Self>> {
        let mut stack: Vec<CalendarFrame> = Vec::with_capacity(4);
        let mut roots: Vec<CompFilter> = Vec::with_capacity(1);
        let mut budget = ElementBudget::new(Namespace::CalDav);

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => {
                    budget.consume(stack.len())?;
                    if name.ns != Namespace::CalDav {
                        return Err(Error::invalid_filter(Namespace::CalDav));
                    }
                    match (name.element, stack.last_mut()) {
                        (Element::CompFilter, None | Some(CalendarFrame::Comp(_))) => {
                            let name = raw.component_name()?;
                            stack.push(CalendarFrame::Comp(Frame::new(name)));
                        }
                        (Element::PropFilter, Some(CalendarFrame::Comp(_))) => {
                            let name = raw.filter_name::<ICalendarProperty>(Namespace::CalDav)?;
                            stack.push(CalendarFrame::Prop(Frame::new(name)));
                        }
                        (Element::ParamFilter, Some(CalendarFrame::Prop(_))) => {
                            let name =
                                raw.filter_name::<ICalendarParameterName>(Namespace::CalDav)?;
                            stack.push(CalendarFrame::Param(Frame::new(name)));
                        }
                        (Element::IsNotDefined, Some(frame)) => {
                            frame.set_not_defined();
                            stream.expect_element_end()?;
                        }
                        (Element::TimeRange, Some(CalendarFrame::Comp(frame)))
                            if frame.filter.time_range.is_none() =>
                        {
                            frame.filter.time_range = Some(raw.filter_time_range()?);
                            stream.expect_element_end()?;
                        }
                        (Element::TimeRange, Some(CalendarFrame::Prop(frame)))
                            if frame.filter.value.is_none() =>
                        {
                            frame.filter.value =
                                Some(PropValueMatch::TimeRange(raw.filter_time_range()?));
                            stream.expect_element_end()?;
                        }
                        (Element::TextMatch, Some(CalendarFrame::Prop(frame)))
                            if frame.filter.value.is_none() =>
                        {
                            let options = TextMatchOptions::parse(&raw, Namespace::CalDav)?;
                            frame.filter.value = Some(PropValueMatch::Text(
                                options.into_text_match(stream.collect_string_value()?),
                            ));
                        }
                        (Element::TextMatch, Some(CalendarFrame::Param(frame)))
                            if frame.filter.is_none() =>
                        {
                            let options = TextMatchOptions::parse(&raw, Namespace::CalDav)?;
                            frame.filter =
                                Some(options.into_text_match(stream.collect_string_value()?));
                        }
                        _ => return Err(Error::invalid_filter(Namespace::CalDav)),
                    }
                }
                Token::ElementEnd => match stack.pop() {
                    Some(CalendarFrame::Comp(frame)) => {
                        let (name, test) = frame.into_parts(Namespace::CalDav)?;
                        match stack.last_mut() {
                            Some(CalendarFrame::Comp(parent)) if parent.name.can_contain(&name) => {
                                parent.filter.comp_filters.push(CompFilter { name, test });
                            }
                            None => roots.push(CompFilter { name, test }),
                            Some(_) => return Err(Error::invalid_filter(Namespace::CalDav)),
                        }
                    }
                    Some(CalendarFrame::Prop(frame)) => {
                        if matches!(frame.filter.value, Some(PropValueMatch::TimeRange(_)))
                            && !frame.name.has_date_value()
                        {
                            return Err(Error::invalid_filter(Namespace::CalDav));
                        }
                        let (name, test) = frame.into_parts(Namespace::CalDav)?;
                        let Some(CalendarFrame::Comp(parent)) = stack.last_mut() else {
                            return Err(Error::invalid_filter(Namespace::CalDav));
                        };
                        parent
                            .filter
                            .prop_filters
                            .push(CalendarPropFilter { name, test });
                    }
                    Some(CalendarFrame::Param(frame)) => {
                        let (name, test) = frame.into_parts(Namespace::CalDav)?;
                        let Some(CalendarFrame::Prop(parent)) = stack.last_mut() else {
                            return Err(Error::invalid_filter(Namespace::CalDav));
                        };
                        parent.filter.param_filters.push(ParamFilter { name, test });
                    }
                    None => break,
                },
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        CompFilter::from_roots(roots)
    }

    fn from_roots(roots: Vec<CompFilter>) -> crate::parser::Result<Option<Self>> {
        let calendar = ICalendarComponentType::VCalendar;
        let mut roots = roots.into_iter();
        match (roots.next(), roots.next()) {
            (None, _) => Ok(None),
            (Some(root), None) if root.name == calendar => Ok(Some(root)),
            (Some(root), None) if calendar.can_contain(&root.name) => Ok(Some(CompFilter {
                name: calendar,
                test: Presence::IsDefined(CompFilterMatch {
                    comp_filters: vec![root],
                    ..Default::default()
                }),
            })),
            _ => Err(Error::invalid_filter(Namespace::CalDav)),
        }
    }
}

impl CardFilter {
    pub(crate) fn parse_filter(
        test: FilterTest,
        stream: &mut Tokenizer<'_>,
    ) -> crate::parser::Result<Self> {
        let mut filter = CardFilter {
            test,
            prop_filters: Vec::new(),
        };
        let mut stack: Vec<CardFrame> = Vec::with_capacity(2);
        let mut budget = ElementBudget::new(Namespace::CardDav);

        loop {
            match stream.token()? {
                Token::ElementStart { name, raw } => {
                    budget.consume(stack.len())?;
                    if name.ns != Namespace::CardDav {
                        return Err(Error::invalid_filter(Namespace::CardDav));
                    }
                    match (name.element, stack.last_mut()) {
                        (Element::PropFilter, None) => {
                            let mut frame = Frame::<_, CardPropMatch>::new(
                                raw.filter_name::<VCardPropertyWithGroup>(Namespace::CardDav)?,
                            );
                            frame.filter.test = raw.filter_test()?;
                            stack.push(CardFrame::Prop(frame));
                        }
                        (Element::ParamFilter, Some(CardFrame::Prop(_))) => {
                            let name = raw.filter_name::<VCardParameterName>(Namespace::CardDav)?;
                            stack.push(CardFrame::Param(Frame::new(name)));
                        }
                        (Element::IsNotDefined, Some(frame)) => {
                            frame.set_not_defined();
                            stream.expect_element_end()?;
                        }
                        (Element::TextMatch, Some(CardFrame::Prop(frame))) => {
                            let options = TextMatchOptions::parse(&raw, Namespace::CardDav)?;
                            frame
                                .filter
                                .text_matches
                                .push(options.into_text_match(stream.collect_string_value()?));
                        }
                        (Element::TextMatch, Some(CardFrame::Param(frame)))
                            if frame.filter.is_none() =>
                        {
                            let options = TextMatchOptions::parse(&raw, Namespace::CardDav)?;
                            frame.filter =
                                Some(options.into_text_match(stream.collect_string_value()?));
                        }
                        _ => return Err(Error::invalid_filter(Namespace::CardDav)),
                    }
                }
                Token::ElementEnd => match stack.pop() {
                    Some(CardFrame::Prop(frame)) => {
                        let (name, test) = frame.into_parts(Namespace::CardDav)?;
                        filter.prop_filters.push(CardPropFilter { name, test });
                    }
                    Some(CardFrame::Param(frame)) => {
                        let (name, test) = frame.into_parts(Namespace::CardDav)?;
                        let Some(CardFrame::Prop(parent)) = stack.last_mut() else {
                            return Err(Error::invalid_filter(Namespace::CardDav));
                        };
                        parent.filter.param_filters.push(ParamFilter { name, test });
                    }
                    None => break,
                },
                Token::UnknownElement(_) => {
                    stream.seek_element_end()?;
                }
                token => return Err(token.into_unexpected()),
            }
        }

        Ok(filter)
    }
}

impl<N, T: FilterConditions + Default> Frame<N, T> {
    fn new(name: N) -> Self {
        Frame {
            name,
            is_not_defined: false,
            filter: T::default(),
        }
    }

    fn into_parts(self, namespace: Namespace) -> crate::parser::Result<(N, Presence<T>)> {
        match (self.is_not_defined, self.filter.has_conditions()) {
            (false, _) => Ok((self.name, Presence::IsDefined(self.filter))),
            (true, false) => Ok((self.name, Presence::IsNotDefined)),
            (true, true) => Err(Error::invalid_filter(namespace)),
        }
    }
}

impl CalendarFrame {
    fn set_not_defined(&mut self) {
        match self {
            CalendarFrame::Comp(frame) => frame.is_not_defined = true,
            CalendarFrame::Prop(frame) => frame.is_not_defined = true,
            CalendarFrame::Param(frame) => frame.is_not_defined = true,
        }
    }
}

impl CardFrame {
    fn set_not_defined(&mut self) {
        match self {
            CardFrame::Prop(frame) => frame.is_not_defined = true,
            CardFrame::Param(frame) => frame.is_not_defined = true,
        }
    }
}

impl FilterConditions for CompFilterMatch {
    fn has_conditions(&self) -> bool {
        self.time_range.is_some() || !self.prop_filters.is_empty() || !self.comp_filters.is_empty()
    }
}

impl FilterConditions for CalendarPropMatch {
    fn has_conditions(&self) -> bool {
        self.value.is_some() || !self.param_filters.is_empty()
    }
}

impl FilterConditions for CardPropMatch {
    fn has_conditions(&self) -> bool {
        !self.text_matches.is_empty() || !self.param_filters.is_empty()
    }
}

impl FilterConditions for Option<TextMatch> {
    fn has_conditions(&self) -> bool {
        self.is_some()
    }
}

impl ComponentNesting for ICalendarComponentType {
    fn can_contain(&self, child: &Self) -> bool {
        use ICalendarComponentType::*;
        match (self, child) {
            (_, VCalendar) => false,
            (
                VCalendar,
                VEvent | VTodo | VJournal | VFreebusy | VTimezone | VAvailability | Other(_),
            ) => true,
            (VCalendar, _) => false,
            (_, VEvent | VTodo | VJournal | VFreebusy | VTimezone | VAvailability) => false,
            (VEvent | VTodo, VAlarm)
            | (VTimezone, Standard | Daylight)
            | (VAvailability, Available) => true,
            (_, VAlarm | Standard | Daylight | Available) => false,
            _ => true,
        }
    }
}

impl DateProperty for ICalendarProperty {
    fn has_date_value(&self) -> bool {
        matches!(
            self,
            ICalendarProperty::Dtstart
                | ICalendarProperty::Dtend
                | ICalendarProperty::Due
                | ICalendarProperty::Completed
                | ICalendarProperty::Created
                | ICalendarProperty::Dtstamp
                | ICalendarProperty::LastModified
                | ICalendarProperty::RecurrenceId
                | ICalendarProperty::Exdate
                | ICalendarProperty::Rdate
                | ICalendarProperty::Trigger
                | ICalendarProperty::Acknowledged
                | ICalendarProperty::Other(_)
        )
    }
}

impl ElementBudget {
    fn new(namespace: Namespace) -> Self {
        ElementBudget {
            elements: 0,
            namespace,
        }
    }

    fn consume(&mut self, depth: usize) -> crate::parser::Result<()> {
        self.elements += 1;
        if self.elements <= MAX_FILTER_ELEMENTS && depth < MAX_FILTER_DEPTH {
            Ok(())
        } else {
            Err(FilterError::TooComplex(self.namespace).into())
        }
    }
}

impl TextMatchOptions {
    fn parse(raw: &RawElement<'_>, namespace: Namespace) -> crate::parser::Result<Self> {
        let mut options = TextMatchOptions {
            match_type: MatchType::Contains,
            collation: Collation::default_for(namespace),
            negate: false,
        };

        for attribute in raw.attributes::<String>() {
            match attribute? {
                Attribute::MatchType(match_type) => {
                    options.match_type = match_type;
                }
                Attribute::NegateCondition(negate) => {
                    options.negate = negate;
                }
                Attribute::Collation(collation) => {
                    options.collation = collation;
                }
                Attribute::Unknown { param, value } if param == "collation" => {
                    if value == "default" {
                        options.collation = Collation::default_for(namespace);
                    } else {
                        return Err(FilterError::UnsupportedCollation(namespace, value).into());
                    }
                }
                Attribute::Unknown { param, .. }
                    if param == "match-type" || param == "negate-condition" =>
                {
                    return Err(Error::invalid_filter(namespace));
                }
                _ => {}
            }
        }

        Ok(options)
    }

    fn into_text_match(self, value: Option<String>) -> TextMatch {
        TextMatch::new(
            value.unwrap_or_default(),
            self.match_type,
            self.collation,
            self.negate,
        )
    }
}

impl RawElement<'_> {
    pub(crate) fn filter_test(&self) -> crate::parser::Result<FilterTest> {
        self.test_attribute()
            .map(|test| test.unwrap_or(FilterTest::AnyOf))
    }

    pub(crate) fn principal_search_test(&self) -> crate::parser::Result<FilterTest> {
        self.test_attribute()
            .map(|test| test.unwrap_or(FilterTest::AllOf))
    }

    fn test_attribute(&self) -> crate::parser::Result<Option<FilterTest>> {
        for attribute in self.attributes::<String>() {
            if let Attribute::TestAllOf(all_of) = attribute? {
                return Ok(Some(if all_of {
                    FilterTest::AllOf
                } else {
                    FilterTest::AnyOf
                }));
            }
        }
        Ok(None)
    }

    fn filter_time_range(&self) -> crate::parser::Result<TimeRange> {
        TimeRange::from_raw_strict(self)?.ok_or_else(|| Error::invalid_filter(Namespace::CalDav))
    }

    fn filter_name<T: AttributeValue>(&self, namespace: Namespace) -> crate::parser::Result<T> {
        for attribute in self.attributes::<T>() {
            if let Attribute::Name(name) = attribute? {
                return Ok(name);
            }
        }
        Err(Error::invalid_filter(namespace))
    }

    fn component_name(&self) -> crate::parser::Result<ICalendarComponentType> {
        for attribute in self.attributes::<ICalendarComponentType>() {
            match attribute? {
                Attribute::Name(name) => return Ok(name),
                Attribute::Unknown { param, value } if param == "name" => {
                    return Ok(ICalendarComponentType::Other(value));
                }
                _ => {}
            }
        }
        Err(Error::invalid_filter(Namespace::CalDav))
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_FILTER_DEPTH, MAX_FILTER_ELEMENTS};
    use crate::{
        parser::{DavParser, Error, FilterError, tokenizer::Tokenizer},
        schema::{Namespace, request::Report},
    };

    const CALENDAR_QUERY: &str = concat!(
        r#"<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">"#,
        "<C:filter>FILTER</C:filter></C:calendar-query>"
    );
    const ADDRESSBOOK_QUERY: &str = concat!(
        r#"<C:addressbook-query xmlns:C="urn:ietf:params:xml:ns:carddav">"#,
        "<C:filter>FILTER</C:filter></C:addressbook-query>"
    );

    fn filter_error(template: &str, filter: &str) -> FilterError {
        let xml = template.replace("FILTER", filter);
        match Report::parse(&mut Tokenizer::new(xml.as_bytes())) {
            Err(Error::Filter(err)) => err,
            other => panic!("expected a filter error for {filter}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_calendar_filters() {
        for filter in [
            concat!(
                r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">"#,
                r#"<C:prop-filter name="SUMMARY"><C:is-not-defined/><C:text-match>x</C:text-match>"#,
                "</C:prop-filter></C:comp-filter></C:comp-filter>"
            ),
            concat!(
                r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VTODO">"#,
                r#"<C:comp-filter name="VEVENT"/></C:comp-filter></C:comp-filter>"#
            ),
            concat!(
                r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VALARM"/>"#,
                "</C:comp-filter>"
            ),
            concat!(
                r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">"#,
                r#"<C:prop-filter name="SUMMARY"><C:time-range start="20060104T000000Z"/>"#,
                "</C:prop-filter></C:comp-filter></C:comp-filter>"
            ),
            concat!(
                r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">"#,
                "<C:time-range/></C:comp-filter></C:comp-filter>"
            ),
            concat!(
                r#"<C:comp-filter name="VCALENDAR"/>"#,
                r#"<C:comp-filter name="VCALENDAR"/>"#
            ),
            r#"<C:comp-filter name="VCALENDAR"><C:prop-filter name="UID"><C:comp-filter name="VEVENT"/></C:prop-filter></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:param-filter name="ROLE"/></C:comp-filter></C:comp-filter>"#,
            r#"<C:comp-filter><C:comp-filter name="VEVENT"/></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:time-range start="garbage"/></C:comp-filter></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:time-range start="20060104T000000Z" end="20060103T000000Z"/></C:comp-filter></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:time-range start="20060104T000000Z" end="20060104T000000Z"/></C:comp-filter></C:comp-filter>"#,
            r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT"><C:prop-filter name="SUMMARY"><C:text-match negate-condition="maybe">x</C:text-match></C:prop-filter></C:comp-filter></C:comp-filter>"#,
        ] {
            assert_eq!(
                filter_error(CALENDAR_QUERY, filter),
                FilterError::Invalid(Namespace::CalDav),
                "{filter}"
            );
        }
    }

    #[test]
    fn rejects_invalid_addressbook_filters() {
        for filter in [
            r#"<C:prop-filter name="FN"><C:is-not-defined/><C:text-match>x</C:text-match></C:prop-filter>"#,
            concat!(
                r#"<C:prop-filter name="EMAIL"><C:param-filter name="TYPE">"#,
                "<C:text-match>work</C:text-match><C:text-match>home</C:text-match>",
                "</C:param-filter></C:prop-filter>"
            ),
            r#"<C:param-filter name="TYPE"/>"#,
            r#"<C:prop-filter><C:text-match>x</C:text-match></C:prop-filter>"#,
            r#"<C:prop-filter name="FN"><C:text-match match-type="sounds-like">x</C:text-match></C:prop-filter>"#,
        ] {
            assert_eq!(
                filter_error(ADDRESSBOOK_QUERY, filter),
                FilterError::Invalid(Namespace::CardDav),
                "{filter}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_collations() {
        assert_eq!(
            filter_error(
                CALENDAR_QUERY,
                concat!(
                    r#"<C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">"#,
                    r#"<C:prop-filter name="SUMMARY"><C:text-match collation="i;ascii-numeric">1"#,
                    "</C:text-match></C:prop-filter></C:comp-filter></C:comp-filter>"
                )
            ),
            FilterError::UnsupportedCollation(Namespace::CalDav, "i;ascii-numeric".to_string())
        );
        assert_eq!(
            filter_error(
                ADDRESSBOOK_QUERY,
                r#"<C:prop-filter name="FN"><C:text-match collation="i;x-custom">a</C:text-match></C:prop-filter>"#
            ),
            FilterError::UnsupportedCollation(Namespace::CardDav, "i;x-custom".to_string())
        );
    }

    #[test]
    fn rejects_overly_complex_filters() {
        let nested = format!(
            "{}{}",
            r#"<C:comp-filter name="X-NESTED">"#.repeat(MAX_FILTER_DEPTH + 1),
            "</C:comp-filter>".repeat(MAX_FILTER_DEPTH + 1)
        );
        assert_eq!(
            filter_error(CALENDAR_QUERY, &nested),
            FilterError::TooComplex(Namespace::CalDav)
        );
        let wide = r#"<C:prop-filter name="FN"/>"#.repeat(MAX_FILTER_ELEMENTS + 1);
        assert_eq!(
            filter_error(ADDRESSBOOK_QUERY, &wide),
            FilterError::TooComplex(Namespace::CardDav)
        );
    }
}
