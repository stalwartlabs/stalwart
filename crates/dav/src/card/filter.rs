/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::common::search::{Candidates, IndexedText, QueryScope, TextIndex};
use calcard::vcard::{
    ArchivedVCard, ArchivedVCardEntry, ArchivedVCardParameterValue, ArchivedVCardValue,
    ArchivedVCardValueType, VCardParameterName, VCardProperty,
};
use common::storage::dav::MAX_CACHED_UID_LEN;
use dav_proto::schema::request::{
    CardFilter, CardPropFilter, CardPropMatch, FilterTest, ParamFilter, Presence,
    VCardPropertyWithGroup,
};
use std::{borrow::Cow, convert::identity};
use store::search::{ContactSearchField, SearchField};

pub(crate) trait CardFilterMatch {
    fn matches(&self, card: &ArchivedVCard) -> bool;
}

pub(crate) trait CardFilterPlan {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates;
}

trait EntryMatch {
    fn matches_entry(&self, entry: &ArchivedVCardEntry) -> bool;
}

trait EntryText {
    fn text_values(&self) -> impl Iterator<Item = Cow<'_, str>>;
}

trait ValueText {
    fn value_text(&self) -> Option<Cow<'_, str>>;
}

trait ContactIndexField {
    fn search_field(&self) -> Option<(SearchField, IndexedText)>;
}

impl CardFilterMatch for CardFilter {
    fn matches(&self, card: &ArchivedVCard) -> bool {
        let mut results = self.prop_filters.iter().map(|filter| filter.matches(card));
        match self.test {
            FilterTest::AnyOf => self.prop_filters.is_empty() || results.any(identity),
            FilterTest::AllOf => results.all(identity),
        }
    }
}

impl CardFilterMatch for CardPropFilter {
    fn matches(&self, card: &ArchivedVCard) -> bool {
        let mut entries = card
            .entries
            .iter()
            .filter(|entry| self.name.matches_entry(entry));
        match &self.test {
            Presence::IsNotDefined => entries.next().is_none(),
            Presence::IsDefined(test) => entries.any(|entry| test.matches_entry(entry)),
        }
    }
}

impl EntryMatch for VCardPropertyWithGroup {
    fn matches_entry(&self, entry: &ArchivedVCardEntry) -> bool {
        entry.name == self.name
            && self.group.as_deref().is_none_or(|group| {
                entry
                    .group
                    .as_ref()
                    .is_some_and(|entry_group| entry_group.eq_ignore_ascii_case(group))
            })
    }
}

impl EntryMatch for CardPropMatch {
    fn matches_entry(&self, entry: &ArchivedVCardEntry) -> bool {
        let mut results = self
            .text_matches
            .iter()
            .map(|text_match| text_match.is_match_any(entry.text_values()))
            .chain(
                self.param_filters
                    .iter()
                    .map(|filter| filter.matches_entry(entry)),
            );
        match self.test {
            FilterTest::AnyOf => {
                (self.text_matches.is_empty() && self.param_filters.is_empty())
                    || results.any(identity)
            }
            FilterTest::AllOf => results.all(identity),
        }
    }
}

impl EntryMatch for ParamFilter<VCardParameterName> {
    fn matches_entry(&self, entry: &ArchivedVCardEntry) -> bool {
        let mut params = entry
            .params
            .iter()
            .filter(|param| param.name == self.name)
            .peekable();
        match &self.test {
            Presence::IsNotDefined => params.peek().is_none(),
            Presence::IsDefined(None) => params.peek().is_some(),
            Presence::IsDefined(Some(text_match)) => {
                params.peek().is_some()
                    && text_match.is_match_any(params.filter_map(|param| param.value.value_text()))
            }
        }
    }
}

impl EntryText for ArchivedVCardEntry {
    fn text_values(&self) -> impl Iterator<Item = Cow<'_, str>> {
        self.values.iter().flat_map(|value| {
            let (text, items) = match value {
                ArchivedVCardValue::Component(items) => (None, items.as_slice()),
                value => (value.value_text(), &[][..]),
            };
            text.into_iter()
                .chain(items.iter().map(|item| Cow::Borrowed(item.as_str())))
        })
    }
}

impl ValueText for ArchivedVCardValue {
    fn value_text(&self) -> Option<Cow<'_, str>> {
        match self {
            ArchivedVCardValue::Integer(value) => Some(Cow::Owned(value.to_native().to_string())),
            ArchivedVCardValue::Float(value) => Some(Cow::Owned(value.to_native().to_string())),
            ArchivedVCardValue::Boolean(value) => {
                Some(Cow::Borrowed(if *value { "TRUE" } else { "FALSE" }))
            }
            ArchivedVCardValue::PartialDateTime(value) => {
                let mut text = String::with_capacity(20);
                value
                    .format_as_vcard(&mut text, &ArchivedVCardValueType::DateAndOrTime)
                    .ok()
                    .map(|_| Cow::Owned(text))
            }
            value => value.as_text().map(Cow::Borrowed),
        }
    }
}

impl ValueText for ArchivedVCardParameterValue {
    fn value_text(&self) -> Option<Cow<'_, str>> {
        match self {
            ArchivedVCardParameterValue::Integer(value) => {
                Some(Cow::Owned(value.to_native().to_string()))
            }
            ArchivedVCardParameterValue::Bool(value) => {
                Some(Cow::Borrowed(if *value { "TRUE" } else { "FALSE" }))
            }
            value => value.as_text().map(Cow::Borrowed),
        }
    }
}

impl CardFilterPlan for CardFilter {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates {
        if self.prop_filters.is_empty() {
            return Candidates::All;
        }
        let candidates = self
            .prop_filters
            .iter()
            .map(|filter| filter.candidates(scope, index));
        match self.test {
            FilterTest::AnyOf => Candidates::or(candidates),
            FilterTest::AllOf => Candidates::and(candidates),
        }
    }
}

impl CardFilterPlan for CardPropFilter {
    fn candidates(&self, scope: &QueryScope<'_>, index: TextIndex<'_>) -> Candidates {
        let Presence::IsDefined(test) = &self.test else {
            return Candidates::All;
        };
        if test.text_matches.is_empty()
            || (test.test == FilterTest::AnyOf && !test.param_filters.is_empty())
        {
            return Candidates::All;
        }

        let is_uid = self.name.name == VCardProperty::Uid && self.name.group.is_none();
        let field = self.name.name.search_field();
        let candidates = test.text_matches.iter().map(|text_match| {
            if text_match.negate {
                Candidates::All
            } else if is_uid {
                scope.matching(|resource| {
                    resource.uid().is_none_or(|uid| {
                        uid.is_empty()
                            || uid.len() >= MAX_CACHED_UID_LEN
                            || text_match.is_match(uid)
                    })
                })
            } else if let Some((field, text)) = &field {
                index.candidates(field.clone(), *text, text_match)
            } else {
                Candidates::All
            }
        });

        match test.test {
            FilterTest::AnyOf => Candidates::or(candidates),
            FilterTest::AllOf => Candidates::and(candidates),
        }
    }
}

impl ContactIndexField for VCardProperty {
    fn search_field(&self) -> Option<(SearchField, IndexedText)> {
        let (field, text) = match self {
            VCardProperty::Fn | VCardProperty::N => (ContactSearchField::Name, IndexedText::Plain),
            VCardProperty::Nickname => (ContactSearchField::Nickname, IndexedText::Plain),
            VCardProperty::Org => (ContactSearchField::Organization, IndexedText::Plain),
            VCardProperty::Email => (ContactSearchField::Email, IndexedText::Identifier),
            VCardProperty::Tel => (ContactSearchField::Phone, IndexedText::Identifier),
            VCardProperty::Impp | VCardProperty::Socialprofile => {
                (ContactSearchField::OnlineService, IndexedText::Identifier)
            }
            VCardProperty::Adr => (ContactSearchField::Address, IndexedText::Plain),
            VCardProperty::Note => (ContactSearchField::Note, IndexedText::Stemmed),
            VCardProperty::Member => (ContactSearchField::Member, IndexedText::Identifier),
            _ => return None,
        };
        Some((field.into(), text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calcard::vcard::VCard;
    use dav_proto::{
        parser::{DavParser, tokenizer::Tokenizer},
        schema::request::Report,
    };

    const CARD: &str = "BEGIN:VCARD
VERSION:4.0
UID:urn:uuid:card-1
FN:Jane Doe
N:Doe;Jane;;;
NICKNAME:JD
item1.EMAIL;TYPE=work:jane@acme.example
item1.X-ABLABEL:Office
EMAIL;TYPE=home;PREF=1:jane@home.example
TEL;TYPE=cell:+1 555 0100
BDAY:19850412
END:VCARD
";

    fn matches(filter: &str) -> bool {
        let xml = format!(
            "<C:addressbook-query xmlns:C=\"urn:ietf:params:xml:ns:carddav\">{filter}</C:addressbook-query>"
        );
        let filter = match Report::parse(&mut Tokenizer::new(xml.as_bytes())) {
            Ok(Report::AddressbookQuery(query)) => query.filter,
            other => panic!("unexpected parse result {other:?}"),
        };
        let card = VCard::parse(CARD.replace('\n', "\r\n")).expect("valid vCard");
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&card).expect("the card archives");
        let card = rkyv::access::<ArchivedVCard, rkyv::rancor::Error>(&bytes)
            .expect("the archive validates");
        filter.matches(card)
    }

    #[test]
    fn filters_default_to_anyof() {
        let filter = |test: &str| {
            format!(
                "<C:filter{test}><C:prop-filter name=\"FN\"><C:text-match>nobody</C:text-match></C:prop-filter><C:prop-filter name=\"NICKNAME\"><C:text-match>jd</C:text-match></C:prop-filter></C:filter>"
            )
        };
        assert!(matches(&filter("")));
        assert!(matches(&filter(" test=\"anyof\"")));
        assert!(!matches(&filter(" test=\"allof\"")));
    }

    #[test]
    fn prop_filter_test_is_scoped_to_its_prop_filter() {
        assert!(matches(
            "<C:filter test=\"anyof\"><C:prop-filter name=\"FN\" test=\"allof\"><C:text-match>jane</C:text-match></C:prop-filter><C:prop-filter name=\"TEL\"><C:text-match>999</C:text-match></C:prop-filter></C:filter>"
        ));
        assert!(matches(
            "<C:filter><C:prop-filter name=\"EMAIL\" test=\"allof\"><C:text-match>jane</C:text-match><C:text-match>acme</C:text-match></C:prop-filter></C:filter>"
        ));
        assert!(!matches(
            "<C:filter><C:prop-filter name=\"EMAIL\" test=\"allof\"><C:text-match>acme</C:text-match><C:text-match>home</C:text-match></C:prop-filter></C:filter>"
        ));
    }

    #[test]
    fn names_without_a_group_match_any_group() {
        let email = |name: &str| {
            format!(
                "<C:filter><C:prop-filter name=\"{name}\"><C:text-match>acme</C:text-match></C:prop-filter></C:filter>"
            )
        };
        assert!(matches(&email("EMAIL")));
        assert!(matches(&email("item1.EMAIL")));
        assert!(matches(&email("ITEM1.email")));
        assert!(!matches(&email("item2.EMAIL")));
    }

    #[test]
    fn text_and_parameters_match_the_same_property() {
        let email = |text: &str| {
            format!(
                "<C:filter><C:prop-filter name=\"EMAIL\" test=\"allof\"><C:text-match>{text}</C:text-match><C:param-filter name=\"TYPE\"><C:text-match match-type=\"equals\">work</C:text-match></C:param-filter></C:prop-filter></C:filter>"
            )
        };
        assert!(matches(&email("acme")));
        assert!(!matches(&email("home")));
    }

    #[test]
    fn existence_and_undefined_properties() {
        assert!(matches(
            "<C:filter><C:prop-filter name=\"TEL\"/></C:filter>"
        ));
        assert!(!matches(
            "<C:filter><C:prop-filter name=\"ADR\"/></C:filter>"
        ));
        assert!(matches(
            "<C:filter><C:prop-filter name=\"ADR\"><C:is-not-defined/></C:prop-filter></C:filter>"
        ));
        assert!(!matches(
            "<C:filter><C:prop-filter name=\"FN\"><C:is-not-defined/></C:prop-filter></C:filter>"
        ));
        assert!(matches(
            "<C:filter><C:prop-filter name=\"TEL\"><C:param-filter name=\"PREF\"><C:is-not-defined/></C:param-filter></C:prop-filter></C:filter>"
        ));
    }

    #[test]
    fn text_matches_apply_to_non_text_values() {
        let pref = |text: &str, negate: &str| {
            format!(
                "<C:filter><C:prop-filter name=\"EMAIL\"><C:param-filter name=\"PREF\"><C:text-match negate-condition=\"{negate}\">{text}</C:text-match></C:param-filter></C:prop-filter></C:filter>"
            )
        };
        assert!(matches(&pref("1", "no")));
        assert!(!matches(&pref("2", "no")));
        assert!(matches(&pref("2", "yes")));
        assert!(matches(
            "<C:filter><C:prop-filter name=\"BDAY\"><C:text-match match-type=\"starts-with\">1985</C:text-match></C:prop-filter></C:filter>"
        ));
        assert!(!matches(
            "<C:filter><C:prop-filter name=\"BDAY\"><C:text-match negate-condition=\"yes\">0412</C:text-match></C:prop-filter></C:filter>"
        ));
    }

    #[test]
    fn structured_values_and_negation() {
        assert!(matches(
            "<C:filter><C:prop-filter name=\"N\"><C:text-match match-type=\"equals\">jane</C:text-match></C:prop-filter></C:filter>"
        ));
        assert!(matches(
            "<C:filter><C:prop-filter name=\"EMAIL\"><C:text-match negate-condition=\"yes\">acme</C:text-match></C:prop-filter></C:filter>"
        ));
        assert!(!matches(
            "<C:filter><C:prop-filter name=\"NICKNAME\"><C:text-match negate-condition=\"yes\">jd</C:text-match></C:prop-filter></C:filter>"
        ));
    }
}
