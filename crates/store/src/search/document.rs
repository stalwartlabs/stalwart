/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::search::*;

impl IndexDocument {
    pub fn new(index: SearchIndex) -> Self {
        Self {
            fields: Default::default(),
            index,
        }
    }

    pub fn with_account_id(mut self, account_id: u32) -> Self {
        self.fields
            .insert(SearchField::AccountId, SearchValue::Uint(account_id as u64));
        self
    }

    pub fn with_document_id(mut self, document_id: u32) -> Self {
        self.fields.insert(
            SearchField::DocumentId,
            SearchValue::Uint(document_id as u64),
        );
        self
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.fields.insert(SearchField::Id, SearchValue::Uint(id));
        self
    }

    pub fn index_text(&mut self, field: impl Into<SearchField>, value: &str, language: Language) {
        match self.fields.entry(field.into()) {
            Entry::Occupied(mut entry) => {
                if let SearchValue::Text {
                    value: existing_value,
                    ..
                } = entry.get_mut()
                {
                    existing_value.push(' ');
                    sanitize_text_to_buf(existing_value, value);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(SearchValue::Text {
                    value: sanitize_text(value),
                    language,
                });
            }
        }
    }

    pub fn index_bool(&mut self, field: impl Into<SearchField>, value: bool) {
        self.fields
            .insert(field.into(), SearchValue::Boolean(value));
    }

    pub fn index_integer<N: Into<i64>>(&mut self, field: impl Into<SearchField>, value: N) {
        self.fields
            .insert(field.into(), SearchValue::Int(value.into()));
    }

    pub fn index_unsigned<N: Into<u64>>(&mut self, field: impl Into<SearchField>, value: N) {
        self.fields
            .insert(field.into(), SearchValue::Uint(value.into()));
    }

    pub fn index_keyword(&mut self, field: impl Into<SearchField>, value: impl AsRef<str>) {
        self.fields.insert(
            field.into(),
            SearchValue::Text {
                value: sanitize_text(value.as_ref()),
                language: Language::None,
            },
        );
    }

    pub fn insert_key_value(
        &mut self,
        field: impl Into<SearchField>,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
    ) {
        let search_field = field.into();
        let key = key
            .as_ref()
            .chars()
            .filter(|ch| !ch.is_control())
            .map(|ch| ch.to_ascii_lowercase())
            .collect::<String>();
        let value = value.as_ref();

        match self.fields.entry(search_field) {
            Entry::Occupied(mut entry) => {
                if let SearchValue::KeyValues(existing_key_values) = entry.get_mut() {
                    if let Some(existing_value) = existing_key_values.get_mut(&key) {
                        existing_value.push(' ');
                        sanitize_text_to_buf(existing_value, value);
                    } else {
                        existing_key_values.append(key, sanitize_text(value));
                    }
                }
            }
            Entry::Vacant(entry) => {
                let mut new_key_values = VecMap::new();
                new_key_values.append(key, sanitize_text(value));
                entry.insert(SearchValue::KeyValues(new_key_values));
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn has_field(&self, field: &SearchField) -> bool {
        self.fields.contains_key(field)
    }

    pub fn fields(&self) -> impl Iterator<Item = (&SearchField, &SearchValue)> {
        self.fields.iter()
    }

    pub fn set_unknown_language(&mut self, lang: Language) {
        for value in self.fields.values_mut() {
            if let SearchValue::Text { language, .. } = value
                && language.is_unknown()
            {
                *language = lang;
            }
        }
    }
}

impl SearchFilter {
    pub fn cond(
        field: impl Into<SearchField>,
        op: SearchOperator,
        value: impl Into<SearchValue>,
    ) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op,
            value: value.into(),
        }
    }

    pub fn eq(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::Equal,
            value: value.into(),
        }
    }

    pub fn lt(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::LowerThan,
            value: value.into(),
        }
    }

    pub fn le(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::LowerEqualThan,
            value: value.into(),
        }
    }

    pub fn gt(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::GreaterThan,
            value: value.into(),
        }
    }

    pub fn ge(field: impl Into<SearchField>, value: impl Into<SearchValue>) -> Self {
        SearchFilter::Operator {
            field: field.into(),
            op: SearchOperator::GreaterEqualThan,
            value: value.into(),
        }
    }

    pub fn has_text_detect(
        field: impl Into<SearchField>,
        text: impl Into<String>,
        default_language: Language,
    ) -> Self {
        let (text, language) = Language::detect(text.into(), default_language);
        Self::has_text(field, text, language)
    }

    pub fn has_text(
        field: impl Into<SearchField>,
        text: impl Into<String>,
        language: Language,
    ) -> Self {
        let text = text.into();
        let (is_exact, text) = if let Some(text) = text
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .or_else(|| text.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')))
        {
            (true, text.to_string())
        } else {
            (false, text)
        };

        if !matches!(language, Language::None) && is_exact {
            SearchFilter::Operator {
                field: field.into(),
                op: SearchOperator::Equal,
                value: SearchValue::Text {
                    value: text,
                    language,
                },
            }
        } else {
            SearchFilter::Operator {
                field: field.into(),
                op: SearchOperator::Contains,
                value: SearchValue::Text {
                    value: text,
                    language,
                },
            }
        }
    }

    #[inline(always)]
    pub fn has_english_text(field: impl Into<SearchField>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::English)
    }

    #[inline(always)]
    pub fn has_keyword(field: impl Into<SearchField>, text: impl Into<String>) -> Self {
        Self::has_text(field, text, Language::None)
    }

    pub fn is_in_set(set: RoaringBitmap) -> Self {
        SearchFilter::DocumentSet(set)
    }
}

impl SearchComparator {
    pub fn field(field: impl Into<SearchField>, ascending: bool) -> Self {
        Self::Field {
            field: field.into(),
            ascending,
        }
    }

    pub fn set(set: RoaringBitmap, ascending: bool) -> Self {
        Self::DocumentSet { set, ascending }
    }

    pub fn sorted_set(set: AHashMap<u32, u32>, ascending: bool) -> Self {
        Self::SortedSet { set, ascending }
    }

    pub fn ascending(field: impl Into<SearchField>) -> Self {
        Self::Field {
            field: field.into(),
            ascending: true,
        }
    }

    pub fn descending(field: impl Into<SearchField>) -> Self {
        Self::Field {
            field: field.into(),
            ascending: false,
        }
    }
}

#[inline(always)]
fn write_sanitized(out: &mut String, text: &str) {
    let mut last_is_space = true;
    for ch in text.chars() {
        match ch {
            ' ' | '\x09'..='\x0d' => {
                if !last_is_space {
                    out.push(' ');
                    last_is_space = true;
                }
            }
            '\0'..='\x1f' | '\x7f'..='\u{9f}' => {}
            ch => {
                out.push(ch);
                last_is_space = false;
            }
        }
    }
}

#[inline(always)]
fn sanitize_text_to_buf(out: &mut String, text: &str) {
    out.reserve_exact(text.len());
    write_sanitized(out, text);
}

#[inline(always)]
fn sanitize_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    write_sanitized(&mut out, text);
    out
}
