/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::propfind::PropFindItem;
use common::{DavResourcePath, GroupwareResourceRef, GroupwareResources, Server};
use dav_proto::schema::{MatchType, request::TextMatch};
use groupware::strip_mailto_scheme;
use nlp::language::Language;
use store::{
    ahash::AHashSet,
    roaring::RoaringBitmap,
    search::{SearchField, SearchFilter, SearchQuery, TextMatch as IndexMatch, tokenize::tokenize},
    write::SearchIndex,
};
use utils::cheeky_hash::CheekyHash;

pub(crate) enum Candidates {
    All,
    Set(RoaringBitmap),
    Text(SearchFilter),
    And(Vec<Candidates>),
    Or(Vec<Candidates>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IndexedText {
    Plain,
    Identifier,
    Stemmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SearchBackend {
    Internal,
    External,
}

#[derive(Clone, Copy)]
pub(crate) struct TextIndex<'x> {
    fields: Option<&'x AHashSet<SearchField>>,
    default_language: Language,
    backend: SearchBackend,
}

pub(crate) struct QueryScope<'x> {
    items: Vec<DavResourcePath<'x>>,
    document_ids: RoaringBitmap,
}

impl<'x> TextIndex<'x> {
    pub fn new(server: &'x Server, index: SearchIndex) -> Self {
        let search_store = server.search_store();
        TextIndex {
            fields: if search_store.is_meilisearch() {
                None
            } else {
                server.core.email.index_fields.get(&index)
            },
            default_language: server.core.email.default_language,
            backend: if search_store.internal_fts().is_some() {
                SearchBackend::Internal
            } else {
                SearchBackend::External
            },
        }
    }

    pub fn candidates(
        &self,
        field: SearchField,
        text: IndexedText,
        text_match: &TextMatch,
    ) -> Candidates {
        if text_match.negate
            || !self.contains(&field)
            || (text == IndexedText::Identifier && !self.backend.splits_identifiers())
        {
            return Candidates::All;
        }
        let (value, has_scheme) = if text == IndexedText::Identifier {
            let address = strip_mailto_scheme(&text_match.value);
            (address, address.len() != text_match.value.len())
        } else {
            (text_match.value.as_str(), false)
        };
        let language = if text == IndexedText::Stemmed {
            Language::detect(value.to_string(), self.default_language).1
        } else {
            Language::None
        };
        let starts_at_word = has_scheme
            || matches!(
                text_match.match_type,
                MatchType::Equals | MatchType::StartsWith
            )
            || value.starts_with(|ch: char| !ch.is_alphanumeric());
        let ends_at_word = matches!(
            text_match.match_type,
            MatchType::Equals | MatchType::EndsWith
        ) || value.ends_with(|ch: char| !ch.is_alphanumeric());

        let mut words = Vec::with_capacity(4);
        tokenize(value, Language::None, |token| {
            words.push(token.word);
            true
        });

        let term = |word: &str, op: IndexMatch| {
            Candidates::Text(SearchFilter::Text {
                field: field.clone(),
                op,
                value: word.to_string(),
                language,
            })
        };
        let last = words.len().saturating_sub(1);
        let is_single = words.len() == 1;

        Candidates::and(words.iter().enumerate().filter_map(|(position, word)| {
            let partial_start = position == 0 && !starts_at_word;
            let partial_end = position == last && !ends_at_word;
            match (partial_start, partial_end) {
                (true, false) if !is_single => None,
                (_, false) => Some(term(word, IndexMatch::Standard)),
                (_, true) => Some(Candidates::or([
                    term(word, IndexMatch::Standard),
                    term(self.prefix_of(word), IndexMatch::Prefix),
                ])),
            }
        }))
    }

    fn prefix_of<'w>(&self, word: &'w str) -> &'w str {
        word.get(..word.floor_char_boundary(self.backend.max_prefix_len()))
            .unwrap_or(word)
    }

    fn contains(&self, field: &SearchField) -> bool {
        self.fields
            .is_some_and(|fields| fields.is_empty() || fields.contains(field))
    }
}

impl SearchBackend {
    fn max_prefix_len(self) -> usize {
        match self {
            SearchBackend::Internal => CheekyHash::HASH_SIZE,
            SearchBackend::External => usize::MAX,
        }
    }

    fn splits_identifiers(self) -> bool {
        self == SearchBackend::Internal
    }
}

impl<'x> QueryScope<'x> {
    pub fn new(items: impl Iterator<Item = DavResourcePath<'x>>) -> Self {
        let items = items.collect::<Vec<_>>();
        let document_ids = items.iter().map(DavResourcePath::document_id).collect();
        QueryScope {
            items,
            document_ids,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn matching(&self, predicate: impl Fn(&GroupwareResourceRef<'x>) -> bool) -> Candidates {
        Candidates::Set(
            self.items
                .iter()
                .filter(|item| predicate(&item.resource))
                .map(DavResourcePath::document_id)
                .collect(),
        )
    }

    pub async fn resolve(
        self,
        server: &Server,
        index: SearchIndex,
        account_id: u32,
        candidates: Candidates,
        resources: &GroupwareResources,
    ) -> Vec<PropFindItem> {
        let QueryScope {
            items,
            document_ids,
        } = self;
        let matches = candidates
            .resolve(server, index, account_id, document_ids)
            .await;

        items
            .into_iter()
            .filter(|item| matches.contains(item.document_id()))
            .map(|item| PropFindItem::new(resources.format_resource(item), account_id, item))
            .collect()
    }

    pub fn into_items(self, resources: &GroupwareResources, account_id: u32) -> Vec<PropFindItem> {
        self.items
            .into_iter()
            .map(|item| PropFindItem::new(resources.format_resource(item), account_id, item))
            .collect()
    }
}

impl Candidates {
    pub fn and(items: impl IntoIterator<Item = Candidates>) -> Self {
        let mut set: Option<RoaringBitmap> = None;
        let mut children = Vec::new();
        for item in items {
            match item {
                Candidates::All => {}
                Candidates::Set(items) => match &mut set {
                    Some(set) => *set &= items,
                    None => set = Some(items),
                },
                Candidates::And(items) => children.extend(items),
                item => children.push(item),
            }
        }
        if let Some(set) = set {
            if set.is_empty() {
                return Candidates::Set(set);
            }
            children.push(Candidates::Set(set));
        }
        if children.len() > 1 {
            Candidates::And(children)
        } else {
            children.pop().unwrap_or(Candidates::All)
        }
    }

    pub fn or(items: impl IntoIterator<Item = Candidates>) -> Self {
        let mut set: Option<RoaringBitmap> = None;
        let mut children = Vec::new();
        for item in items {
            match item {
                Candidates::All => return Candidates::All,
                Candidates::Set(items) => match &mut set {
                    Some(set) => *set |= items,
                    None => set = Some(items),
                },
                Candidates::Or(items) => children.extend(items),
                item => children.push(item),
            }
        }
        if let Some(set) = set.filter(|set| !set.is_empty()) {
            children.push(Candidates::Set(set));
        }
        if children.len() > 1 {
            Candidates::Or(children)
        } else {
            children
                .pop()
                .unwrap_or_else(|| Candidates::Set(RoaringBitmap::new()))
        }
    }

    pub async fn resolve(
        self,
        server: &Server,
        index: SearchIndex,
        account_id: u32,
        scope: RoaringBitmap,
    ) -> RoaringBitmap {
        match self {
            Candidates::All => scope,
            candidates if candidates.has_text() => {
                let mut filters = Vec::with_capacity(8);
                candidates.into_filters(&mut filters);
                match server
                    .search_store()
                    .filter_account(
                        SearchQuery::new(index)
                            .with_account_id(account_id)
                            .with_mask(scope.clone())
                            .with_filters(filters),
                    )
                    .await
                {
                    Ok(matches) => matches,
                    Err(err) => {
                        trc::error!(err.caused_by(trc::location!()));
                        scope
                    }
                }
            }
            candidates => {
                let mut matches = candidates.evaluate(&scope);
                matches &= &scope;
                matches
            }
        }
    }

    fn has_text(&self) -> bool {
        match self {
            Candidates::Text(_) => true,
            Candidates::And(items) | Candidates::Or(items) => {
                items.iter().any(Candidates::has_text)
            }
            Candidates::All | Candidates::Set(_) => false,
        }
    }

    fn into_filters(self, filters: &mut Vec<SearchFilter>) {
        match self {
            Candidates::All => {}
            Candidates::Set(set) => filters.push(SearchFilter::is_in_set(set)),
            Candidates::Text(filter) => filters.push(filter),
            Candidates::And(items) => {
                filters.push(SearchFilter::And);
                for item in items {
                    item.into_filters(filters);
                }
                filters.push(SearchFilter::End);
            }
            Candidates::Or(items) => {
                filters.push(SearchFilter::Or);
                for item in items {
                    item.into_filters(filters);
                }
                filters.push(SearchFilter::End);
            }
        }
    }

    fn evaluate(self, scope: &RoaringBitmap) -> RoaringBitmap {
        match self {
            Candidates::All | Candidates::Text(_) => scope.clone(),
            Candidates::Set(set) => set,
            Candidates::And(items) => items
                .into_iter()
                .map(|item| item.evaluate(scope))
                .reduce(|a, b| a & b)
                .unwrap_or_else(|| scope.clone()),
            Candidates::Or(items) => items
                .into_iter()
                .map(|item| item.evaluate(scope))
                .reduce(|a, b| a | b)
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dav_proto::schema::Collation;
    use store::search::ContactSearchField;

    fn words(candidates: &Candidates) -> Vec<(String, bool)> {
        let mut words = Vec::new();
        candidates.collect_words(&mut words);
        words
    }

    impl Candidates {
        fn collect_words(&self, words: &mut Vec<(String, bool)>) {
            match self {
                Candidates::Text(SearchFilter::Text { value, op, .. }) => {
                    words.push((value.clone(), *op == IndexMatch::Prefix))
                }
                Candidates::And(items) | Candidates::Or(items) => {
                    items.iter().for_each(|item| item.collect_words(words))
                }
                _ => {}
            }
        }
    }

    impl Candidates {
        fn languages(&self, languages: &mut Vec<Language>) {
            match self {
                Candidates::Text(SearchFilter::Text { language, .. }) => languages.push(*language),
                Candidates::And(items) | Candidates::Or(items) => {
                    items.iter().for_each(|item| item.languages(languages))
                }
                _ => {}
            }
        }
    }

    fn text_match(value: &str, match_type: MatchType, negate: bool) -> TextMatch {
        TextMatch::new(
            value.to_string(),
            match_type,
            Collation::UnicodeCasemap,
            negate,
        )
    }

    fn internal_index(fields: &AHashSet<SearchField>) -> TextIndex<'_> {
        TextIndex {
            fields: Some(fields),
            default_language: Language::English,
            backend: SearchBackend::Internal,
        }
    }

    fn text(value: &str, match_type: MatchType, negate: bool) -> Candidates {
        internal_index(&AHashSet::new()).candidates(
            ContactSearchField::Email.into(),
            IndexedText::Identifier,
            &text_match(value, match_type, negate),
        )
    }

    #[test]
    fn text_matches_use_whole_words_and_a_trailing_prefix() {
        let prefix = |word: &str| vec![(word.to_string(), false), (word.to_string(), true)];
        let exact = |word: &str| (word.to_string(), false);
        assert_eq!(
            words(&text("mailto:Lisa@Example.com", MatchType::Contains, false)),
            [vec![exact("lisa"), exact("example")], prefix("com")].concat()
        );
        assert_eq!(
            words(&text("@Example.com", MatchType::Contains, false)),
            [vec![exact("example")], prefix("com")].concat()
        );
        assert_eq!(
            words(&text("ample.com", MatchType::Contains, false)),
            prefix("com")
        );
        assert_eq!(
            words(&text("Smith", MatchType::Contains, false)),
            prefix("smith")
        );
        assert_eq!(
            words(&text("Jo", MatchType::StartsWith, false)),
            prefix("jo")
        );
        assert_eq!(
            words(&text("john smith", MatchType::Equals, false)),
            vec![exact("john"), exact("smith")]
        );
        assert_eq!(
            words(&text("acme corp", MatchType::EndsWith, false)),
            vec![exact("corp")]
        );
        assert_eq!(
            words(&text("smith", MatchType::EndsWith, false)),
            vec![exact("smith")]
        );
        assert!(matches!(
            text("anything", MatchType::Contains, true),
            Candidates::All
        ));
        assert!(matches!(
            text("--", MatchType::Contains, false),
            Candidates::All
        ));
    }

    #[test]
    fn prefixes_fit_the_internal_index() {
        let fields = AHashSet::new();
        let candidates = internal_index(&fields).candidates(
            ContactSearchField::Note.into(),
            IndexedText::Plain,
            &text_match("internationalizat", MatchType::Contains, false),
        );
        assert_eq!(
            words(&candidates),
            vec![
                ("internationalizat".to_string(), false),
                ("internationaliza".to_string(), true)
            ]
        );
        let unbounded = TextIndex {
            backend: SearchBackend::External,
            ..internal_index(&fields)
        }
        .candidates(
            ContactSearchField::Note.into(),
            IndexedText::Plain,
            &text_match("internationalizat", MatchType::Contains, false),
        );
        assert_eq!(
            words(&unbounded),
            vec![
                ("internationalizat".to_string(), false),
                ("internationalizat".to_string(), true)
            ]
        );
    }

    #[test]
    fn stemmed_fields_carry_a_language() {
        let fields = AHashSet::new();
        let index = internal_index(&fields);
        let value = text_match(
            "the quarterly planning meeting for the engineering department",
            MatchType::Contains,
            false,
        );
        let mut languages = Vec::new();
        index
            .candidates(
                ContactSearchField::Note.into(),
                IndexedText::Stemmed,
                &value,
            )
            .languages(&mut languages);
        assert!(!languages.is_empty());
        assert!(
            languages
                .iter()
                .all(|language| *language == Language::English)
        );

        languages.clear();
        index
            .candidates(ContactSearchField::Name.into(), IndexedText::Plain, &value)
            .languages(&mut languages);
        assert!(languages.iter().all(|language| *language == Language::None));
    }

    #[test]
    fn unindexed_fields_are_not_pruned() {
        let value = text_match("smith", MatchType::Contains, false);
        let meilisearch = TextIndex {
            fields: None,
            default_language: Language::English,
            backend: SearchBackend::External,
        };
        assert!(matches!(
            meilisearch.candidates(ContactSearchField::Name.into(), IndexedText::Plain, &value),
            Candidates::All
        ));
        let fields = AHashSet::from_iter([SearchField::from(ContactSearchField::Email)]);
        assert!(matches!(
            internal_index(&fields).candidates(
                ContactSearchField::Name.into(),
                IndexedText::Plain,
                &value
            ),
            Candidates::All
        ));
        assert!(!matches!(
            internal_index(&fields).candidates(
                ContactSearchField::Email.into(),
                IndexedText::Identifier,
                &value
            ),
            Candidates::All
        ));
        let external = TextIndex {
            backend: SearchBackend::External,
            ..internal_index(&fields)
        };
        assert!(matches!(
            external.candidates(
                ContactSearchField::Email.into(),
                IndexedText::Identifier,
                &value
            ),
            Candidates::All
        ));
        assert!(!matches!(
            external.candidates(ContactSearchField::Email.into(), IndexedText::Plain, &value),
            Candidates::All
        ));
    }

    #[test]
    fn boolean_simplification() {
        let set = |ids: &[u32]| Candidates::Set(ids.iter().copied().collect());
        let scope = RoaringBitmap::from_iter([1u32, 2, 3, 4]);
        assert_eq!(
            Candidates::and([set(&[1, 2, 3]), Candidates::All, set(&[2, 3, 9])]).evaluate(&scope),
            RoaringBitmap::from_iter([2u32, 3])
        );
        assert!(matches!(
            Candidates::or([set(&[1]), Candidates::All]),
            Candidates::All
        ));
        assert!(matches!(Candidates::and([]), Candidates::All));
        assert_eq!(Candidates::or([]).evaluate(&scope), RoaringBitmap::new());
        assert_eq!(
            Candidates::or([set(&[1]), set(&[4])]).evaluate(&scope),
            RoaringBitmap::from_iter([1u32, 4])
        );
    }
}
