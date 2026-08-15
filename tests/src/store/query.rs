/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use nlp::language::Language;
use store::{
    SearchStore, Store,
    ahash::AHashMap,
    rand::{self, RngExt, distr::Alphanumeric},
    roaring::RoaringBitmap,
    search::{
        ContactSearchField, EmailSearchField, IndexDocument, KeyValueMatch, SearchComparator,
        SearchField, SearchFilter, SearchQuery, SearchValue, TextMatch,
    },
    write::SearchIndex,
};

const ACCOUNT: u32 = 0;
const ACCOUNT_OTHER: u32 = 1;
const ACCOUNT_CONTACTS: u32 = 5;
const ACCOUNT_DUP: u32 = 6;
const ACCOUNT_CHUNKS: u32 = 8;
const ACCOUNT_LARGE: u32 = 9;
const ACCOUNT_MIXED: u32 = 11;
const ACCOUNT_PHRASE: u32 = 12;
const ACCOUNT_BLOCKS: u32 = 13;

struct EmailDoc {
    id: u32,
    subject: &'static str,
    body: &'static str,
    from: &'static str,
    to: &'static str,
    header: Option<(&'static str, &'static str)>,
}

const CORPUS: &[EmailDoc] = &[
    EmailDoc {
        id: 0,
        subject: "Quarterly financial report",
        body: "the quick brown fox jumps over the lazy dog",
        from: "alicecorp",
        to: "management",
        header: Some(("X-Mailer", "SuperMail 3000")),
    },
    EmailDoc {
        id: 1,
        subject: "Running shoes review",
        body: "he runs daily and enjoys running long marathons",
        from: "carolshop",
        to: "sports",
        header: None,
    },
    EmailDoc {
        id: 2,
        subject: "Study results published",
        body: "multiple studies confirm the initial study findings",
        from: "alicecorp",
        to: "research",
        header: None,
    },
    EmailDoc {
        id: 3,
        subject: "Helicopter maintenance guide",
        body: "the helicopter rotor requires regular maintenance",
        from: "frankair",
        to: "aviation",
        header: None,
    },
    EmailDoc {
        id: 4,
        subject: "quick brown foxes everywhere",
        body: "brown quick dog fox scattered words",
        from: "carolshop",
        to: "wildlife",
        header: None,
    },
    EmailDoc {
        id: 5,
        subject: "Internationalization support",
        body: "internationalization and localization of internationalized text",
        from: "devteam",
        to: "engineering",
        header: None,
    },
    EmailDoc {
        id: 6,
        subject: "Special edition release",
        body: "released with resume and attachments included",
        from: "devteam",
        to: "unicode",
        header: None,
    },
];

const FILLER_IDS: std::ops::Range<u32> = 7..20;

fn filler_doc(id: u32) -> IndexDocument {
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT)
        .with_document_id(id);
    document.index_text(
        EmailSearchField::Subject,
        &format!("filler item number{id}"),
        Language::English,
    );
    document.index_text(
        EmailSearchField::Body,
        &format!("generic filler content number{id}"),
        Language::English,
    );
    document.index_text(EmailSearchField::From, "fillerco", Language::None);
    document.index_text(EmailSearchField::To, "misc", Language::None);
    document
}

fn email_doc(account_id: u32, doc: &EmailDoc) -> IndexDocument {
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(account_id)
        .with_document_id(doc.id);
    document.index_text(EmailSearchField::Subject, doc.subject, Language::English);
    document.index_text(EmailSearchField::Body, doc.body, Language::English);
    document.index_text(EmailSearchField::From, doc.from, Language::None);
    document.index_text(EmailSearchField::To, doc.to, Language::None);
    if let Some((key, value)) = doc.header {
        document.insert_key_value(EmailSearchField::Headers, key, value);
    }
    document
}

struct Caps {
    internal: bool,
    stem: bool,
    stem_reverse: bool,
    phrase: bool,
    prefix: bool,
    prefix_verbatim: bool,
    text_boolean: bool,
}

async fn search_index(store: &SearchStore, documents: Vec<IndexDocument>) -> trc::Result<()> {
    let Some(internal) = store.internal_fts() else {
        return store.index(documents).await;
    };

    let mut accounts: AHashMap<(SearchIndex, u32), Vec<IndexDocument>> = AHashMap::new();
    let mut traces = Vec::new();

    for document in documents {
        if matches!(document.index(), SearchIndex::Tracing) {
            traces.push(document);
        } else {
            let account_id = document_field(&document, &SearchField::AccountId)
                .expect("Missing accountId for document") as u32;
            accounts
                .entry((document.index(), account_id))
                .or_default()
                .push(document);
        }
    }

    for ((index, account_id), documents) in accounts {
        internal
            .index_account_documents(account_id, index, documents, vec![])
            .await?;
    }

    if !traces.is_empty() {
        internal.index_trace(traces).await?;
    }

    Ok(())
}

async fn search_unindex(store: &SearchStore, query: SearchQuery) -> trc::Result<()> {
    let Some(internal) = store.internal_fts() else {
        return store.unindex(query).await.map(|_| ());
    };

    let index = query.index();
    let mut accounts: Vec<(u32, Vec<u32>)> = Vec::new();
    let mut before_id = None;

    for filter in query.filters() {
        match filter {
            SearchFilter::Integer {
                field: SearchField::AccountId,
                op: std::cmp::Ordering::Equal,
                value,
            } => {
                accounts.push((*value as u32, Vec::new()));
            }
            SearchFilter::Integer {
                field: SearchField::DocumentId,
                op: std::cmp::Ordering::Equal,
                value,
            } => {
                accounts
                    .last_mut()
                    .expect("Missing accountId for unindex")
                    .1
                    .push(*value as u32);
            }
            SearchFilter::Integer {
                field: SearchField::Id,
                op: std::cmp::Ordering::Less,
                value,
            } => {
                before_id = Some(*value);
            }
            SearchFilter::And | SearchFilter::Or | SearchFilter::End => {}
            other => {
                return Err(trc::StoreEvent::NotSupported
                    .into_err()
                    .details(format!("Unsupported unindex filter {other:?}")));
            }
        }
    }

    if let Some(before_id) = before_id {
        return internal.unindex_traces(before_id).await;
    }

    assert!(!accounts.is_empty(), "Missing accountId for unindex");

    for (account_id, document_ids) in accounts {
        if document_ids.is_empty() {
            internal.unindex_account(index, account_id).await?;
        } else {
            internal
                .index_account_documents(account_id, index, vec![], document_ids)
                .await?;
        }
    }

    Ok(())
}

fn document_field(document: &IndexDocument, field: &SearchField) -> Option<u64> {
    document.fields().find_map(|(name, value)| match value {
        SearchValue::Uint(value) if name == field => Some(*value),
        _ => None,
    })
}

async fn refresh(store: &SearchStore) {
    if let SearchStore::ElasticSearch(store) = store {
        for index in [
            SearchIndex::Email,
            SearchIndex::Contacts,
            SearchIndex::Tracing,
        ] {
            store.refresh_index(index).await.unwrap();
        }
    } else if store.is_mysql() {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
}

fn full_mask() -> RoaringBitmap {
    let mut mask = RoaringBitmap::new();
    for doc in CORPUS {
        mask.insert(doc.id);
    }
    for id in FILLER_IDS {
        mask.insert(id);
    }
    mask
}

async fn assert_query(
    store: &SearchStore,
    filters: Vec<SearchFilter>,
    mask: RoaringBitmap,
    expected: &[u32],
    context: &str,
) {
    let mut all_filters = vec![SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT)];
    all_filters.extend(filters);
    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_filters(all_filters)
                .with_mask(mask),
        )
        .await
        .unwrap_or_else(|err| panic!("query failed for {context}: {err:?}"));
    let mut results = results;
    results.sort_unstable();
    assert_eq!(results, expected, "unexpected results for {context}");
}

pub async fn test(test: &TestServer) {
    let store = test.server.search_store().clone();

    let internal = store.internal_fts().is_some();
    let caps = Caps {
        internal,
        stem: !store.is_mysql(),
        stem_reverse: !(store.is_mysql() || store.is_meilisearch()),
        phrase: true,
        prefix: true,
        prefix_verbatim: internal || !(store.is_postgres() || store.is_elasticsearch()),
        text_boolean: !store.is_meilisearch(),
    };

    println!(
        "Running Store query tests ({})...",
        if caps.internal { "internal" } else { "native" }
    );

    crate::utils::cleanup::search_store_destroy(&store).await;

    println!("Indexing synthetic corpus...");
    let mut documents = Vec::new();
    for doc in CORPUS {
        documents.push(email_doc(ACCOUNT, doc));
    }
    for id in FILLER_IDS {
        documents.push(filler_doc(id));
    }
    documents.push(email_doc(
        ACCOUNT_OTHER,
        &EmailDoc {
            id: 0,
            subject: "Quarterly isolation check",
            body: "separate account data",
            from: "alicecorp",
            to: "other",
            header: None,
        },
    ));
    search_index(&store, documents).await.unwrap();
    refresh(&store).await;

    println!("Running robustness tests (large document)...");
    test_large_document(&store, &caps).await;

    println!("Running filter tests...");
    test_filters(&store, &caps).await;

    if caps.phrase {
        println!("Running phrase position tests...");
        test_phrase_positions(&store).await;
    }

    if caps.internal {
        let internal_store = store.internal_fts().unwrap().clone();

        println!("Running internal-only tests...");
        test_internal_features(&store).await;
        verify_account_regions_empty(&internal_store, ACCOUNT_LARGE).await;

        println!("Running incremental indexing tests...");
        test_incremental(&store, &caps).await;

        println!("Running bulk unindex tests...");
        test_bulk_unindex(&store, &internal_store).await;
    }

    println!("Running in-memory sort tests...");
    test_sort(&store).await;

    println!("Running update tests...");
    test_update(&store).await;

    println!("Running duplicate batch tests...");
    test_duplicate_batch(&store).await;

    println!("Running unindex tests...");
    test_unindex(&store).await;

    println!("Running term block tests...");
    test_term_blocks(&store).await;

    println!("Running hashed term unindex tests...");
    test_hashed_term_unindex(&store).await;

    println!("Running account wipe tests...");
    test_account_wipe(&store).await;

    println!("Running global index tests...");
    test_global(&store, &caps).await;
}

async fn test_filters(store: &SearchStore, caps: &Caps) {
    let mask = full_mask();

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "alicecorp",
        )],
        mask.clone(),
        &[0, 2],
        "keyword from alicecorp",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::text_eq(EmailSearchField::From, "carolshop")],
        mask.clone(),
        &[1, 4],
        "exact from carolshop",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "quarterly",
        )],
        mask.clone(),
        &[0],
        "standard subject quarterly",
    )
    .await;

    if caps.stem {
        assert_query(
            store,
            vec![SearchFilter::has_english_text(
                EmailSearchField::Body,
                "run",
            )],
            mask.clone(),
            &[1],
            "standard body run stems to runs/running",
        )
        .await;

        assert_query(
            store,
            vec![SearchFilter::has_english_text(
                EmailSearchField::Body,
                "study",
            )],
            mask.clone(),
            &[2],
            "standard body study matches studies",
        )
        .await;
    }

    if caps.stem_reverse {
        assert_query(
            store,
            vec![SearchFilter::has_english_text(
                EmailSearchField::Body,
                "dogs",
            )],
            mask.clone(),
            &[0, 4],
            "standard body dogs matches base form dog",
        )
        .await;
    }

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Body,
            "fox",
        )],
        mask.clone(),
        &[0, 4],
        "standard body fox",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Body,
            "brown fox",
        )],
        mask.clone(),
        &[0, 4],
        "standard multi token and",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Body,
            "internationalization",
        )],
        mask.clone(),
        &[5],
        "standard long hashed term",
    )
    .await;

    if caps.phrase {
        assert_query(
            store,
            vec![SearchFilter::has_english_text(
                EmailSearchField::Body,
                "\"quick brown fox\"",
            )],
            mask.clone(),
            &[0],
            "phrase quick brown fox",
        )
        .await;

        assert_query(
            store,
            vec![SearchFilter::has_english_text(
                EmailSearchField::Body,
                "\"brown quick\"",
            )],
            mask.clone(),
            &[4],
            "phrase brown quick",
        )
        .await;

        assert_query(
            store,
            vec![SearchFilter::has_english_text(
                EmailSearchField::Body,
                "\"fox brown quick\"",
            )],
            mask.clone(),
            &[],
            "phrase words present but out of order",
        )
        .await;
    }

    if caps.prefix {
        assert_query(
            store,
            vec![SearchFilter::text_prefix(
                EmailSearchField::Subject,
                "quart",
            )],
            mask.clone(),
            &[0],
            "prefix subject quart",
        )
        .await;

        if caps.prefix_verbatim {
            assert_query(
                store,
                vec![SearchFilter::text_prefix(EmailSearchField::Subject, "runn")],
                mask.clone(),
                &[1],
                "prefix subject runn",
            )
            .await;
        } else {
            assert_query(
                store,
                vec![SearchFilter::text_prefix(EmailSearchField::Subject, "run")],
                mask.clone(),
                &[1],
                "prefix subject run over stemmed lexemes",
            )
            .await;
        }
    }

    assert_query(
        store,
        vec![
            SearchFilter::has_keyword(EmailSearchField::To, "wildlife"),
            SearchFilter::has_english_text(EmailSearchField::Body, "fox"),
        ],
        mask.clone(),
        &[4],
        "implicit and of two text filters",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::KeyValue {
            field: SearchField::Email(EmailSearchField::Headers),
            key: "x-mailer".to_string(),
            op: KeyValueMatch::Exists,
        }],
        mask.clone(),
        &[0],
        "header exists",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::KeyValue {
            field: SearchField::Email(EmailSearchField::Headers),
            key: "x-mailer".to_string(),
            op: KeyValueMatch::Equals("SuperMail 3000".to_string()),
        }],
        mask.clone(),
        &[0],
        "header equals",
    )
    .await;

    if !store.is_meilisearch() {
        assert_query(
            store,
            vec![SearchFilter::KeyValue {
                field: SearchField::Email(EmailSearchField::Headers),
                key: "x-mailer".to_string(),
                op: KeyValueMatch::Contains("3000".to_string()),
            }],
            mask.clone(),
            &[0],
            "header contains",
        )
        .await;
    }

    if caps.text_boolean {
        assert_query(
            store,
            vec![
                SearchFilter::Or,
                SearchFilter::has_keyword(EmailSearchField::From, "carolshop"),
                SearchFilter::has_keyword(EmailSearchField::From, "frankair"),
                SearchFilter::End,
            ],
            mask.clone(),
            &[1, 3, 4],
            "flat or",
        )
        .await;

        let expected_not = mask
            .iter()
            .filter(|id| ![0u32, 2].contains(id))
            .collect::<Vec<_>>();
        assert_query(
            store,
            vec![
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::End,
            ],
            mask.clone(),
            &expected_not,
            "not keyword",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "doesnotexist"),
                SearchFilter::End,
            ],
            mask.clone(),
            &mask.iter().collect::<Vec<_>>(),
            "not of missing keyword matches all",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::And,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "doesnotexist"),
                SearchFilter::End,
                SearchFilter::End,
            ],
            mask.clone(),
            &[0, 2],
            "and with nested not of missing keyword",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::has_keyword(EmailSearchField::From, "frankair"),
                SearchFilter::End,
            ],
            mask.clone(),
            &mask
                .iter()
                .filter(|id| ![0u32, 2, 3].contains(id))
                .collect::<Vec<_>>(),
            "not group excludes any matching child",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::And,
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::End,
                SearchFilter::has_keyword(EmailSearchField::From, "carolshop"),
                SearchFilter::End,
            ],
            mask.clone(),
            &[1, 4],
            "not nested inside and",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::End,
            ],
            RoaringBitmap::from_iter([0u32, 1]),
            &[1],
            "not respects a restricted mask",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::And,
                SearchFilter::has_keyword(EmailSearchField::From, "doesnotexist"),
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::End,
                SearchFilter::End,
            ],
            mask.clone(),
            &[],
            "empty and leg skips across a not group",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::is_in_set(RoaringBitmap::from_iter([0u32, 1, 2, 3, 4])),
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::has_keyword(EmailSearchField::From, "frankair"),
                SearchFilter::End,
            ],
            mask.clone(),
            &[1, 4],
            "split not group keeps de morgan semantics",
        )
        .await;

        assert_query(
            store,
            vec![
                SearchFilter::Or,
                SearchFilter::And,
                SearchFilter::has_keyword(EmailSearchField::From, "nobody"),
                SearchFilter::Or,
                SearchFilter::has_keyword(EmailSearchField::From, "carolshop"),
                SearchFilter::has_keyword(EmailSearchField::From, "frankair"),
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                SearchFilter::End,
            ],
            mask.clone(),
            &[0, 2],
            "nested or with empty and branch",
        )
        .await;
    }

    assert_query(
        store,
        vec![
            SearchFilter::is_in_set(RoaringBitmap::from_iter([0u32, 1, 2])),
            SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
        ],
        mask.clone(),
        &[0, 2],
        "document set and keyword",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "alicecorp",
        )],
        RoaringBitmap::from_iter([2u32, 3]),
        &[2],
        "mask restricts results",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "doesnotexist",
        )],
        mask.clone(),
        &[],
        "no matches",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::And, SearchFilter::End],
        mask.clone(),
        &mask.iter().collect::<Vec<_>>(),
        "empty and group returns the mask",
    )
    .await;

    assert!(
        store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filter(SearchFilter::has_keyword(
                        EmailSearchField::From,
                        "alicecorp",
                    ))
                    .with_mask(mask.clone()),
            )
            .await
            .is_err(),
        "queries without an account id filter are rejected"
    );

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_filters(vec![
                    SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT_OTHER),
                    SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                ])
                .with_mask(RoaringBitmap::from_iter([0u32])),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![0], "account isolation positive");

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_filters(vec![
                    SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT_OTHER),
                    SearchFilter::has_keyword(EmailSearchField::From, "carolshop"),
                ])
                .with_mask(RoaringBitmap::from_iter([0u32])),
        )
        .await
        .unwrap();
    assert_eq!(results, Vec::<u32>::new(), "account isolation negative");

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "alicecorp",
        )],
        RoaringBitmap::new(),
        &[],
        "empty mask",
    )
    .await;

    let mut deep_filters = Vec::new();
    let depth = if caps.internal { 100 } else { 10 };
    for _ in 0..depth {
        deep_filters.push(SearchFilter::And);
    }
    deep_filters.push(SearchFilter::has_keyword(
        EmailSearchField::From,
        "alicecorp",
    ));
    for _ in 0..depth {
        deep_filters.push(SearchFilter::End);
    }
    assert_query(
        store,
        deep_filters,
        mask.clone(),
        &[0, 2],
        "deeply nested and",
    )
    .await;

    if caps.text_boolean {
        let mut wide_filters = vec![SearchFilter::Or];
        for n in 0..100 {
            wide_filters.push(SearchFilter::has_keyword(
                EmailSearchField::From,
                format!("missing{n}"),
            ));
        }
        wide_filters.push(SearchFilter::has_keyword(
            EmailSearchField::From,
            "frankair",
        ));
        wide_filters.push(SearchFilter::End);
        assert_query(store, wide_filters, mask.clone(), &[3], "wide or").await;
    }
}

async fn test_phrase_positions(store: &SearchStore) {
    let mask = RoaringBitmap::from_iter([0u32]);
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT_PHRASE)
        .with_document_id(0);
    document.index_text(
        EmailSearchField::Body,
        "alpha alpha alpha omega",
        Language::English,
    );
    search_index(store, vec![document]).await.unwrap();
    refresh(store).await;

    for (phrase, expected, context) in [
        (
            "\"alpha alpha omega\"",
            vec![0u32],
            "phrase with overlapping restart",
        ),
        ("\"alpha alpha alpha\"", vec![0], "repeated word phrase"),
        ("\"alpha omega\"", vec![0], "phrase tail"),
        ("\"omega alpha\"", vec![], "phrase reversed"),
        (
            "\"alpha alpha alpha alpha\"",
            vec![],
            "phrase exceeds repetitions",
        ),
    ] {
        if (store.is_meilisearch() || store.is_mysql()) && context == "phrase exceeds repetitions" {
            continue;
        }
        let results = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_account_id(ACCOUNT_PHRASE)
                    .with_filter(SearchFilter::has_english_text(
                        EmailSearchField::Body,
                        phrase,
                    ))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();
        assert_eq!(results, expected, "unexpected results for {context}");
    }

    let mut documents = Vec::new();
    let mut bulk_mask = RoaringBitmap::from_iter([0u32]);
    let mut expected = vec![0u32];
    for n in 1u32..=24 {
        let id = if n % 2 == 0 { n } else { (1 << 16) | n };
        bulk_mask.insert(id);
        let body = if n % 3 == 0 {
            expected.push(id);
            "alpha omega tail"
        } else {
            "alpha filler omega"
        };
        let mut document = IndexDocument::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_PHRASE)
            .with_document_id(id);
        document.index_text(EmailSearchField::Body, body, Language::English);
        documents.push(document);
    }
    expected.sort_unstable();
    search_index(store, documents).await.unwrap();
    refresh(store).await;

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT_PHRASE)
                .with_filter(SearchFilter::has_english_text(
                    EmailSearchField::Body,
                    "\"alpha omega\"",
                ))
                .with_mask(bulk_mask),
        )
        .await
        .unwrap();
    assert_eq!(
        results, expected,
        "phrase verification across fetch chunks and id blocks"
    );
}

async fn test_internal_features(store: &SearchStore) {
    let mask = full_mask();

    assert_query(
        store,
        vec![SearchFilter::KeyValue {
            field: SearchField::Email(EmailSearchField::Headers),
            key: "X-Mailer".to_string(),
            op: KeyValueMatch::Exists,
        }],
        mask.clone(),
        &[0],
        "header exists with mixed case key",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::KeyValue {
            field: SearchField::Email(EmailSearchField::Headers),
            key: "x-mailer".to_string(),
            op: KeyValueMatch::Equals("SuperMail".to_string()),
        }],
        mask.clone(),
        &[0],
        "header equals on value token",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::text_prefix(
            EmailSearchField::Body,
            "internationalizat",
        )],
        mask.clone(),
        &[],
        "prefix longer than 16 bytes cannot match",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::text_prefix(
            EmailSearchField::Body,
            "internationaliz",
        )],
        mask.clone(),
        &[],
        "prefix cannot match hashed terms",
    )
    .await;

    assert_query(
        store,
        vec![
            SearchFilter::text_prefix(EmailSearchField::Subject, "quart"),
            SearchFilter::text_prefix(EmailSearchField::Subject, "quarterly"),
        ],
        mask.clone(),
        &[0],
        "nested prefixes",
    )
    .await;

    assert_query(
        store,
        vec![
            SearchFilter::text_prefix(EmailSearchField::Subject, "quart"),
            SearchFilter::has_english_text(EmailSearchField::Subject, "quarterly"),
        ],
        mask.clone(),
        &[0],
        "prefix combined with contained exact term",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "",
        )],
        mask.clone(),
        &[],
        "empty text filter",
    )
    .await;

    let long_token = "z".repeat(300);
    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Body,
            &long_token,
        )],
        mask.clone(),
        &[],
        "overlong token",
    )
    .await;

    assert_query(
        store,
        vec![SearchFilter::Text {
            field: SearchField::Email(EmailSearchField::Body),
            op: TextMatch::Exact,
            value: "internationalization and localization".to_string(),
            language: Language::English,
        }],
        mask.clone(),
        &[5],
        "phrase with hashed terms",
    )
    .await;
}

async fn test_incremental(store: &SearchStore, caps: &Caps) {
    let mut mask = full_mask();
    mask.insert(20);

    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT)
        .with_document_id(20);
    document.index_text(
        EmailSearchField::Subject,
        "Quarterly addendum notes",
        Language::English,
    );
    document.index_text(
        EmailSearchField::Body,
        "addendum to the report",
        Language::English,
    );
    document.index_text(EmailSearchField::From, "alicecorp", Language::None);
    document.index_unsigned(EmailSearchField::To, 2020u64);
    document.index_bool(EmailSearchField::Cc, true);
    document.index_integer(EmailSearchField::Bcc, -42i64);
    search_index(store, vec![document]).await.unwrap();

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "quarterly",
        )],
        mask.clone(),
        &[0, 20],
        "incrementally added document",
    )
    .await;
    assert_query(
        store,
        vec![SearchFilter::text_prefix(
            EmailSearchField::Subject,
            "quart",
        )],
        mask.clone(),
        &[0, 20],
        "incrementally added document prefix",
    )
    .await;
    assert_query(
        store,
        vec![SearchFilter::integer_eq(EmailSearchField::To, 2020u64)],
        mask.clone(),
        &[20],
        "unsigned integer roundtrip",
    )
    .await;
    assert_query(
        store,
        vec![SearchFilter::integer_eq(EmailSearchField::Cc, 1u64)],
        mask.clone(),
        &[20],
        "boolean roundtrip",
    )
    .await;
    assert_query(
        store,
        vec![SearchFilter::signed_eq(EmailSearchField::Bcc, -42i64)],
        mask.clone(),
        &[20],
        "signed integer roundtrip",
    )
    .await;
    assert_query(
        store,
        vec![SearchFilter::signed_eq(EmailSearchField::Bcc, 42i64)],
        mask.clone(),
        &[],
        "signed integer sign mismatch",
    )
    .await;

    let query = SearchQuery::new(SearchIndex::Email)
        .with_account_id(ACCOUNT)
        .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, 20u32));
    search_unindex(store, query).await.unwrap();

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "quarterly",
        )],
        mask.clone(),
        &[0],
        "document hidden after unindex",
    )
    .await;

    test_filters(store, caps).await;
}

async fn test_sort(store: &SearchStore) {
    let mask = RoaringBitmap::from_iter([0u32, 1, 2, 3, 4]);
    let ranks = AHashMap::from_iter([(0u32, 4u32), (1, 1), (2, 3), (3, 0), (4, 2)]);

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT)
                .with_filter(SearchFilter::is_in_set(mask.clone()))
                .with_comparator(SearchComparator::sorted_set(ranks.clone(), true))
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![3, 1, 4, 2, 0], "sorted set ascending");

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT)
                .with_filter(SearchFilter::is_in_set(mask.clone()))
                .with_comparator(SearchComparator::sorted_set(ranks, false))
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![0, 2, 4, 1, 3], "sorted set descending");

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT)
                .with_filter(SearchFilter::is_in_set(mask.clone()))
                .with_comparators(vec![
                    SearchComparator::set(RoaringBitmap::from_iter([1u32, 3]), false),
                    SearchComparator::sorted_set(
                        AHashMap::from_iter([(0u32, 0u32), (1, 1), (2, 2), (3, 3), (4, 4)]),
                        true,
                    ),
                ])
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![1, 3, 0, 2, 4], "document set then sorted set");

    let sparse_ranks = AHashMap::from_iter([(0u32, 1u32), (1, 0)]);
    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT)
                .with_filter(SearchFilter::is_in_set(mask.clone()))
                .with_comparator(SearchComparator::sorted_set(sparse_ranks.clone(), true))
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        results,
        vec![1, 0, 2, 3, 4],
        "missing ids sort last ascending"
    );

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT)
                .with_filter(SearchFilter::is_in_set(mask.clone()))
                .with_comparator(SearchComparator::sorted_set(sparse_ranks, false))
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        results,
        vec![0, 1, 2, 3, 4],
        "missing ids sort last descending"
    );

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT)
                .with_filter(SearchFilter::is_in_set(mask.clone()))
                .with_comparator(SearchComparator::set(
                    RoaringBitmap::from_iter([1u32, 3]),
                    true,
                ))
                .with_mask(mask.clone()),
        )
        .await
        .unwrap();
    assert_eq!(
        results,
        vec![0, 2, 4, 1, 3],
        "document set comparator ascending"
    );
}

async fn test_update(store: &SearchStore) {
    let mask = RoaringBitmap::from_iter([0u32]);

    let mut document = IndexDocument::new(SearchIndex::Contacts)
        .with_account_id(ACCOUNT_CONTACTS)
        .with_document_id(0);
    document.index_text(ContactSearchField::Name, "john smith", Language::None);
    search_index(store, vec![document]).await.unwrap();
    refresh(store).await;

    let query_name = |name: &str| {
        SearchQuery::new(SearchIndex::Contacts)
            .with_account_id(ACCOUNT_CONTACTS)
            .with_filter(SearchFilter::has_keyword(ContactSearchField::Name, name))
            .with_mask(mask.clone())
    };

    assert_eq!(
        store.query_account(query_name("john")).await.unwrap(),
        vec![0],
        "contact indexed"
    );

    let mut document = IndexDocument::new(SearchIndex::Contacts)
        .with_account_id(ACCOUNT_CONTACTS)
        .with_document_id(0);
    document.index_text(ContactSearchField::Name, "jane doe", Language::None);
    search_index(store, vec![document]).await.unwrap();
    refresh(store).await;

    assert_eq!(
        store.query_account(query_name("john")).await.unwrap(),
        Vec::<u32>::new(),
        "old contact terms removed after update"
    );
    assert_eq!(
        store.query_account(query_name("jane")).await.unwrap(),
        vec![0],
        "new contact terms visible after update"
    );
}

async fn test_unindex(store: &SearchStore) {
    let mask = full_mask();

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "fillerco",
        )],
        mask.clone(),
        &FILLER_IDS.collect::<Vec<_>>(),
        "fillers before unindex",
    )
    .await;

    let mut query = SearchQuery::new(SearchIndex::Email)
        .with_account_id(ACCOUNT)
        .with_filter(SearchFilter::Or);
    for id in [7u32, 8] {
        query = query.with_filter(SearchFilter::integer_eq(SearchField::DocumentId, id));
    }
    query = query.with_filter(SearchFilter::End);
    search_unindex(store, query).await.unwrap();
    refresh(store).await;

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "fillerco",
        )],
        mask.clone(),
        &FILLER_IDS.filter(|id| *id > 8).collect::<Vec<_>>(),
        "fillers after unindex",
    )
    .await;

    let mut query = SearchQuery::new(SearchIndex::Email)
        .with_account_id(ACCOUNT)
        .with_filter(SearchFilter::Or);
    for id in [9u32, 9, 500] {
        query = query.with_filter(SearchFilter::integer_eq(SearchField::DocumentId, id));
    }
    query = query.with_filter(SearchFilter::End);
    search_unindex(store, query).await.unwrap();
    refresh(store).await;

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "fillerco",
        )],
        mask.clone(),
        &FILLER_IDS.filter(|id| *id > 9).collect::<Vec<_>>(),
        "duplicate and unknown ids are tolerated",
    )
    .await;

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Email)
            .with_filter(SearchFilter::Or)
            .with_filter(SearchFilter::And)
            .with_account_id(ACCOUNT)
            .with_filter(SearchFilter::Or)
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, 10u32))
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, 11u32))
            .with_filter(SearchFilter::End)
            .with_filter(SearchFilter::End)
            .with_filter(SearchFilter::And)
            .with_account_id(ACCOUNT_DUP)
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, 0u32))
            .with_filter(SearchFilter::End)
            .with_filter(SearchFilter::End),
    )
    .await
    .unwrap();
    refresh(store).await;

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "fillerco",
        )],
        mask.clone(),
        &FILLER_IDS.filter(|id| *id > 11).collect::<Vec<_>>(),
        "multi account unindex removes own documents",
    )
    .await;

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT_DUP)
                .with_filter(SearchFilter::has_english_text(
                    EmailSearchField::Subject,
                    "finalword",
                ))
                .with_mask(RoaringBitmap::from_iter([0u32])),
        )
        .await
        .unwrap();
    assert_eq!(
        results,
        Vec::<u32>::new(),
        "multi account unindex removes other account documents"
    );

    if store.internal_fts().is_some() {
        assert!(
            search_unindex(
                store,
                SearchQuery::new(SearchIndex::Email)
                    .with_account_id(ACCOUNT)
                    .with_filter(SearchFilter::has_keyword(EmailSearchField::From, "x")),
            )
            .await
            .is_err(),
            "unsupported unindex filters are rejected"
        );
    }
}

async fn test_term_blocks(store: &SearchStore) {
    let ids = [1u32, 0xFFFF, 0x10000, (2 << 16) | 3, (1 << 24) | 1];
    let mask = RoaringBitmap::from_iter(ids);

    let mut documents = Vec::new();
    for id in ids {
        let mut document = IndexDocument::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_BLOCKS)
            .with_document_id(id);
        document.index_text(
            EmailSearchField::Subject,
            &format!("blockterm entry{id}"),
            Language::English,
        );
        if id == 1 {
            document.index_text(
                EmailSearchField::Subject,
                "abcdefghijklmnop",
                Language::None,
            );
        }
        documents.push(document);
    }
    search_index(store, documents).await.unwrap();
    refresh(store).await;

    let query = |filter: SearchFilter| {
        SearchQuery::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_BLOCKS)
            .with_filter(filter)
            .with_mask(mask.clone())
    };

    let results = store
        .query_account(query(SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "blockterm",
        )))
        .await
        .unwrap();
    assert_eq!(results, ids.to_vec(), "term spans document id blocks");

    let results = store
        .query_account(query(SearchFilter::text_prefix(
            EmailSearchField::Subject,
            "blockte",
        )))
        .await
        .unwrap();
    assert_eq!(results, ids.to_vec(), "prefix spans document id blocks");

    for (prefix, context) in [
        (
            "abcdefghijklmnop",
            "sixteen byte prefix matches verbatim term",
        ),
        ("abcdefghijklmno", "prefix of sixteen byte verbatim term"),
    ] {
        let results = store
            .query_account(query(SearchFilter::text_prefix(
                EmailSearchField::Subject,
                prefix,
            )))
            .await
            .unwrap();
        assert_eq!(results, vec![1], "unexpected results for {context}");
    }

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_BLOCKS)
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, ids[4])),
    )
    .await
    .unwrap();
    refresh(store).await;

    let results = store
        .query_account(query(SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "blockterm",
        )))
        .await
        .unwrap();
    assert_eq!(
        results,
        ids[..4].to_vec(),
        "removing an aliased block entry keeps its block neighbors"
    );

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_BLOCKS)
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, ids[1])),
    )
    .await
    .unwrap();
    refresh(store).await;

    let results = store
        .query_account(query(SearchFilter::has_english_text(
            EmailSearchField::Subject,
            "blockterm",
        )))
        .await
        .unwrap();
    assert_eq!(
        results,
        vec![ids[0], ids[2], ids[3]],
        "removing a block boundary entry keeps the adjacent block"
    );
}

async fn search_region_key_count(store: &Store, typ: u8, account_id: u32) -> u64 {
    use store::write::{AnyKey, SearchIndex};
    let tag = typ | SearchIndex::Email.to_u8();
    let mut begin = vec![tag];
    begin.extend_from_slice(&account_id.to_be_bytes());
    let mut end = begin.clone();
    end.extend_from_slice(&[u8::MAX; 30]);
    let mut count = 0u64;
    store
        .iterate(
            store::IterateParams::new(
                AnyKey {
                    subspace: store::SUBSPACE_SEARCH_INDEX,
                    key: begin,
                },
                AnyKey {
                    subspace: store::SUBSPACE_SEARCH_INDEX,
                    key: end,
                },
            )
            .no_values(),
            |_, _| {
                count += 1;
                Ok(true)
            },
        )
        .await
        .unwrap();
    count
}

async fn verify_account_regions_empty(store: &Store, account_id: u32) {
    use store::write::SearchIndexClass;
    for typ in [SearchIndexClass::TYPE_TERM, SearchIndexClass::TYPE_DOCUMENT] {
        assert_eq!(
            search_region_key_count(store, typ, account_id).await,
            0,
            "search region type {typ} for account {account_id} is not empty"
        );
    }
}

async fn global_region_key_count(store: &Store, typ: u8) -> u64 {
    use store::write::{AnyKey, SearchIndex};
    let tag = typ | SearchIndex::Tracing.to_u8();
    let begin = vec![tag];
    let mut end = vec![tag];
    end.extend_from_slice(&[u8::MAX; 30]);
    let mut count = 0u64;
    store
        .iterate(
            store::IterateParams::new(
                AnyKey {
                    subspace: store::SUBSPACE_SEARCH_INDEX,
                    key: begin,
                },
                AnyKey {
                    subspace: store::SUBSPACE_SEARCH_INDEX,
                    key: end,
                },
            )
            .no_values(),
            |_, _| {
                count += 1;
                Ok(true)
            },
        )
        .await
        .unwrap();
    count
}

async fn test_duplicate_batch(store: &SearchStore) {
    let mask = RoaringBitmap::from_iter([0u32]);

    let mut first = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT_DUP)
        .with_document_id(0);
    first.index_text(
        EmailSearchField::Subject,
        "obsoleteword draft",
        Language::English,
    );
    let mut second = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT_DUP)
        .with_document_id(0);
    second.index_text(
        EmailSearchField::Subject,
        "finalword revision",
        Language::English,
    );
    search_index(store, vec![first, second]).await.unwrap();

    let mut first = IndexDocument::new(SearchIndex::Contacts)
        .with_account_id(ACCOUNT_DUP)
        .with_document_id(0);
    first.index_text(ContactSearchField::Name, "obsoletename", Language::None);
    let mut second = IndexDocument::new(SearchIndex::Contacts)
        .with_account_id(ACCOUNT_DUP)
        .with_document_id(0);
    second.index_text(ContactSearchField::Name, "finalname", Language::None);
    search_index(store, vec![first, second]).await.unwrap();
    refresh(store).await;

    let assert_dup =
        |index: SearchIndex, filter: SearchFilter, expected: Vec<u32>, context: &'static str| {
            let mask = mask.clone();
            async move {
                let results = store
                    .query_account(
                        SearchQuery::new(index)
                            .with_account_id(ACCOUNT_DUP)
                            .with_filter(filter)
                            .with_mask(mask),
                    )
                    .await
                    .unwrap();
                assert_eq!(results, expected, "unexpected results for {context}");
            }
        };

    let verify = || async {
        assert_dup(
            SearchIndex::Email,
            SearchFilter::has_english_text(EmailSearchField::Subject, "obsoleteword"),
            vec![],
            "first email version replaced within batch",
        )
        .await;
        assert_dup(
            SearchIndex::Email,
            SearchFilter::has_english_text(EmailSearchField::Subject, "finalword"),
            vec![0],
            "second email version wins within batch",
        )
        .await;
        assert_dup(
            SearchIndex::Contacts,
            SearchFilter::has_keyword(ContactSearchField::Name, "obsoletename"),
            vec![],
            "first contact version replaced within batch",
        )
        .await;
        assert_dup(
            SearchIndex::Contacts,
            SearchFilter::has_keyword(ContactSearchField::Name, "finalname"),
            vec![0],
            "second contact version wins within batch",
        )
        .await;
    };

    verify().await;
}

async fn test_hashed_term_unindex(store: &SearchStore) {
    let mask = full_mask();

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Body,
            "internationalization",
        )],
        mask.clone(),
        &[5],
        "hashed term before unindex",
    )
    .await;

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Email)
            .with_account_id(ACCOUNT)
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, 5u32)),
    )
    .await
    .unwrap();
    refresh(store).await;

    assert_query(
        store,
        vec![SearchFilter::has_english_text(
            EmailSearchField::Body,
            "internationalization",
        )],
        mask.clone(),
        &[],
        "hashed term removed after unindex",
    )
    .await;
}

async fn test_bulk_unindex(store: &SearchStore, internal_store: &Store) {
    use store::write::SearchIndexClass;

    let total = 1200u32;
    let unique_terms = total as u64 + 1;
    let mask = RoaringBitmap::from_iter(0..total);
    for chunk_start in (0..total).step_by(200) {
        let mut documents = Vec::new();
        for id in chunk_start..(chunk_start + 200).min(total) {
            let mut document = IndexDocument::new(SearchIndex::Email)
                .with_account_id(ACCOUNT_CHUNKS)
                .with_document_id(id);
            let mut body = "chunkterm ".repeat(40);
            body.push_str(&format!("uniqueterm{id}"));
            document.index_text(EmailSearchField::Body, &body, Language::None);
            documents.push(document);
        }
        search_index(store, documents).await.unwrap();
    }

    let query_chunkterm = || {
        SearchQuery::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_CHUNKS)
            .with_filter(SearchFilter::has_keyword(
                EmailSearchField::Body,
                "chunkterm",
            ))
            .with_mask(mask.clone())
    };

    let results = store
        .query_account(query_chunkterm())
        .await
        .unwrap()
        .into_iter()
        .collect::<RoaringBitmap>();
    assert_eq!(results, mask, "all documents match before deletion");

    let keys_before =
        search_region_key_count(internal_store, SearchIndexClass::TYPE_TERM, ACCOUNT_CHUNKS).await;
    assert_eq!(keys_before, unique_terms, "expected one key per term");

    let mut unindex = SearchQuery::new(SearchIndex::Email)
        .with_account_id(ACCOUNT_CHUNKS)
        .with_filter(SearchFilter::Or);
    for id in 400..800u32 {
        unindex = unindex.with_filter(SearchFilter::integer_eq(SearchField::DocumentId, id));
    }
    unindex = unindex.with_filter(SearchFilter::End);
    search_unindex(store, unindex).await.unwrap();

    let expected = RoaringBitmap::from_iter((0..400u32).chain(800..total));
    let results = store
        .query_account(query_chunkterm())
        .await
        .unwrap()
        .into_iter()
        .collect::<RoaringBitmap>();
    assert_eq!(results, expected, "deleted range is hidden");

    for id in [0u32, 399, 800, 1199] {
        let results = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_account_id(ACCOUNT_CHUNKS)
                    .with_filter(SearchFilter::has_keyword(
                        EmailSearchField::Body,
                        format!("uniqueterm{id}"),
                    ))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();
        assert_eq!(results, vec![id], "unique term for surviving document {id}");
    }

    let keys_after =
        search_region_key_count(internal_store, SearchIndexClass::TYPE_TERM, ACCOUNT_CHUNKS).await;
    assert_eq!(
        keys_after,
        unique_terms - 400,
        "term keys of unindexed documents were not removed"
    );
}

async fn test_account_wipe(store: &SearchStore) {
    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Email).with_account_id(ACCOUNT_OTHER),
    )
    .await
    .unwrap();
    refresh(store).await;

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_filters(vec![
                    SearchFilter::integer_eq(SearchField::AccountId, ACCOUNT_OTHER),
                    SearchFilter::has_keyword(EmailSearchField::From, "alicecorp"),
                ])
                .with_mask(RoaringBitmap::from_iter([0u32])),
        )
        .await
        .unwrap();
    assert_eq!(results, Vec::<u32>::new(), "wiped account has no results");

    assert_query(
        store,
        vec![SearchFilter::has_keyword(
            EmailSearchField::From,
            "alicecorp",
        )],
        full_mask(),
        &[0, 2],
        "other accounts unaffected by wipe",
    )
    .await;
}

async fn test_large_document(store: &SearchStore, caps: &Caps) {
    let (keyword_len, body_len) = if caps.internal {
        (10 * 1024, 20 * 1024 * 1024)
    } else if store.is_postgres() || store.is_mysql() {
        (512, 512 * 1024)
    } else {
        (10 * 1024, 20 * 1024 * 1024)
    };
    let mut large_text = String::with_capacity(body_len);
    while large_text.len() < body_len {
        let word = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(rand::rng().random_range(3..10))
            .map(char::from)
            .collect::<String>();
        large_text.push_str(&word);
        large_text.push(' ');
    }
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT_LARGE)
        .with_document_id(1);
    for field in [
        EmailSearchField::From,
        EmailSearchField::To,
        EmailSearchField::Cc,
        EmailSearchField::Bcc,
        EmailSearchField::Subject,
    ] {
        document.index_text(field, &large_text[..keyword_len], Language::English);
    }
    for field in [EmailSearchField::Body, EmailSearchField::Attachment] {
        document.index_text(field, &large_text, Language::English);
    }
    document.index_text(
        EmailSearchField::Subject,
        "needleinhaystack marker",
        Language::English,
    );
    search_index(store, vec![document]).await.unwrap();
    refresh(store).await;

    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT_LARGE)
                .with_filter(SearchFilter::has_english_text(
                    EmailSearchField::Subject,
                    "needleinhaystack",
                ))
                .with_mask(RoaringBitmap::from_iter([1u32])),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![1], "large document is searchable");

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Email)
            .with_account_id(ACCOUNT_LARGE)
            .with_filter(SearchFilter::integer_eq(SearchField::DocumentId, 1u32)),
    )
    .await
    .unwrap();
    refresh(store).await;
}

async fn test_global(store: &SearchStore, caps: &Caps) {
    use store::search::TracingSearchField;

    const BUCKET: u64 = 1 << 48;
    const ID1: u64 = 1;
    const ID2: u64 = 2;
    const ID0: u64 = BUCKET - 1;
    const ID3: u64 = BUCKET | 3;
    const ID4: u64 = BUCKET | 4;
    const ID5: u64 = (2 * BUCKET) | 5;
    const ID6: u64 = (2 * BUCKET) | 6;
    const ID7: u64 = (2 * BUCKET) | 7;

    let mut documents = Vec::new();
    for (id, queue_id, event_type, keywords) in [
        (ID1, 1000u64, 1u64, "init start"),
        (ID2, 1000, 2, "init complete"),
        (ID0, 1000, 1, "edge start"),
        (ID3, 1001, 1, "process start"),
        (ID4, 1001, 2, "process complete"),
        (ID5, 1002, 1, "cleanup start"),
        (ID6, 1002, 2, "cleanup complete"),
    ] {
        let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(id);
        document.index_unsigned(TracingSearchField::QueueId, queue_id);
        document.index_unsigned(TracingSearchField::EventType, event_type);
        document.index_text(TracingSearchField::Keywords, keywords, Language::None);
        documents.push(document);
    }
    search_index(store, documents).await.unwrap();
    refresh(store).await;

    let query_all = || {
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_gt(SearchField::Id, 0u64))
    };
    let assert_global = |query: SearchQuery, expected: Vec<u64>, context: &'static str| async move {
        let results = store
            .query_global(query)
            .await
            .unwrap_or_else(|err| panic!("global query failed for {context}: {err:?}"))
            .into_iter()
            .collect::<Vec<_>>();
        assert_eq!(results, expected, "unexpected results for {context}");
    };

    assert_global(
        query_all(),
        vec![ID1, ID2, ID0, ID3, ID4, ID5, ID6],
        "all ids",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_gt(SearchField::Id, ID2))
            .with_filter(SearchFilter::integer_lt(SearchField::Id, ID6))
            .with_filter(SearchFilter::has_keyword(
                TracingSearchField::Keywords,
                "start",
            )),
        vec![ID0, ID3, ID5],
        "id window with keyword",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::integer_eq(
            TracingSearchField::QueueId,
            1001u64,
        )),
        vec![ID3, ID4],
        "queue id",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::integer_eq(
            TracingSearchField::EventType,
            1u64,
        )),
        vec![ID1, ID0, ID3, ID5],
        "event type",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filters(vec![
            SearchFilter::Or,
            SearchFilter::integer_eq(TracingSearchField::QueueId, 1000u64),
            SearchFilter::integer_eq(TracingSearchField::QueueId, 1002u64),
            SearchFilter::End,
        ]),
        vec![ID1, ID2, ID0, ID5, ID6],
        "global or",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filters(vec![
            SearchFilter::Or,
            SearchFilter::integer_eq(TracingSearchField::QueueId, 1000u64),
            SearchFilter::integer_eq(TracingSearchField::QueueId, 1001u64),
            SearchFilter::End,
            SearchFilter::has_keyword(TracingSearchField::Keywords, "start"),
        ]),
        vec![ID1, ID0, ID3],
        "global or intersected with keyword",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_eq(SearchField::Id, ID4)),
        vec![ID4],
        "id equals fast path",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_gt(SearchField::Id, ID4))
            .with_filter(SearchFilter::integer_lt(SearchField::Id, ID4)),
        vec![],
        "empty id window",
    )
    .await;
    if caps.internal {
        for (filters, context) in [
            (
                vec![
                    SearchFilter::Not,
                    SearchFilter::has_keyword(TracingSearchField::Keywords, "start"),
                    SearchFilter::End,
                ],
                "not is unsupported",
            ),
            (
                vec![SearchFilter::is_in_set(RoaringBitmap::from_iter([1u32]))],
                "document sets are unsupported",
            ),
            (
                vec![
                    SearchFilter::Or,
                    SearchFilter::has_keyword(TracingSearchField::Keywords, "start"),
                    SearchFilter::integer_gt(SearchField::Id, 0u64),
                    SearchFilter::End,
                ],
                "id filters inside or are unsupported",
            ),
        ] {
            assert!(
                store
                    .query_global(SearchQuery::new(SearchIndex::Tracing).with_filters(filters))
                    .await
                    .is_err(),
                "expected error for {context}"
            );
        }
    }
    assert_global(
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_eq(
                TracingSearchField::QueueId,
                1000u64,
            ))
            .with_filter(SearchFilter::has_keyword(
                TracingSearchField::Keywords,
                "complete",
            )),
        vec![ID2],
        "queue id with keyword",
    )
    .await;
    if caps.prefix {
        assert_global(
            SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
                TracingSearchField::Keywords,
                "proc*",
            )),
            vec![ID3, ID4],
            "keyword prefix",
        )
        .await;
    }

    if caps.internal {
        assert!(
            search_unindex(
                store,
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::integer_lt(SearchField::Id, 3u64)),
            )
            .await
            .is_err(),
            "purge cutoff within the first bucket must be rejected"
        );
    }

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_lt(SearchField::Id, ID3)),
    )
    .await
    .unwrap();
    refresh(store).await;

    assert_global(query_all(), vec![ID3, ID4, ID5, ID6], "all ids after purge").await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "init",
        )),
        vec![],
        "purged keywords are hidden",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "start",
        )),
        vec![ID3, ID5],
        "surviving keywords after purge",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "edge",
        )),
        vec![],
        "document at the top of a purged bucket is swept",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_gt(SearchField::Id, ID3))
            .with_filter(SearchFilter::has_keyword(
                TracingSearchField::Keywords,
                "start",
            )),
        vec![ID5],
        "id window clamps term results",
    )
    .await;

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_lt(SearchField::Id, 2 * BUCKET)),
    )
    .await
    .unwrap();
    refresh(store).await;

    assert_global(query_all(), vec![ID5, ID6], "all ids after boundary purge").await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "process",
        )),
        vec![],
        "boundary purge sweeps the full bucket below the cutoff",
    )
    .await;

    let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(ID7);
    document.index_unsigned(TracingSearchField::QueueId, 1003u64);
    document.index_unsigned(TracingSearchField::EventType, 1u64);
    document.index_text(
        TracingSearchField::Keywords,
        "restart start",
        Language::None,
    );
    search_index(store, vec![document]).await.unwrap();
    refresh(store).await;

    assert_global(query_all(), vec![ID5, ID6, ID7], "id added after purge").await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "start",
        )),
        vec![ID5, ID7],
        "keyword added after purge",
    )
    .await;

    search_unindex(
        store,
        SearchQuery::new(SearchIndex::Tracing)
            .with_filter(SearchFilter::integer_lt(SearchField::Id, u64::MAX)),
    )
    .await
    .unwrap();
    refresh(store).await;

    assert_global(query_all(), vec![], "all ids after wipe").await;

    if caps.internal {
        use store::write::SearchIndexClass;
        let internal_store = store.internal_fts().unwrap();
        for typ in [
            SearchIndexClass::TYPE_TERM,
            SearchIndexClass::TYPE_DOCUMENT,
            SearchIndexClass::TYPE_DOCUMENT_ID,
        ] {
            assert_eq!(
                global_region_key_count(internal_store, typ).await,
                0,
                "global region type {typ} is not empty after wipe"
            );
        }
    }

    let mut account_document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(ACCOUNT_MIXED)
        .with_document_id(0);
    account_document.index_text(
        EmailSearchField::Subject,
        "mixedbatch email",
        Language::English,
    );
    let mut stale_document = IndexDocument::new(SearchIndex::Tracing).with_id(10u64);
    stale_document.index_unsigned(TracingSearchField::EventType, 4u64);
    stale_document.index_text(
        TracingSearchField::Keywords,
        "stalefirst trace",
        Language::None,
    );
    let mut global_document = IndexDocument::new(SearchIndex::Tracing).with_id(10u64);
    global_document.index_unsigned(TracingSearchField::EventType, 5u64);
    global_document.index_text(
        TracingSearchField::Keywords,
        "mixedbatch trace",
        Language::None,
    );
    search_index(
        store,
        vec![account_document, stale_document, global_document],
    )
    .await
    .unwrap();
    refresh(store).await;

    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "mixedbatch",
        )),
        vec![10],
        "global document from mixed batch",
    )
    .await;
    assert_global(
        SearchQuery::new(SearchIndex::Tracing).with_filter(SearchFilter::has_keyword(
            TracingSearchField::Keywords,
            "stalefirst",
        )),
        vec![],
        "duplicate global document in one batch is replaced",
    )
    .await;
    let results = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_account_id(ACCOUNT_MIXED)
                .with_filter(SearchFilter::has_english_text(
                    EmailSearchField::Subject,
                    "mixedbatch",
                ))
                .with_mask(RoaringBitmap::from_iter([0u32])),
        )
        .await
        .unwrap();
    assert_eq!(results, vec![0], "account document from mixed batch");
}
