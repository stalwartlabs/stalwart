/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::store::deflate_test_resource;
use ahash::AHashSet;
use nlp::language::Language;
use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Instant,
};
use store::{
    SearchStore,
    ahash::AHashMap,
    rand::{self, Rng, distr::Alphanumeric},
    roaring::RoaringBitmap,
    search::{
        EmailSearchField, IndexDocument, SearchComparator, SearchField, SearchFilter,
        SearchOperator, SearchQuery, SearchValue, TracingSearchField,
    },
    write::SearchIndex,
};
use utils::map::vec_map::VecMap;

pub const FIELDS: [&str; 20] = [
    "id",
    "accession_number",
    "artist",
    "artistRole",
    "artistId",
    "title",
    "dateText",
    "medium",
    "creditLine",
    "year",
    "acquisitionYear",
    "dimensions",
    "width",
    "height",
    "depth",
    "units",
    "inscription",
    "thumbnailCopyright",
    "thumbnailUrl",
    "url",
];

/*
 "title", // Subject
 "year".   // ReceivedAt
 "width",  // Size
 "height", // SentAt
 "artist" // Headers
 "artistRole" // Cc
 "medium",  // From
 "creditLine" // Body
 "acquisitionYear" // Bcc
 "accession_number" // To
*/

const FIELD_MAPPINGS: [EmailSearchField; 20] = [
    EmailSearchField::HasAttachment, // "id",
    EmailSearchField::To,            // "accession_number",
    EmailSearchField::Headers,       // "artist",
    EmailSearchField::Cc,            // "artistRole",
    EmailSearchField::HasAttachment, // "artistId",
    EmailSearchField::Subject,       // "title",
    EmailSearchField::HasAttachment, // "dateText",
    EmailSearchField::From,          // "medium",
    EmailSearchField::Body,          // "creditLine",
    EmailSearchField::ReceivedAt,    // "year",
    EmailSearchField::Bcc,           // "acquisitionYear",
    EmailSearchField::HasAttachment, // "dimensions",
    EmailSearchField::Size,          // "width",
    EmailSearchField::SentAt,        // "height",
    EmailSearchField::HasAttachment, // "depth",
    EmailSearchField::HasAttachment, // "units",
    EmailSearchField::HasAttachment, // "inscription",
    EmailSearchField::HasAttachment, // "thumbnailCopyright",
    EmailSearchField::HasAttachment, // "thumbnailUrl",
    EmailSearchField::HasAttachment, // "url",
];

const ALL_IDS: &[&str] = &[
    "p11293", "p79426", "p79427", "p79428", "p79429", "p79430", "d05503", "d00399", "d05352",
    "p01764", "t05843", "n02478", "n02479", "n03568", "n03658", "n04327", "n04328", "n04721",
    "n04739", "n05095", "n05096", "n05145", "n05157", "n05158", "n05159", "n05298", "n05303",
    "n06070", "t01181", "t03571", "t05805", "t05806", "t12147", "t12154", "t12155", "ar00039",
    "t12600", "p80203", "t13209", "t13560", "t13561", "t13655", "t13811", "p13352", "p13351",
    "p13350", "p13349", "p13348", "p13347", "p13346", "p13345", "p13344", "p13342", "p13341",
    "p13340", "p13339", "p13338", "p13337", "p13336", "p13335", "p13334", "p13333", "p13332",
    "p13331", "p13330", "p13329", "p13328", "p13327", "p13326", "p13325", "p13324", "p13323",
    "t13786", "p13322", "p13321", "p13320", "p13319", "p13318", "p13317", "p13316", "p13315",
    "p13314", "t13588", "t13587", "t13586", "t13585", "t13584", "t13540", "t13444", "ar01154",
    "ar01153", "t03681", "t12601", "ar00166", "t12625", "t12915", "p04182", "t06483", "ar00703",
    "t07671", "ar00021", "t05557", "t07918", "p06298", "p05465", "p06640", "t12855", "t01355",
    "t12800", "t12557", "t02078", "ar00052", "ar00627", "t00352", "t07275", "t12318", "t04931",
    "t13683", "t13686", "t13687", "t13688", "t13689", "t13690", "t13691", "t13769", "t13773",
    "t07151", "t13684", "t07523", "t12369", "t12567", "ar00627", "ar00052", "t00352", "t07275",
    "t12318", "t04931", "t13683", "t13686", "t13687", "t13688", "t13689", "t13690", "t13691",
    "t07766", "t07918", "t12993", "ar00044", "t13326", "t07614", "t12414",
];

#[allow(clippy::mutex_atomic)]
pub async fn test(store: SearchStore, do_insert: bool) {
    println!("Running Store query tests...");

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .unwrap();
    let now = Instant::now();
    let documents = Arc::new(Mutex::new(Vec::new()));
    let mut mask = RoaringBitmap::new();
    let mut fields = AHashMap::new();

    // Global ids test
    println!("Running global id filtering tests...");
    test_global(store.clone()).await;

    // Large document insert test
    println!("Running large document insert tests...");
    let mut large_text = String::with_capacity(20 * 1024 * 1024);
    while large_text.len() < 20 * 1024 * 1024 {
        let word = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(rand::rng().random_range(3..10))
            .map(char::from)
            .collect::<String>();
        large_text.push_str(&word);
        large_text.push(' ');
    }
    let mut document = IndexDocument::new(SearchIndex::Email)
        .with_account_id(1)
        .with_document_id(1);
    for field in [
        EmailSearchField::From,
        EmailSearchField::To,
        EmailSearchField::Cc,
        EmailSearchField::Bcc,
        EmailSearchField::Subject,
    ] {
        document.index_text(field, &large_text[..10 * 1024], Language::English);
    }
    for field in [EmailSearchField::Body, EmailSearchField::Attachment] {
        document.index_text(field, &large_text, Language::English);
    }
    for field in [
        EmailSearchField::ReceivedAt,
        EmailSearchField::SentAt,
        EmailSearchField::Size,
    ] {
        document.index_unsigned(field, rand::rng().random_range(100u64..1_000_000u64));
    }
    store.index(vec![document]).await.unwrap();
    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Email).await.unwrap();
    }

    println!("Running account filtering tests...");
    let filter_ids = std::env::var("QUICK_TEST").is_ok().then(|| {
        let mut ids = AHashSet::new();
        for &id in ALL_IDS {
            ids.insert(id.to_string());
            let id = id.as_bytes();
            if id.last().unwrap() > &b'0' {
                let mut alt_id = id.to_vec();
                *alt_id.last_mut().unwrap() -= 1;
                ids.insert(String::from_utf8(alt_id).unwrap());
            }
            if id.last().unwrap() < &b'9' {
                let mut alt_id = id.to_vec();
                *alt_id.last_mut().unwrap() += 1;
                ids.insert(String::from_utf8(alt_id).unwrap());
            }
        }

        ids
    });

    pool.scope_fifo(|s| {
        for (document_id, record) in csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(&deflate_test_resource("artwork_data.csv.gz")[..])
            .records()
            .enumerate()
        {
            let record = record.unwrap();
            let documents = documents.clone();

            if let Some(filter_ids) = &filter_ids {
                let id = record.get(1).unwrap().to_lowercase();
                if !filter_ids.contains(&id) {
                    continue;
                }
            }

            s.spawn_fifo(move |_| {
                let mut document = IndexDocument::new(SearchIndex::Email)
                    .with_account_id(0)
                    .with_document_id(document_id as u32);
                for (pos, field) in record.iter().enumerate() {
                    match FIELD_MAPPINGS[pos] {
                        EmailSearchField::From
                        | EmailSearchField::To
                        | EmailSearchField::Cc
                        | EmailSearchField::Bcc => {
                            document.index_text(
                                FIELD_MAPPINGS[pos].clone(),
                                &field.to_lowercase(),
                                Language::None,
                            );
                        }
                        EmailSearchField::Subject
                        | EmailSearchField::Body
                        | EmailSearchField::Attachment => {
                            document.index_text(
                                FIELD_MAPPINGS[pos].clone(),
                                &field
                                    .replace(|ch: char| !ch.is_alphanumeric(), " ")
                                    .to_lowercase(),
                                Language::English,
                            );
                        }
                        EmailSearchField::Headers => {
                            document.insert_key_value(
                                EmailSearchField::Headers,
                                "artist",
                                field.to_lowercase(),
                            );
                        }
                        EmailSearchField::ReceivedAt
                        | EmailSearchField::SentAt
                        | EmailSearchField::Size => {
                            document.index_unsigned(
                                FIELD_MAPPINGS[pos].clone(),
                                field.parse::<u64>().unwrap_or(0),
                            );
                        }
                        _ => {
                            continue;
                        }
                    };
                }

                documents.lock().unwrap().push(document);
            });
        }
    });

    println!(
        "Parsed {} entries in {} ms.",
        documents.lock().unwrap().len(),
        now.elapsed().as_millis()
    );

    let now = Instant::now();
    let batches = documents.lock().unwrap().drain(..).collect::<Vec<_>>();

    print!("Inserting... ",);
    let mut chunks = Vec::new();
    let mut chunk = Vec::new();
    for document in batches {
        let mut document_id = None;
        let mut to_field = None;

        for (key, value) in document.fields() {
            if key == &SearchField::DocumentId {
                if let SearchValue::Uint(id) = value {
                    document_id = Some(*id as u32);
                }
            } else if key == &SearchField::Email(EmailSearchField::To)
                && let SearchValue::Text { value, .. } = value
            {
                to_field = Some(value.to_string());
            }
        }
        let document_id = document_id.unwrap();
        let to_field = to_field.unwrap();
        mask.insert(document_id);
        fields.insert(document_id, to_field);

        chunk.push(document);
        if chunk.len() == 10 {
            chunks.push(chunk);
            chunk = Vec::new();
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }

    if do_insert {
        let mut tasks = Vec::new();
        for chunk in chunks {
            let chunk_instance = Instant::now();
            tasks.push({
                let db = store.clone();
                tokio::spawn(async move { db.index(chunk).await })
            });

            if tasks.len() == 100 {
                for handle in tasks {
                    handle.await.unwrap().unwrap();
                }
                print!(" [{} ms]", chunk_instance.elapsed().as_millis());
                std::io::stdout().flush().unwrap();
                tasks = Vec::new();
            }
        }

        if !tasks.is_empty() {
            for handle in tasks {
                handle.await.unwrap().unwrap();
            }
        }

        // Refresh
        if let SearchStore::ElasticSearch(store) = &store {
            store.refresh_index(SearchIndex::Email).await.unwrap();
        }

        println!("\nInsert took {} ms.", now.elapsed().as_millis());
    }

    if store.internal_fts().is_none() {
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![SearchFilter::eq(SearchField::AccountId, 0u32)])
                    .with_comparator(SearchComparator::ascending(EmailSearchField::ReceivedAt))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<RoaringBitmap>();
        assert_eq!(ids, mask);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![
                        SearchFilter::eq(SearchField::AccountId, 0u32),
                        SearchFilter::ge(SearchField::DocumentId, 0u32),
                    ])
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<RoaringBitmap>();
        assert_eq!(ids, mask);
    }

    println!("Running account filter tests...");
    let now = Instant::now();
    test_filter(store.clone(), &fields, &mask).await;
    println!("Filtering took {} ms.", now.elapsed().as_millis());

    println!("Running account sort tests...");
    let now = Instant::now();
    test_sort(store.clone(), &fields, &mask).await;
    println!("Sorting took {} ms.", now.elapsed().as_millis());

    println!("Running unindex tests...");
    let now = Instant::now();
    test_unindex(store.clone(), &fields).await;
    println!("Unindexing took {} ms.", now.elapsed().as_millis());
}

async fn test_filter(store: SearchStore, fields: &AHashMap<u32, String>, mask: &RoaringBitmap) {
    let can_stem = !store.is_mysql();

    let tests = [
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::has_english_text(EmailSearchField::Subject, "water"),
                SearchFilter::eq(EmailSearchField::ReceivedAt, 1979u32),
            ],
            vec!["p11293"],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::has_keyword(EmailSearchField::From, "gelatin"),
                SearchFilter::gt(EmailSearchField::ReceivedAt, 2000u32),
                SearchFilter::lt(EmailSearchField::Size, 180u32),
                SearchFilter::gt(EmailSearchField::Size, 0u32),
            ],
            vec!["p79426", "p79427", "p79428", "p79429", "p79430"],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::has_english_text(EmailSearchField::Subject, "'rustic bridge'"),
            ],
            vec!["d05503"],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::has_english_text(EmailSearchField::Subject, "'rustic'"),
                SearchFilter::has_english_text(
                    EmailSearchField::Subject,
                    if can_stem { "study" } else { "studies" },
                ),
            ],
            vec!["d00399", "d05352"],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::cond(
                    EmailSearchField::Headers,
                    SearchOperator::Contains,
                    SearchValue::KeyValues(VecMap::from_iter([(
                        "artist".to_string(),
                        "kunst, mauro".to_string(),
                    )])),
                ),
                SearchFilter::has_keyword(EmailSearchField::Cc, "artist"),
                SearchFilter::Or,
                SearchFilter::eq(EmailSearchField::ReceivedAt, 1969u32),
                SearchFilter::eq(EmailSearchField::ReceivedAt, 1971u32),
                SearchFilter::End,
            ],
            vec!["p01764", "t05843"],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::Not,
                SearchFilter::has_keyword(EmailSearchField::From, "oil"),
                SearchFilter::End,
                SearchFilter::has_english_text(
                    EmailSearchField::Body,
                    if can_stem { "bequeath" } else { "bequeathed" },
                ),
                SearchFilter::Or,
                SearchFilter::And,
                SearchFilter::ge(EmailSearchField::ReceivedAt, 1900u32),
                SearchFilter::lt(EmailSearchField::ReceivedAt, 1910u32),
                SearchFilter::End,
                SearchFilter::And,
                SearchFilter::ge(EmailSearchField::ReceivedAt, 2000u32),
                SearchFilter::lt(EmailSearchField::ReceivedAt, 2010u32),
                SearchFilter::End,
                SearchFilter::End,
            ],
            vec![
                "n02478", "n02479", "n03568", "n03658", "n04327", "n04328", "n04721", "n04739",
                "n05095", "n05096", "n05145", "n05157", "n05158", "n05159", "n05298", "n05303",
                "n06070", "t01181", "t03571", "t05805", "t05806", "t12147", "t12154", "t12155",
            ],
        ),
        (
            vec![
                SearchFilter::And,
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::cond(
                    EmailSearchField::Headers,
                    SearchOperator::Contains,
                    SearchValue::KeyValues(VecMap::from_iter([(
                        "artist".to_string(),
                        "warhol".to_string(),
                    )])),
                ),
                SearchFilter::Not,
                SearchFilter::has_english_text(EmailSearchField::Subject, "'campbell'"),
                SearchFilter::End,
                SearchFilter::Not,
                SearchFilter::Or,
                SearchFilter::gt(EmailSearchField::ReceivedAt, 1980u32),
                SearchFilter::And,
                SearchFilter::gt(EmailSearchField::Size, 500u32),
                SearchFilter::gt(EmailSearchField::SentAt, 500u32),
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::End,
                SearchFilter::eq(EmailSearchField::Bcc, "2008".to_string()),
                SearchFilter::End,
            ],
            vec!["ar00039", "t12600"],
        ),
        (
            if can_stem {
                vec![
                    SearchFilter::eq(SearchField::AccountId, 0u32),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "study"),
                    SearchFilter::has_keyword(EmailSearchField::From, "paper"),
                    SearchFilter::has_english_text(EmailSearchField::Body, "'purchased'"),
                    SearchFilter::Not,
                    SearchFilter::Or,
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'anatomical'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'discarded'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'untitled'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'girl'"),
                    SearchFilter::End,
                    SearchFilter::End,
                    SearchFilter::gt(EmailSearchField::ReceivedAt, 1900u32),
                    SearchFilter::gt(EmailSearchField::Bcc, "2008".to_string()),
                ]
            } else {
                vec![
                    SearchFilter::eq(SearchField::AccountId, 0u32),
                    SearchFilter::Or,
                    SearchFilter::has_english_text(EmailSearchField::Subject, "study"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "studies"),
                    SearchFilter::End,
                    SearchFilter::has_keyword(EmailSearchField::From, "paper"),
                    SearchFilter::has_english_text(EmailSearchField::Body, "'purchased'"),
                    SearchFilter::Not,
                    SearchFilter::Or,
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'anatomical'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'discarded'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'untitled'"),
                    SearchFilter::has_english_text(EmailSearchField::Subject, "'girl'"),
                    SearchFilter::End,
                    SearchFilter::End,
                    SearchFilter::gt(EmailSearchField::ReceivedAt, 1900u32),
                    SearchFilter::gt(EmailSearchField::Bcc, "2008".to_string()),
                ]
            },
            vec!["p80203", "t13209", "t13560", "t13561"],
        ),
    ];

    for (filters, expected_results) in tests {
        //println!("Running test: {:?}", filter);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparator(SearchComparator::ascending(EmailSearchField::To))
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in ids {
            results.push(fields.get(&document_id).unwrap());
        }
        assert_eq!(results, expected_results);
    }
}

async fn test_sort(store: SearchStore, fields: &AHashMap<u32, String>, mask: &RoaringBitmap) {
    let is_reversed = store.is_postgres();

    let tests = [
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::gt(EmailSearchField::ReceivedAt, 0u32),
                SearchFilter::gt(EmailSearchField::Bcc, "0000".to_string()),
                SearchFilter::gt(EmailSearchField::Size, 0u32),
            ],
            vec![
                SearchComparator::descending(EmailSearchField::ReceivedAt),
                SearchComparator::ascending(EmailSearchField::Bcc),
                SearchComparator::ascending(EmailSearchField::Size),
                SearchComparator::descending(EmailSearchField::To),
            ],
            vec![
                "t13655", "t13811", "p13352", "p13351", "p13350", "p13349", "p13348", "p13347",
                "p13346", "p13345", "p13344", "p13342", "p13341", "p13340", "p13339", "p13338",
                "p13337", "p13336", "p13335", "p13334", "p13333", "p13332", "p13331", "p13330",
                "p13329", "p13328", "p13327", "p13326", "p13325", "p13324", "p13323", "t13786",
                "p13322", "p13321", "p13320", "p13319", "p13318", "p13317", "p13316", "p13315",
                "p13314", "t13588", "t13587", "t13586", "t13585", "t13584", "t13540", "t13444",
                "ar01154", "ar01153",
            ],
        ),
        (
            vec![
                SearchFilter::eq(SearchField::AccountId, 0u32),
                SearchFilter::gt(EmailSearchField::Size, 0u32),
                SearchFilter::gt(EmailSearchField::SentAt, 0u32),
            ],
            vec![
                SearchComparator::descending(EmailSearchField::Size),
                SearchComparator::ascending(EmailSearchField::SentAt),
            ],
            vec![
                "t03681", "t12601", "ar00166", "t12625", "t12915", "p04182", "t06483", "ar00703",
                "t07671", "ar00021", "t05557", "t07918", "p06298", "p05465", "p06640", "t12855",
                "t01355", "t12800", "t12557", "t02078",
            ],
        ),
        (
            vec![SearchFilter::eq(SearchField::AccountId, 0u32)],
            vec![
                SearchComparator::descending(EmailSearchField::From),
                SearchComparator::descending(EmailSearchField::Cc),
                SearchComparator::ascending(EmailSearchField::To),
            ],
            if is_reversed {
                vec![
                    "ar00052", "ar00627", "t00352", "t07275", "t12318", "t04931", "t13683",
                    "t13686", "t13687", "t13688", "t13689", "t13690", "t13691", "t13769", "t13773",
                    "t07151", "t13684", "t07523", "t12369", "t12567",
                ]
            } else {
                vec![
                    "ar00627", "ar00052", "t00352", "t07275", "t12318", "t04931", "t13683",
                    "t13686", "t13687", "t13688", "t13689", "t13690", "t13691", "t07766", "t07918",
                    "t12993", "ar00044", "t13326", "t07614", "t12414",
                ]
            },
        ),
    ];

    for (filters, comparators, expected_results) in tests {
        //println!("Running test: {:?}", sort);
        let ids = store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(filters)
                    .with_comparators(comparators)
                    .with_mask(mask.clone()),
            )
            .await
            .unwrap();

        let mut results = Vec::new();
        for document_id in ids.into_iter().take(expected_results.len()) {
            results.push(fields.get(&document_id).unwrap());
        }
        assert_eq!(results, expected_results);
    }
}

async fn test_unindex(store: SearchStore, fields: &AHashMap<u32, String>) {
    let ids = store
        .query_account(
            SearchQuery::new(SearchIndex::Email)
                .with_mask(RoaringBitmap::from_iter(fields.keys().copied()))
                .with_filters(vec![
                    SearchFilter::has_keyword(EmailSearchField::From, "gelatin"),
                    SearchFilter::gt(EmailSearchField::ReceivedAt, 2000u32),
                    SearchFilter::lt(EmailSearchField::Size, 180u32),
                    SearchFilter::gt(EmailSearchField::Size, 0u32),
                ])
                .with_account_id(0),
        )
        .await
        .unwrap();
    assert!(!ids.is_empty());
    let expected_count = ids.len().saturating_sub(10);

    let mut query = SearchQuery::new(SearchIndex::Email)
        .with_account_id(0)
        .with_filter(SearchFilter::Or);
    for id in ids.into_iter().take(10) {
        query = query.with_filter(SearchFilter::eq(SearchField::DocumentId, id));
    }
    query = query.with_filter(SearchFilter::End);

    store.unindex(query).await.unwrap();

    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Email).await.unwrap();
    }

    assert_eq!(
        store
            .query_account(
                SearchQuery::new(SearchIndex::Email)
                    .with_filters(vec![
                        SearchFilter::has_keyword(EmailSearchField::From, "gelatin"),
                        SearchFilter::gt(EmailSearchField::ReceivedAt, 2000u32),
                        SearchFilter::lt(EmailSearchField::Size, 180u32),
                        SearchFilter::gt(EmailSearchField::Size, 0u32),
                    ])
                    .with_account_id(0)
                    .with_mask(RoaringBitmap::from_iter(fields.keys().copied())),
            )
            .await
            .unwrap()
            .len(),
        expected_count
    );
}

async fn test_global(store: SearchStore) {
    // Insert global ids
    for (id, queue_id, etyp, keywords) in [
        (0, 1000u64, 1u64, "init start"),
        (1, 1000u64, 2u64, "init complete"),
        (2, 1001u64, 1u64, "process start"),
        (3, 1001u64, 2u64, "process complete"),
        (4, 1002u64, 1u64, "cleanup start"),
        (5, 1002u64, 2u64, "cleanup complete"),
    ] {
        let mut document = IndexDocument::new(SearchIndex::Tracing).with_id(id);
        document.index_unsigned(TracingSearchField::QueueId, queue_id);
        document.index_unsigned(TracingSearchField::EventType, etyp);
        document.index_text(TracingSearchField::Keywords, keywords, Language::None);
        store.index(vec![document]).await.unwrap();
    }

    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Tracing).await.unwrap();
    }

    // Query all
    assert_eq!(
        store
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::ge(SearchField::Id, 0u64))
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter([0, 1, 2, 3, 4, 5])
    );

    // Query with filter
    assert_eq!(
        store
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::gt(SearchField::Id, 1u64))
                    .with_filter(SearchFilter::lt(SearchField::Id, 5u64))
                    .with_filter(SearchFilter::has_keyword(
                        TracingSearchField::Keywords,
                        "start",
                    )),
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter([2, 4])
    );

    // Delete by filter
    store
        .unindex(
            SearchQuery::new(SearchIndex::Tracing)
                .with_filter(SearchFilter::lt(SearchField::Id, 3u64)),
        )
        .await
        .unwrap();

    // Refresh
    if let SearchStore::ElasticSearch(store) = &store {
        store.refresh_index(SearchIndex::Tracing).await.unwrap();
    }

    assert_eq!(
        store
            .query_global(
                SearchQuery::new(SearchIndex::Tracing)
                    .with_filter(SearchFilter::ge(SearchField::Id, 0u64))
            )
            .await
            .unwrap()
            .into_iter()
            .collect::<AHashSet<_>>(),
        AHashSet::from_iter([3, 4, 5])
    );
}
