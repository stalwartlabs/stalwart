/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    Store, ValueKey,
    search::{
        IndexDocument, SearchValue,
        codec::{self, GLOBAL_META_WATERMARK, MAX_FIELD_TOKENS, WAL_ADDS, WalWriter},
        maintain::MetaU64,
        tokenize,
    },
    write::{BatchBuilder, SearchIndex, SearchIndexClass, ValueClass, assert::AssertValue},
};
use ahash::AHashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use trc::AddContext;
use utils::{cheeky_hash::CheekyHash, snowflake::SnowflakeIdGenerator};

pub(crate) type GlobalGroups = AHashMap<SearchIndex, BTreeMap<u64, BTreeSet<(u8, CheekyHash)>>>;

pub(crate) fn analyze_global(document: IndexDocument) -> BTreeSet<(u8, CheekyHash)> {
    let mut members = BTreeSet::new();

    for (field, value) in document.fields {
        let field_id = field.u8_id();

        match value {
            SearchValue::Text { value, language } => {
                let mut tokens = 0u32;
                tokenize::tokenize(&value, language, |token| {
                    members.insert((field_id, CheekyHash::new(token.word.as_bytes())));
                    tokens += 1;
                    tokens < MAX_FIELD_TOKENS as u32
                });
            }
            SearchValue::KeyValues(map) => {
                for (key, value) in map {
                    members.insert((field_id, CheekyHash::new(key.as_bytes())));
                    tokenize::tokenize(&value, nlp::language::Language::None, |token| {
                        members.insert((field_id, tokenize::key_value_term(&key, &token.word)));
                        true
                    });
                }
            }
            SearchValue::Int(v) => {
                members.insert((field_id, tokenize::integer_term(v as u64)));
            }
            SearchValue::Uint(v) => {
                members.insert((field_id, tokenize::integer_term(v)));
            }
            SearchValue::Boolean(v) => {
                members.insert((field_id, tokenize::integer_term(v as u64)));
            }
        }
    }

    members
}

impl Store {
    pub(crate) fn index_global_documents(&self, batch: &mut BatchBuilder, groups: GlobalGroups) {
        for (index, documents) in groups {
            let mut adds = WalWriter::new(WAL_ADDS);
            for (document_id, members) in &documents {
                adds.begin_document(*document_id);
                for (field, term) in members {
                    adds.push_entry(|buf| {
                        buf.push(*field);
                        codec::push_term(buf, term);
                    });
                }
                adds.end_document();

                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::GlobalDocument {
                        index,
                        document_id: *document_id,
                    }),
                    vec![],
                );
                batch.commit_point();
            }
            for (id, value) in adds.finish() {
                batch.set(
                    ValueClass::SearchIndex(SearchIndexClass::GlobalWal { index, id }),
                    value,
                );
            }
            batch.commit_point();
        }
    }

    pub(crate) async fn unindex_global(
        &self,
        index: SearchIndex,
        purge_id: u64,
    ) -> trc::Result<()> {
        let newest_id = SnowflakeIdGenerator::from_duration(Duration::ZERO).unwrap_or(u64::MAX);
        if purge_id == u64::MAX || purge_id > newest_id {
            let (begin, end) = codec::global_type_range(SearchIndexClass::TYPE_GLOBAL_WAL, index);
            self.delete_range(codec::any_key(begin), codec::any_key(end))
                .await
                .caused_by(trc::location!())?;

            let mut attempts = 0;
            loop {
                match self.claim_global_generation(index).await {
                    Ok(_) => break,
                    Err(err) if err.is_assertion_failure() && attempts < 3 => {
                        attempts += 1;
                    }
                    Err(err) => {
                        return Err(err.caused_by(trc::location!()));
                    }
                }
            }

            for typ in [
                SearchIndexClass::TYPE_GLOBAL_TERM,
                SearchIndexClass::TYPE_GLOBAL_DOCUMENT,
                SearchIndexClass::TYPE_GLOBAL_META,
            ] {
                let (begin, end) = codec::global_type_range(typ, index);
                self.delete_range(codec::any_key(begin), codec::any_key(end))
                    .await
                    .caused_by(trc::location!())?;
            }
            return Ok(());
        }

        let watermark_class = ValueClass::SearchIndex(SearchIndexClass::GlobalMeta {
            index,
            kind: GLOBAL_META_WATERMARK,
        });
        let mut attempts = 0;
        loop {
            let current = self
                .get_value::<MetaU64>(ValueKey::from(watermark_class.clone()))
                .await
                .caused_by(trc::location!())?;
            if current
                .as_ref()
                .is_some_and(|current| current.0 >= purge_id)
            {
                break;
            }
            let mut batch = BatchBuilder::new();
            batch.assert_value(
                watermark_class.clone(),
                current.map_or(AssertValue::None, |current| AssertValue::U64(current.0)),
            );
            batch.set(watermark_class.clone(), purge_id.to_be_bytes().to_vec());
            match self.write(batch.build_all()).await {
                Ok(_) => break,
                Err(err) if err.is_assertion_failure() && attempts < 3 => {
                    attempts += 1;
                }
                Err(err) => {
                    return Err(err.caused_by(trc::location!()));
                }
            }
        }

        self.delete_range(
            codec::any_key(codec::global_document_key(index, 0)),
            codec::any_key(codec::global_document_key(index, purge_id)),
        )
        .await
        .caused_by(trc::location!())
    }
}
