/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    backend::elastic::ElasticSearchStore,
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchableField,
        TracingSearchField,
    },
};
use reqwest::{Error, Response, Url};
use serde_json::{Value, json};
use utils::config::{Config, http::build_http_client, utils::AsKey};

impl ElasticSearchStore {
    pub async fn open(config: &mut Config, prefix: impl AsKey) -> Option<Self> {
        let client = build_http_client(config, prefix.clone(), "application/json".into())?;
        let prefix = prefix.as_key();
        let url = config
            .value_require((&prefix, "url"))?
            .trim_end_matches("/")
            .to_string();
        Url::parse(&url)
            .map_err(|e| config.new_parse_error((&prefix, "url"), format!("Invalid URL: {e}",)))
            .ok()?;

        let es = Self { client, url };

        let shards = config
            .property_or_default((&prefix, "index.shards"), "3")
            .unwrap_or(3);
        let replicas = config
            .property_or_default((&prefix, "index.replicas"), "0")
            .unwrap_or(0);
        let with_source = config
            .property_or_default((&prefix, "index.include-source"), "false")
            .unwrap_or(false);

        if let Err(err) = es.create_indexes(shards, replicas, with_source).await {
            config.new_build_error(prefix.as_str(), err.to_string());
        }

        Some(es)
    }

    pub async fn create_indexes(
        &self,
        shards: usize,
        replicas: usize,
        with_source: bool,
    ) -> trc::Result<()> {
        self.create_index::<EmailSearchField>(shards, replicas, with_source)
            .await?;
        self.create_index::<CalendarSearchField>(shards, replicas, with_source)
            .await?;
        self.create_index::<ContactSearchField>(shards, replicas, with_source)
            .await?;
        self.create_index::<TracingSearchField>(shards, replicas, with_source)
            .await?;
        Ok(())
    }

    async fn create_index<T: SearchableField>(
        &self,
        shards: usize,
        replicas: usize,
        with_source: bool,
    ) -> trc::Result<()> {
        let mut mappings = serde_json::Map::new();
        mappings.insert(
            "properties".to_string(),
            Value::Object(
                T::primary_keys()
                    .iter()
                    .chain(T::all_fields())
                    .map(|field| (field.field_name().to_string(), field.es_schema()))
                    .collect::<serde_json::Map<String, Value>>(),
            ),
        );
        if !with_source {
            mappings.insert("_source".to_string(), json!({ "enabled": false }));
        }
        let body = json!({
          "mappings": mappings,
          "settings": {
            "index.number_of_shards": shards,
            "index.number_of_replicas": replicas,
            "analysis": {
              "analyzer": {
                "default": {
                  "type": "custom",
                  "tokenizer": "standard",
                  "filter": ["lowercase", "stemmer"]
                }
              }
            }
          }
        });

        let response = self
            .client
            .put(format!("{}/{}", self.url, T::index().index_name()))
            .body(body.to_string())
            .send()
            .await
            .map_err(|err| {
                trc::StoreEvent::ElasticsearchError
                    .reason(err)
                    .details("Failed to create index")
            })?;

        match response.status().as_u16() {
            200..300 => Ok(()),
            status @ (400..500) => {
                let text = response.text().await.unwrap_or_default();
                if text.contains("resource_already_exists_exception") {
                    // Index already exists, ignore
                    Ok(())
                } else {
                    Err(trc::StoreEvent::ElasticsearchError
                        .reason(text)
                        .ctx(trc::Key::Code, status))
                }
            }
            status => {
                let text = response.text().await.unwrap_or_default();
                Err(trc::StoreEvent::ElasticsearchError
                    .reason(text)
                    .ctx(trc::Key::Code, status))
            }
        }
    }

    #[cfg(feature = "test_mode")]
    pub async fn drop_indexes(&self) -> trc::Result<()> {
        use crate::write::SearchIndex;

        for index in &[
            SearchIndex::Email,
            SearchIndex::Calendar,
            SearchIndex::Contacts,
            SearchIndex::Tracing,
        ] {
            assert_success(
                self.client
                    .delete(format!("{}/{}", self.url, index.index_name()))
                    .send()
                    .await,
            )
            .await
            .map(|_| ())?;
        }

        Ok(())
    }
}

pub(crate) async fn assert_success(response: Result<Response, Error>) -> trc::Result<Response> {
    match response {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                Ok(response)
            } else {
                Err(trc::StoreEvent::ElasticsearchError
                    .reason(response.text().await.unwrap_or_default())
                    .ctx(trc::Key::Code, status.as_u16()))
            }
        }
        Err(err) => Err(trc::StoreEvent::ElasticsearchError.reason(err)),
    }
}
