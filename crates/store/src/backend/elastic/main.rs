/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use crate::{
    SearchStore,
    backend::elastic::ElasticSearchStore,
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchableField,
        TracingSearchField,
    },
};
use registry::schema::structs;
use reqwest::{Error, Response, Url};
use serde_json::{Value, json};

impl ElasticSearchStore {
    pub async fn open(config: structs::ElasticSearchStore) -> Result<SearchStore, String> {
        Url::parse(&config.url).map_err(|e| format!("Invalid URL: {e}",))?;

        Ok(SearchStore::ElasticSearch(Arc::new(Self {
            client: config
                .http_auth
                .build_http_client(
                    config.http_headers,
                    "application/json".into(),
                    config.timeout,
                    config.allow_invalid_certs,
                )
                .await?,
            url: config.url,
            num_replicas: config.num_replicas as usize,
            num_shards: config.num_shards as usize,
            include_source: config.include_source,
        })))
    }

    pub async fn create_indexes(&self) -> trc::Result<()> {
        self.create_index::<EmailSearchField>().await?;
        self.create_index::<CalendarSearchField>().await?;
        self.create_index::<ContactSearchField>().await?;
        self.create_index::<TracingSearchField>().await?;
        Ok(())
    }

    async fn create_index<T: SearchableField>(&self) -> trc::Result<()> {
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
        if !self.include_source {
            mappings.insert("_source".to_string(), json!({ "enabled": false }));
        }
        let body = json!({
          "mappings": mappings,
          "settings": {
            "index.number_of_shards": self.num_shards,
            "index.number_of_replicas": self.num_replicas,
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
