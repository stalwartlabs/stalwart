/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    SearchStore,
    backend::meili::{MeiliSearchStore, Task, TaskStatus, TaskUid},
    search::{
        CalendarSearchField, ContactSearchField, EmailSearchField, SearchField, SearchableField,
        TracingSearchField,
    },
};
use registry::schema::structs;
use reqwest::{Error, Response, Url};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};

impl MeiliSearchStore {
    pub async fn open(config: structs::MeilisearchStore) -> Result<SearchStore, String> {
        let client = config.http_auth.build_http_client(
            config.http_headers,
            "application/json".into(),
            config.timeout,
            config.allow_invalid_certs,
        )?;

        Url::parse(&config.url).map_err(|e| format!("Invalid URL: {e}",))?;

        let ms = Self {
            client,
            url: config.url,
            task_poll_interval: Duration::from_millis(500),
            task_poll_retries: 120,
            task_fail_on_timeout: true,
        };

        if let Err(err) = ms.create_indexes().await {
            return Err(format!("Failed to create indexes: {err}"));
        }

        Ok(SearchStore::MeiliSearch(Arc::new(MeiliSearchStore {
            client: ms.client,
            url: ms.url,
            task_poll_interval: config.poll_interval.into_inner(),
            task_poll_retries: config.max_retries as usize,
            task_fail_on_timeout: config.fail_on_timeout,
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
        let index_name = T::index().index_name();
        let response = assert_success(
            self.client
                .post(format!("{}/indexes", self.url))
                .body(
                    json!({
                        "uid": index_name,
                        "primaryKey": "id",
                    })
                    .to_string(),
                )
                .send()
                .await,
        )
        .await?;

        if !self.wait_for_task(response).await? {
            // Index already exists
            return Ok(());
        }

        let mut searchable = Vec::new();
        let mut filterable = Vec::new();
        let mut sortable = Vec::new();

        for field in T::all_fields() {
            if field.is_indexed() {
                sortable.push(Value::String(field.field_name().to_string()));
            }
            if field.is_text() {
                searchable.push(Value::String(field.field_name().to_string()));
            } else {
                filterable.push(Value::String(field.field_name().to_string()));
            }
        }

        for key in T::primary_keys() {
            filterable.push(Value::String(key.field_name().to_string()));
            if matches!(key, SearchField::Id) {
                sortable.push(Value::String(key.field_name().to_string()));
            }
        }

        #[cfg(feature = "test_mode")]
        filterable.push(Value::String("bcc".into()));

        if !searchable.is_empty() {
            self.update_index_settings(
                index_name,
                "searchable-attributes",
                Value::Array(searchable),
            )
            .await?;
        }

        if !filterable.is_empty() {
            self.update_index_settings(
                index_name,
                "filterable-attributes",
                Value::Array(filterable),
            )
            .await?;
        }

        if !sortable.is_empty() {
            self.update_index_settings(index_name, "sortable-attributes", Value::Array(sortable))
                .await?;
        }

        Ok(())
    }

    async fn update_index_settings(
        &self,
        index_uid: &str,
        setting: &str,
        value: Value,
    ) -> trc::Result<bool> {
        let response = assert_success(
            self.client
                .put(format!(
                    "{}/indexes/{}/settings/{}",
                    self.url, index_uid, setting
                ))
                .body(value.to_string())
                .send()
                .await,
        )
        .await?;
        self.wait_for_task(response).await
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
            let response = self
                .client
                .delete(format!("{}/indexes/{}", self.url, index.index_name()))
                .send()
                .await
                .map_err(|err| trc::StoreEvent::MeilisearchError.reason(err))?;

            match response.status().as_u16() {
                200..=299 => {
                    self.wait_for_task(response).await?;
                }
                400..=499 => {
                    // Index does not exist
                    return Ok(());
                }
                _ => {
                    let status = response.status();
                    let msg = response.text().await.unwrap_or_default();
                    return Err(trc::StoreEvent::MeilisearchError
                        .reason(msg)
                        .ctx(trc::Key::Code, status.as_u16()));
                }
            }
        }

        Ok(())
    }

    pub(crate) async fn wait_for_task(&self, response: Response) -> trc::Result<bool> {
        let response_body = response.text().await.map_err(|err| {
            trc::StoreEvent::MeilisearchError
                .reason(err)
                .details("Request failed")
        })?;
        let task_uid = serde_json::from_str::<TaskUid>(&response_body)
            .map_err(|err| trc::StoreEvent::MeilisearchError.reason(err))?
            .task_uid;

        let mut loop_count = 0;
        let url = format!("{}/tasks/{}", self.url, task_uid);

        while loop_count < self.task_poll_retries {
            let resp = assert_success(self.client.get(&url).send().await).await?;

            let text = resp
                .text()
                .await
                .map_err(|err| trc::StoreEvent::MeilisearchError.reason(err))?;

            let task = serde_json::from_str::<Task>(&text).map_err(|err| {
                trc::StoreEvent::MeilisearchError
                    .reason(err)
                    .details(text.clone())
            })?;

            match task.status {
                TaskStatus::Succeeded => return Ok(true),
                TaskStatus::Failed => {
                    let (code, message) = task
                        .error
                        .map(|e| (e.code, Some(e.message)))
                        .unwrap_or((None, None));
                    return if matches!(code.as_deref(), Some("index_already_exists")) {
                        Ok(false)
                    } else {
                        Err(trc::StoreEvent::MeilisearchError
                            .reason("Meilisearch task failed.")
                            .id(task_uid)
                            .code(code)
                            .details(message))
                    };
                }
                TaskStatus::Canceled => {
                    return Err(trc::StoreEvent::MeilisearchError
                        .reason("Meilisearch task was canceled")
                        .id(task_uid));
                }
                TaskStatus::Enqueued | TaskStatus::Processing => {
                    loop_count += 1;
                    tokio::time::sleep(self.task_poll_interval).await;
                }
                TaskStatus::Unknown => {
                    return Err(trc::StoreEvent::MeilisearchError
                        .reason("Meilisearch task returned an unknown status")
                        .id(task_uid)
                        .details(text));
                }
            }
        }

        if self.task_fail_on_timeout {
            Err(trc::StoreEvent::MeilisearchError
                .reason("Timed out waiting for Meilisearch task")
                .id(task_uid))
        } else {
            Ok(true)
        }
    }
}

pub(crate) async fn assert_success(response: Result<Response, Error>) -> trc::Result<Response> {
    match response {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                Ok(response)
            } else {
                Err(trc::StoreEvent::MeilisearchError
                    .reason(response.text().await.unwrap_or_default())
                    .ctx(trc::Key::Code, status.as_u16()))
            }
        }
        Err(err) => Err(trc::StoreEvent::MeilisearchError.reason(err)),
    }
}
