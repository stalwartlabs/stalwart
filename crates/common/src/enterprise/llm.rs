/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: LicenseRef-SEL
 *
 * This file is subject to the Stalwart Enterprise License Agreement (SEL) and
 * is NOT open source software.
 *
 */

use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AiApiConfig {
    pub id: String,
    pub api_type: ApiType,
    pub url: String,
    pub model: String,
    pub timeout: Duration,
    pub headers: HeaderMap,
    pub tls_allow_invalid_certs: bool,
    pub default_temperature: f64,
}

#[derive(Clone, Copy, Debug)]
pub enum ApiType {
    ChatCompletion,
    TextCompletion,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatCompletionResponse {
    pub created: i64,
    pub object: String,
    pub id: String,
    pub model: String,
    pub choices: Vec<ChatCompletionChoice>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ChatCompletionChoice {
    pub index: i32,
    pub finish_reason: String,
    pub message: Message,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TextCompletionRequest {
    pub model: String,
    pub prompt: String,
    pub temperature: f64,
}

#[derive(Deserialize, Debug)]
pub struct TextCompletionResponse {
    pub created: i64,
    pub object: String,
    pub id: String,
    pub model: String,
    pub choices: Vec<TextCompletionChoice>,
}

#[derive(Deserialize, Debug)]
pub struct TextCompletionChoice {
    pub index: i32,
    pub finish_reason: String,
    pub text: String,
}

impl AiApiConfig {
    pub async fn send_request(
        &self,
        prompt: impl Into<String>,
        temperature: Option<f64>,
    ) -> trc::Result<String> {
        self.post_api(prompt, temperature).await.map_err(|err| {
            trc::Error::new(trc::EventType::Ai(trc::AiEvent::ApiError))
                .id(self.id.clone())
                .details("OpenAPI request failed")
                .reason(err)
        })
    }

    async fn post_api(
        &self,
        prompt: impl Into<String>,
        temperature: Option<f64>,
    ) -> Result<String, String> {
        // Serialize body
        let body = match self.api_type {
            ApiType::ChatCompletion => serde_json::to_string(&ChatCompletionRequest {
                model: self.model.to_string(),
                messages: vec![Message {
                    role: "user".to_string(),
                    content: prompt.into(),
                }],
                temperature: temperature.unwrap_or(self.default_temperature),
            })
            .map_err(|err| format!("Failed to serialize request: {}", err))?,
            ApiType::TextCompletion => serde_json::to_string(&TextCompletionRequest {
                model: self.model.to_string(),
                prompt: prompt.into(),
                temperature: temperature.unwrap_or(self.default_temperature),
            })
            .map_err(|err| format!("Failed to serialize request: {}", err))?,
        };

        // Send request
        let response = reqwest::Client::builder()
            .timeout(self.timeout)
            .danger_accept_invalid_certs(self.tls_allow_invalid_certs)
            .build()
            .map_err(|err| format!("Failed to create HTTP client: {}", err))?
            .post(&self.url)
            .headers(self.headers.clone())
            .body(body)
            .send()
            .await
            .map_err(|err| format!("API request to {} failed: {err}", self.url))?;

        if response.status().is_success() {
            let bytes = response.bytes().await.map_err(|err| {
                format!("Failed to read response body from {}: {}", self.url, err)
            })?;

            match self.api_type {
                ApiType::ChatCompletion => {
                    let response = serde_json::from_slice::<ChatCompletionResponse>(&bytes)
                        .map_err(|err| {
                            format!(
                                "Failed to chat completion parse response from {}: {}",
                                self.url, err
                            )
                        })?;
                    response
                        .choices
                        .into_iter()
                        .next()
                        .map(|choice| choice.message.content)
                        .filter(|text| !text.is_empty())
                        .ok_or_else(|| {
                            format!(
                                "Chat completion response from {} did not contain any choices: {}",
                                self.url,
                                std::str::from_utf8(&bytes).unwrap_or_default()
                            )
                        })
                }
                ApiType::TextCompletion => {
                    let response = serde_json::from_slice::<TextCompletionResponse>(&bytes)
                        .map_err(|err| {
                            format!(
                                "Failed to parse text completion response from {}: {}",
                                self.url, err
                            )
                        })?;
                    response
                        .choices
                        .into_iter()
                        .next()
                        .map(|choice| choice.text)
                        .filter(|text| !text.is_empty())
                        .ok_or_else(|| {
                            format!(
                                "Text completion response from {} did not contain any choices: {}",
                                self.url,
                                std::str::from_utf8(&bytes).unwrap_or_default()
                            )
                        })
                }
            }
        } else {
            let status = response.status();
            let bytes = response.bytes().await.unwrap_or_default();

            Err(format!(
                "OpenAPI request to {} failed with code {} ({}): {}",
                self.url,
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown"),
                std::str::from_utf8(&bytes).unwrap_or_default()
            ))
        }
    }
}
