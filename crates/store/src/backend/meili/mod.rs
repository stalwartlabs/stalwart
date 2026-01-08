/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;

pub mod main;
pub mod search;

pub struct MeiliSearchStore {
    client: Client,
    url: String,
    task_poll_interval: Duration,
    task_poll_retries: usize,
    task_fail_on_timeout: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TaskUid {
    #[serde(rename = "taskUid")]
    pub task_uid: u64,
}

#[derive(Debug, Deserialize)]
struct TaskError {
    message: String,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Task {
    //#[serde(rename = "uid")]
    //uid: u64,
    status: TaskStatus,
    #[serde(default)]
    error: Option<TaskError>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TaskStatus {
    Enqueued,
    Processing,
    Succeeded,
    Failed,
    Canceled,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
struct MeiliSearchResponse {
    hits: Vec<MeiliHit>,
    //#[allow(dead_code)]
    //#[serde(default, rename = "estimatedTotalHits")]
    //estimated_total_hits: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct MeiliHit {
    id: u64,
}
