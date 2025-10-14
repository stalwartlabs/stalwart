/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

 use crate::jmap::{JMAPTest, JmapUtils};
use jmap_proto::request::method::MethodObject;
use serde_json::json;

pub async fn test(params: &mut JMAPTest) {
    println!("Running tests...");
    let account = params.account("jdoe@example.com");


}
