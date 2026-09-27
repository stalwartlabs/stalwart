/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{server::TestServer, webdav::GenerateTestDavResource};
use dav_proto::schema::property::{CalDavProperty, CardDavProperty, DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();

    for resource_type in [DavResourceName::Cal, DavResourceName::Card] {
        println!(
            "Running REPORT multiget tests ({})...",
            resource_type.base_path()
        );

        let container = format!("{}/john%40example.com/default", resource_type.base_path());
        let mut paths = Vec::new();
        let mut hrefs = Vec::new();
        for (stored, requested, canonical) in [
            ("file1", "file1", "file1"),
            ("file2", "file2", "file2"),
            ("abc@example.org", "abc%40example.org", "abc@example.org"),
            ("xyz%40example.org", "xyz@example.org", "xyz@example.org"),
        ] {
            let contents = resource_type.generate();
            let etag = client
                .request("PUT", &format!("{container}/{stored}"), contents.as_str())
                .await
                .with_status(StatusCode::CREATED)
                .etag()
                .to_string();
            hrefs.push(format!("{container}/{requested}"));
            paths.push((format!("{container}/{canonical}"), etag, contents));
        }
        let hrefs = hrefs.iter().map(String::as_str).collect::<Vec<_>>();

        if resource_type == DavResourceName::Cal {
            let path = format!("{}/john%40example.com", resource_type.base_path());
            let response = client.multiget_calendar(&path, &hrefs).await;
            for (path, etag, contents) in paths {
                let props = response.properties(&path);
                props
                    .get(DavProperty::WebDav(WebDavProperty::GetETag))
                    .with_values([etag.as_str()]);
                props
                    .get(DavProperty::CalDav(CalDavProperty::CalendarData(
                        Default::default(),
                    )))
                    .with_values([contents.as_str()]);
            }
        } else {
            let path = format!("{}/john%40example.com", resource_type.base_path());
            let response = client.multiget_addressbook(&path, &hrefs).await;
            for (path, etag, contents) in paths {
                let props = response.properties(&path);
                props
                    .get(DavProperty::WebDav(WebDavProperty::GetETag))
                    .with_values([etag.as_str()]);
                props
                    .get(DavProperty::CardDav(CardDavProperty::AddressData {
                        properties: Default::default(),
                        version: None,
                    }))
                    .with_values([contents.as_str()]);
            }
        }
    }

    client.delete_default_containers().await;
    test.assert_is_empty().await;
}
