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

        let mut paths = Vec::new();
        for name in ["file1", "file2"] {
            let contents = resource_type.generate();
            let path = format!(
                "{}/john%40example.com/default/{}",
                resource_type.base_path(),
                name
            );
            let etag = client
                .request("PUT", &path, contents.as_str())
                .await
                .with_status(StatusCode::CREATED)
                .etag()
                .to_string();
            paths.push((path, etag, contents));
        }

        if resource_type == DavResourceName::Cal {
            let path = format!("{}/john%40example.com", resource_type.base_path());
            let response = client
                .multiget_calendar(&path, &[&paths[0].0, &paths[1].0])
                .await;
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
            let response = client
                .multiget_addressbook(&path, &[&paths[0].0, &paths[1].0])
                .await;
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
