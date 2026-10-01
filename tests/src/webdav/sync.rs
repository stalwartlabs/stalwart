/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    server::TestServer,
    webdav::{DavResponse, GenerateTestDavResource},
};

use ahash::AHashSet;
use dav_proto::Depth;
use groupware::{DavResourceName, cache::GroupwareCache};
use hyper::StatusCode;
use serde_json::json;
use store::write::LogCollection;
use types::{collection::SyncCollection, id::Id};

pub async fn test(test: &TestServer) {
    let client = test.account("john@example.com").webdav_client();

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!(
            "Running REPORT sync-collection tests ({})...",
            resource_type.base_path()
        );
        let user_base_path = format!("{}/john%40example.com/", resource_type.base_path());

        // Test 1: Initial sync
        let response = client
            .sync_collection(&user_base_path, "", Depth::Infinity, None, ["D:getetag"])
            .await;
        assert_eq!(
            response.hrefs().len(),
            if resource_type == DavResourceName::File {
                1
            } else {
                2
            },
            "{:?}",
            response.hrefs()
        );
        let sync_token_1 = response.sync_token().to_string();

        // Test 2: No changes since last sync
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), Vec::<String>::new());

        // Test 3: Create a collection and make sure it is synced
        let new_collection = format!("{}new-collection/", user_base_path);
        client
            .mkcol("MKCOL", &new_collection, [], [])
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), vec![new_collection.clone()]);
        let sync_token_2 = response.sync_token().to_string();

        // Test 4: Create a file and make sure it is synced
        let new_file = format!("{new_collection}new-file");
        let contents = resource_type.generate();
        client
            .request("PUT", &new_file, &contents)
            .await
            .with_status(StatusCode::CREATED);
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        assert_eq!(
            response.hrefs(),
            vec![new_collection.clone(), new_file.clone()]
        );
        let sync_token_3 = response.sync_token().to_string();
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_2,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), vec![new_file.clone()]);

        // Test 5: sync-token with Depth 1
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token_1,
                Depth::One,
                None,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), vec![new_collection.clone()]);

        // Test 6: sync-token with Depth 0
        let response = client
            .sync_collection(
                &new_collection,
                &sync_token_1,
                Depth::Zero,
                None,
                ["D:getetag"],
            )
            .await;
        assert_eq!(response.hrefs(), vec![new_collection.clone()]);

        // Test 7: Outdated sync-token in If header should fail
        let new_file2 = format!("{new_collection}new-file2");
        let contents = resource_type.generate();
        let condition = format!("(<{sync_token_2}>)");
        client
            .request_with_headers(
                "PUT",
                &new_file2,
                [("if", condition.as_str())],
                contents.as_str(),
            )
            .await
            .with_status(StatusCode::PRECONDITION_FAILED)
            .with_empty_body();

        // Test 8: Correct sync-token in If header should work
        let condition = format!("(<{sync_token_3}>)");
        client
            .request_with_headers(
                "PUT",
                &new_file2,
                [("if", condition.as_str())],
                contents.as_str(),
            )
            .await
            .with_status(StatusCode::CREATED)
            .with_empty_body();

        // Test 9: Limit
        let mut sync_token = client
            .sync_collection(
                &new_collection,
                &sync_token_3,
                Depth::Zero,
                None,
                ["D:getetag"],
            )
            .await
            .sync_token()
            .to_string();
        let (folder_name, files) = client
            .create_hierarchy(user_base_path.trim_end_matches('/'), 1, 0, 10)
            .await;
        let mut expected_changes = files
            .iter()
            .map(|x| x.0.as_str())
            .chain([folder_name.as_str()])
            .collect::<AHashSet<_>>();
        for _ in 0..10 {
            let response = client
                .sync_collection(
                    &user_base_path,
                    &sync_token,
                    Depth::Infinity,
                    2.into(),
                    ["D:getetag"],
                )
                .await;
            sync_token = response.sync_token().to_string();
            let hrefs = response.hrefs();
            if hrefs.is_empty() {
                break;
            }
            let mut has_user_base_path = false;
            let mut item_count = 0;
            for href in hrefs {
                if href == user_base_path {
                    has_user_base_path = true;
                } else if expected_changes.remove(href) {
                    item_count += 1;
                } else {
                    panic!("Unexpected href: {href}");
                }
            }
            if has_user_base_path {
                assert_eq!(item_count, 2);
                response
                    .with_value(
                        "D:multistatus.D:response.D:status",
                        "HTTP/1.1 507 Insufficient Storage",
                    )
                    .with_value(
                        "D:multistatus.D:response.D:error.D:number-of-matches-within-limits",
                        "",
                    )
                    .with_value(
                        "D:multistatus.D:response.D:responsedescription",
                        "The number of matches exceeds the limit of 2",
                    );
            } else {
                assert!(item_count <= 2);
                break;
            }
        }
        assert!(expected_changes.is_empty(), "{:?}", expected_changes);

        // Test 10: Expect changes after deletion
        client
            .request("DELETE", &new_file, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        sync_token = response.sync_token().to_string();
        response
            .with_href_count(1)
            .with_value("D:multistatus.D:response.D:href", &new_file)
            .with_value(
                "D:multistatus.D:response.D:status",
                "HTTP/1.1 404 Not Found",
            );
        client
            .request("DELETE", &new_collection, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        let response = client
            .sync_collection(
                &user_base_path,
                &sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await;
        sync_token = response.sync_token().to_string();
        response
            .with_href_count(1)
            .with_value("D:multistatus.D:response.D:href", &new_collection)
            .with_value(
                "D:multistatus.D:response.D:status",
                "HTTP/1.1 404 Not Found",
            );
        client
            .request("DELETE", &folder_name, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        client
            .sync_collection(
                &user_base_path,
                &sync_token,
                Depth::Infinity,
                None,
                ["D:getetag"],
            )
            .await
            .with_href_count(1)
            .with_value("D:multistatus.D:response.D:href", &folder_name)
            .with_value(
                "D:multistatus.D:response.D:status",
                "HTTP/1.1 404 Not Found",
            );

        // Test 11: A truncated initial sync pages through every member while the collection changes
        let (paged_folder, created) = client
            .create_hierarchy(user_base_path.trim_end_matches('/'), 1, 0, 6)
            .await;
        let initial_files = created
            .into_iter()
            .map(|(href, _)| href)
            .filter(|href| *href != paged_folder)
            .collect::<Vec<_>>();
        let added_file = format!("{paged_folder}added-file");
        let mut deleted_files = Vec::new();
        let mut synced = AHashSet::new();
        let mut sync_token = String::new();
        for page_num in 0.. {
            assert!(page_num < 10, "initial sync did not finish");
            let response = client
                .sync_collection(
                    &paged_folder,
                    &sync_token,
                    Depth::One,
                    2.into(),
                    ["D:getetag"],
                )
                .await;
            sync_token = response.sync_token().to_string();
            let page = SyncPage::parse(&response, &paged_folder);
            assert!(page.removed.is_empty(), "{page:?}");
            assert!(page.changed.len() <= 2, "{page:?}");
            synced.extend(page.changed);
            if !page.is_truncated {
                break;
            }
            if page_num == 0 {
                let delivered = initial_files
                    .iter()
                    .find(|href| synced.contains(*href))
                    .expect("a file on the first page")
                    .clone();
                let pending = initial_files
                    .iter()
                    .rfind(|href| !synced.contains(*href))
                    .expect("a file after the first page")
                    .clone();
                for href in [&delivered, &pending] {
                    client
                        .request("DELETE", href, "")
                        .await
                        .with_status(StatusCode::NO_CONTENT);
                }
                client
                    .request("PUT", &added_file, &resource_type.generate())
                    .await
                    .with_status(StatusCode::CREATED);
                deleted_files.extend([delivered, pending]);
            }
        }
        let response = client
            .sync_collection(&paged_folder, &sync_token, Depth::One, None, ["D:getetag"])
            .await;
        let follow_up = SyncPage::parse(&response, &paged_folder);
        assert!(!follow_up.is_truncated, "{follow_up:?}");
        for href in &deleted_files {
            assert!(follow_up.removed.contains(href), "{href} {follow_up:?}");
        }
        assert!(follow_up.changed.contains(&added_file), "{follow_up:?}");
        synced.extend(follow_up.changed);
        for href in initial_files
            .iter()
            .filter(|href| !deleted_files.contains(*href))
            .chain([&paged_folder, &added_file])
        {
            assert!(synced.contains(href), "{href} never synced: {synced:?}");
        }

        // Test 12: A truncated incremental sync keeps changes made while paging
        let base_token = response.sync_token().to_string();
        let mut new_files = Vec::new();
        for num in 0..6 {
            let href = format!("{paged_folder}incremental-{num}");
            client
                .request("PUT", &href, &resource_type.generate())
                .await
                .with_status(StatusCode::CREATED);
            new_files.push(href);
        }
        let older_file = initial_files
            .iter()
            .find(|href| !deleted_files.contains(*href))
            .expect("a file synced before the base token")
            .clone();
        let mut deleted_files = Vec::new();
        let mut synced = AHashSet::new();
        let mut sync_token = base_token;
        for page_num in 0.. {
            assert!(page_num < 10, "incremental sync did not finish");
            let limit = 2 + page_num % 2;
            let response = client
                .sync_collection(
                    &paged_folder,
                    &sync_token,
                    Depth::One,
                    limit.into(),
                    ["D:getetag"],
                )
                .await;
            sync_token = response.sync_token().to_string();
            let page = SyncPage::parse(&response, &paged_folder);
            assert!(page.changed.len() + page.removed.len() <= limit, "{page:?}");
            synced.extend(page.changed);
            if !page.is_truncated {
                break;
            }
            if page_num == 0 {
                let delivered = new_files
                    .iter()
                    .find(|href| synced.contains(*href))
                    .expect("a new file on the first page")
                    .clone();
                for href in [&delivered, &older_file] {
                    client
                        .request("DELETE", href, "")
                        .await
                        .with_status(StatusCode::NO_CONTENT);
                }
                deleted_files.extend([delivered, older_file.clone()]);
            }
        }
        for href in new_files
            .iter()
            .filter(|href| !deleted_files.contains(*href))
        {
            assert!(synced.contains(href), "{href} never synced: {synced:?}");
        }
        let follow_up = SyncPage::parse(
            &client
                .sync_collection(&paged_folder, &sync_token, Depth::One, None, ["D:getetag"])
                .await,
            &paged_folder,
        );
        for href in &deleted_files {
            assert!(follow_up.removed.contains(href), "{href} {follow_up:?}");
        }

        // Test 13: A card cannot gain a second name in the address book that holds it
        if resource_type == DavResourceName::Card {
            let original = format!("{paged_folder}no-uid.vcf");
            let copy = format!("{paged_folder}no-uid-copy.vcf");
            client
                .request("PUT", &original, NO_UID_VCARD)
                .await
                .with_status(StatusCode::CREATED);
            client
                .request_with_headers("COPY", &original, [("destination", copy.as_str())], "")
                .await
                .with_status(StatusCode::PRECONDITION_FAILED);
            client
                .request("GET", &copy, "")
                .await
                .with_status(StatusCode::NOT_FOUND);
        }

        // Test 14: A sync token older than the retained change log is rejected
        let stale_token = client
            .sync_collection(&paged_folder, "", Depth::One, None, ["D:getetag"])
            .await
            .sync_token()
            .to_string();
        for num in 0..3 {
            client
                .request(
                    "PUT",
                    &format!("{paged_folder}purged-{num}"),
                    &resource_type.generate(),
                )
                .await
                .with_status(StatusCode::CREATED);
        }
        let sync_collection = match resource_type {
            DavResourceName::Cal => SyncCollection::Calendar,
            DavResourceName::Card => SyncCollection::AddressBook,
            _ => SyncCollection::FileNode,
        };
        assert!(
            test.server
                .truncate_change_log(
                    test.account("john@example.com").id().document_id(),
                    LogCollection::Sync(sync_collection),
                    1,
                )
                .await
                .expect("change log truncated")
                .is_some()
        );
        let body = format!(
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<D:sync-collection xmlns:D=\"DAV:\">",
                "<D:sync-token>{}</D:sync-token><D:sync-level>1</D:sync-level>",
                "<D:prop><D:getetag/></D:prop></D:sync-collection>"
            ),
            stale_token
        );
        let response = client
            .request("REPORT", &paged_folder, &body)
            .await
            .with_status(StatusCode::FORBIDDEN);
        assert!(
            response.expect_body().contains("valid-sync-token"),
            "{:?}",
            response.body
        );
        let fresh_token = client
            .sync_collection(&paged_folder, "", Depth::One, None, ["D:getetag"])
            .await
            .sync_token()
            .to_string();
        client
            .sync_collection(&paged_folder, &fresh_token, Depth::One, None, ["D:getetag"])
            .await
            .with_href_count(0);

        client
            .request("DELETE", &paged_folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    // Sharees are told when a shared collection is deleted
    let owner_client = test.account("jane@example.com").webdav_client();
    let sharee_principal = format!(
        "{}/john%40example.com/",
        DavResourceName::Principal.base_path()
    );
    let owner_base_path = format!("{}/jane%40example.com/", DavResourceName::Cal.base_path());
    let shared_folder = format!("{owner_base_path}shared-sync/");
    let kept_folder = format!("{owner_base_path}kept-sync/");
    for folder in [&shared_folder, &kept_folder] {
        owner_client
            .mkcol("MKCOL", folder, [], [])
            .await
            .with_status(StatusCode::CREATED);
        owner_client
            .acl(folder, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);
    }
    let sync_token = client
        .sync_collection(&owner_base_path, "", Depth::Infinity, None, ["D:getetag"])
        .await
        .sync_token()
        .to_string();
    owner_client
        .request("DELETE", &shared_folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    client
        .sync_collection(
            &owner_base_path,
            &sync_token,
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await
        .with_href_count(1)
        .with_value("D:multistatus.D:response.D:href", &shared_folder)
        .with_value(
            "D:multistatus.D:response.D:status",
            "HTTP/1.1 404 Not Found",
        );
    owner_client
        .request("DELETE", &kept_folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    // Changes a sharee cannot see neither fill nor extend their pages
    let team_folder = format!("{owner_base_path}team-sync/");
    let private_folder = format!("{owner_base_path}private-sync/");
    for folder in [&team_folder, &private_folder] {
        owner_client
            .mkcol("MKCOL", folder, [], [])
            .await
            .with_status(StatusCode::CREATED);
    }
    owner_client
        .acl(&team_folder, sharee_principal.as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);
    let sync_token = client
        .sync_collection(&owner_base_path, "", Depth::Infinity, None, ["D:getetag"])
        .await
        .sync_token()
        .to_string();
    for num in 0..4 {
        owner_client
            .request(
                "PUT",
                &format!("{private_folder}private-{num}.ics"),
                &DavResourceName::Cal.generate(),
            )
            .await
            .with_status(StatusCode::CREATED);
    }
    let team_event = format!("{team_folder}team.ics");
    owner_client
        .request("PUT", &team_event, &DavResourceName::Cal.generate())
        .await
        .with_status(StatusCode::CREATED);
    let response = client
        .sync_collection(
            &owner_base_path,
            &sync_token,
            Depth::Infinity,
            2.into(),
            ["D:getetag"],
        )
        .await;
    let page = SyncPage::parse(&response, &owner_base_path);
    assert!(!page.is_truncated, "{page:?}");
    assert!(page.removed.is_empty(), "{page:?}");
    assert!(page.changed.contains(&team_event), "{page:?}");
    assert!(
        page.changed
            .iter()
            .all(|href| *href == team_event || *href == team_folder),
        "{page:?}"
    );
    for folder in [&team_folder, &private_folder] {
        owner_client
            .request("DELETE", folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    // Sharees are told when a shared file node stops being visible to them
    let owner = test.account("jane@example.com");
    let sharee = test.account("john@example.com");
    let file_base_path = format!("{}/jane%40example.com/", DavResourceName::File.base_path());
    let shared_dir = format!("{file_base_path}shared-dir/");
    let kept_dir = format!("{file_base_path}kept-dir/");
    for folder in [&shared_dir, &kept_dir] {
        owner_client
            .mkcol("MKCOL", folder, [], [])
            .await
            .with_status(StatusCode::CREATED);
        owner_client
            .acl(folder, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);
    }
    let sync_token = client
        .sync_collection(&file_base_path, "", Depth::Infinity, None, ["D:getetag"])
        .await
        .sync_token()
        .to_string();
    let since_state = sharee
        .jmap_method_call(
            "FileNode/get",
            json!({ "accountId": owner.id_string(), "ids": [] }),
        )
        .await
        .state()
        .to_string();
    let shared_dir_id = Id::from(
        test.server
            .fetch_groupware_resources(
                owner.id().document_id(),
                owner.id().document_id(),
                SyncCollection::FileNode,
            )
            .await
            .expect("file resources")
            .by_path("shared-dir")
            .expect("shared directory")
            .document_id(),
    )
    .to_string();
    owner_client
        .acl(&shared_dir, sharee_principal.as_str(), [])
        .await
        .with_status(StatusCode::OK);
    client
        .sync_collection(
            &file_base_path,
            &sync_token,
            Depth::Infinity,
            None,
            ["D:getetag"],
        )
        .await
        .with_href_count(1)
        .with_value("D:multistatus.D:response.D:href", &shared_dir)
        .with_value(
            "D:multistatus.D:response.D:status",
            "HTTP/1.1 404 Not Found",
        );
    let changes = sharee
        .jmap_method_call(
            "FileNode/changes",
            json!({ "accountId": owner.id_string(), "sinceState": &since_state }),
        )
        .await;
    assert_eq!(
        changes.changes_by_type("destroyed").collect::<Vec<_>>(),
        [shared_dir_id.as_str()],
        "{changes:?}"
    );
    for folder in [&shared_dir, &kept_dir] {
        owner_client
            .request("DELETE", folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    client.delete_default_containers().await;
    owner_client.delete_default_containers().await;
    test.assert_is_empty().await;
}

#[derive(Debug, Default)]
struct SyncPage {
    changed: Vec<String>,
    removed: Vec<String>,
    is_truncated: bool,
}

impl SyncPage {
    fn parse(response: &DavResponse, request_uri: &str) -> Self {
        let mut entries: Vec<(&str, Option<&str>)> = Vec::new();
        for (key, value) in &response.xml {
            match key.as_str() {
                "D:multistatus.D:response.D:href" => entries.push((value, None)),
                "D:multistatus.D:response.D:status" => {
                    if let Some((_, status)) = entries.last_mut() {
                        *status = Some(value);
                    }
                }
                _ => {}
            }
        }
        let mut page = SyncPage::default();
        for (href, status) in entries {
            match status {
                None => page.changed.push(href.to_string()),
                Some("HTTP/1.1 404 Not Found") => page.removed.push(href.to_string()),
                Some("HTTP/1.1 507 Insufficient Storage") if href == request_uri => {
                    page.is_truncated = true
                }
                Some(status) => panic!("Unexpected status {status} for {href}"),
            }
        }
        page
    }
}

const NO_UID_VCARD: &str = "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:No UID\r\nEND:VCARD\r\n";
