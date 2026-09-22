/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{server::TestServer, webdav::GenerateTestDavResource};
use dav_proto::schema::property::{DavProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;
use std::fmt::Write;

const MAX_SHARES: usize = 10;

pub async fn test(test: &TestServer) {
    let owner_client = test.account("bill@example.com").webdav_client();
    let sharee_client = test.account("john@example.com").webdav_client();

    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        println!("Running ACL tests ({})...", resource_type.base_path());
        let is_file = resource_type == DavResourceName::File;
        let sharee_principal = format!(
            "{}/john%40example.com/",
            DavResourceName::Principal.base_path()
        );
        let sharee_base_path = format!("{}/john%40example.com/", resource_type.base_path());
        let owner_principal = format!(
            "{}/bill%40example.com/",
            DavResourceName::Principal.base_path()
        );
        let owner_base_path = format!("{}/bill%40example.com/", resource_type.base_path());

        // Create a resource for the owner
        let owner_folder = format!("{owner_base_path}test-shared/");
        let owner_folder_private = format!("{owner_base_path}test-private/");
        let owner_file = format!("{owner_folder}test-file");
        let owner_file_content = resource_type.generate();
        let owner_file_private = format!("{owner_folder_private}test-file-private");
        let owner_file_content_private = resource_type.generate();
        let sharee_created_file = format!("{owner_folder}test-file-sharee");
        for (folder, file, content) in [
            (&owner_folder, &owner_file, &owner_file_content),
            (
                &owner_folder_private,
                &owner_file_private,
                &owner_file_content_private,
            ),
        ] {
            owner_client
                .request("MKCOL", folder, "")
                .await
                .with_status(StatusCode::CREATED);
            owner_client
                .request("PUT", file, content)
                .await
                .with_status(StatusCode::CREATED);
        }

        // Create a resource for the sharee
        let sharee_folder = format!("{sharee_base_path}test-folder/");
        let sharee_file = format!("{sharee_folder}test-file");
        let sharee_file_content = resource_type.generate();
        sharee_client
            .request("MKCOL", &sharee_folder, "")
            .await
            .with_status(StatusCode::CREATED);
        sharee_client
            .request("PUT", &sharee_file, &sharee_file_content)
            .await
            .with_status(StatusCode::CREATED);

        // Test 1: Sharee should only see their own resources
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str()]);

        // Test 2: Share a resource and make sure the root folder is visible
        owner_client
            .acl(&owner_folder, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);
        if is_file {
            owner_client
                .acl(&owner_file, sharee_principal.as_str(), ["read"])
                .await
                .with_status(StatusCode::OK);
        }
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str(), owner_base_path.as_str()]);

        // Test 3: Verify that only the shared resource is visible
        sharee_client
            .propfind_with_headers(
                &owner_base_path,
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([owner_folder.as_str()]);

        // Test 4: Verify that the sharee can access the shared resource
        sharee_client
            .propfind(
                &owner_folder,
                [DavProperty::WebDav(WebDavProperty::GetETag)],
            )
            .await
            .with_hrefs([owner_folder.as_str(), owner_file.as_str()]);
        sharee_client
            .request("GET", &owner_file, "")
            .await
            .with_status(StatusCode::OK)
            .with_body(&owner_file_content);
        match resource_type {
            DavResourceName::Cal => {
                sharee_client
                    .multiget_calendar(&owner_folder, &[&owner_file])
                    .await
                    .properties(&owner_file)
                    .with_status(StatusCode::OK)
                    .is_defined(DavProperty::WebDav(WebDavProperty::GetETag));
                sharee_client
                    .request("REPORT", &owner_folder, CALENDAR_QUERY_ANY_VEVENT)
                    .await
                    .with_status(StatusCode::MULTI_STATUS)
                    .with_hrefs([owner_file.as_str()]);
            }
            DavResourceName::Card => {
                sharee_client
                    .multiget_addressbook(&owner_folder, &[&owner_file])
                    .await
                    .properties(&owner_file)
                    .with_status(StatusCode::OK)
                    .is_defined(DavProperty::WebDav(WebDavProperty::GetETag));
                sharee_client
                    .request("REPORT", &owner_folder, ADDRESSBOOK_QUERY_ANY_FN)
                    .await
                    .with_status(StatusCode::MULTI_STATUS)
                    .with_hrefs([owner_file.as_str()]);
            }
            _ => {}
        }

        // Test 5: Read ACL as owner
        let response = owner_client
            .propfind(&owner_folder, [DavProperty::WebDav(WebDavProperty::Acl)])
            .await;
        response
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::Acl))
            .with_values([
                format!("D:ace.D:principal.D:href:{sharee_principal}").as_str(),
                "D:ace.D:grant.D:privilege.D:read",
                "D:ace.D:grant.D:privilege.D:read-current-user-privilege-set",
            ]);

        // Test 6: acl-principal-prop-set REPORT
        let response = owner_client
            .request("REPORT", &owner_folder, ACL_PRINCIPAL_QUERY)
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None);
        response
            .properties(&sharee_principal)
            .get(DavProperty::WebDav(WebDavProperty::DisplayName))
            .with_values(["John Doe"]);

        // Test 7: Verify current-user-privilege-set and owner
        let response = sharee_client
            .propfind(
                &owner_folder,
                [
                    DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet),
                    DavProperty::WebDav(WebDavProperty::Owner),
                ],
            )
            .await;
        for href in [owner_folder.as_str(), owner_file.as_str()] {
            let props = response.properties(href);
            props
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                .with_values([
                    "D:privilege.D:read",
                    "D:privilege.D:read-current-user-privilege-set",
                ]);
            props
                .get(DavProperty::WebDav(WebDavProperty::Owner))
                .with_values([format!("D:href:{owner_principal}").as_str()]);
        }

        // Test 7b: ACL changes follow the sharing rules
        owner_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-acl"],
            )
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-acl", "write-content"],
            )
            .await
            .with_status(StatusCode::FORBIDDEN)
            .with_failed_precondition("D:no-ace-conflict", "");
        sharee_client
            .acl(&owner_folder, owner_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::FORBIDDEN)
            .with_failed_precondition("D:allowed-principal", "");
        sharee_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-acl"],
            )
            .await
            .with_status(StatusCode::OK);
        let aces = (1..=MAX_SHARES + 1).fold(String::new(), |mut aces, account_id| {
            let _ = write!(
                aces,
                concat!(
                    "<D:ace><D:principal><D:href>{}/_{}/</D:href></D:principal>",
                    "<D:grant><D:privilege><D:read/></D:privilege></D:grant></D:ace>"
                ),
                DavResourceName::Principal.base_path(),
                account_id
            );
            aces
        });
        owner_client
            .request(
                "ACL",
                &owner_folder,
                format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\" ?><D:acl xmlns:D=\"DAV:\">{aces}</D:acl>"
                ),
            )
            .await
            .with_status(StatusCode::FORBIDDEN)
            .with_failed_precondition("D:limited-number-of-aces", "");
        owner_client
            .acl(&owner_folder, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);

        // Test 8: Write operations should fail
        for (path, dest, dest_copy) in [
            (
                &owner_folder,
                &sharee_folder,
                Some(format!("{sharee_base_path}copied/")),
            ),
            (&owner_file, &sharee_file, None),
        ] {
            sharee_client
                .proppatch(
                    path,
                    [(DavProperty::WebDav(WebDavProperty::DisplayName), "test")],
                    [],
                    [],
                )
                .await
                .with_status(StatusCode::FORBIDDEN);
            sharee_client
                .request("DELETE", path, "")
                .await
                .with_status(StatusCode::FORBIDDEN);
            sharee_client
                .request_with_headers("MOVE", path, [("destination", dest.as_str())], "")
                .await
                .with_status(StatusCode::FORBIDDEN);
            if let Some(dest_copy) = dest_copy {
                sharee_client
                    .request_with_headers("COPY", path, [("destination", dest_copy.as_str())], "")
                    .await
                    .with_status(StatusCode::CREATED);
            }
        }
        sharee_client
            .request("PUT", &owner_file, resource_type.generate())
            .await
            .with_status(StatusCode::FORBIDDEN);
        sharee_client
            .request("PUT", &sharee_created_file, resource_type.generate())
            .await
            .with_status(StatusCode::FORBIDDEN);

        // Test 9: Grant write access to the sharee
        owner_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-content", "write-properties"],
            )
            .await
            .with_status(StatusCode::OK);
        if is_file {
            owner_client
                .acl(
                    &owner_file,
                    sharee_principal.as_str(),
                    ["read", "write-content", "write-properties"],
                )
                .await
                .with_status(StatusCode::OK);
        }
        let response = owner_client
            .propfind(&owner_folder, [DavProperty::WebDav(WebDavProperty::Acl)])
            .await;
        response
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::Acl))
            .with_values([
                format!("D:ace.D:principal.D:href:{sharee_principal}").as_str(),
                "D:ace.D:grant.D:privilege.D:read",
                "D:ace.D:grant.D:privilege.D:read-current-user-privilege-set",
                "D:ace.D:grant.D:privilege.D:write-content",
                "D:ace.D:grant.D:privilege.D:write-properties",
            ]);
        let response = sharee_client
            .propfind(
                &owner_folder,
                [DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet)],
            )
            .await;
        for href in [owner_folder.as_str(), owner_file.as_str()] {
            response
                .properties(href)
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                .with_values([
                    "D:privilege.D:read",
                    "D:privilege.D:read-current-user-privilege-set",
                    "D:privilege.D:write-content",
                    "D:privilege.D:write-properties",
                ]);
        }

        // Test 10: Delete operations should fail
        for (path, dest) in [(&owner_folder, &sharee_folder), (&owner_file, &sharee_file)] {
            sharee_client
                .proppatch(
                    path,
                    [(DavProperty::WebDav(WebDavProperty::DisplayName), "test")],
                    [],
                    [],
                )
                .await
                .with_status(StatusCode::MULTI_STATUS);
            sharee_client
                .request("DELETE", path, "")
                .await
                .with_status(StatusCode::FORBIDDEN);
            sharee_client
                .request_with_headers("MOVE", path, [("destination", dest.as_str())], "")
                .await
                .with_status(StatusCode::FORBIDDEN);
        }
        sharee_client
            .request("PUT", &owner_file, &owner_file_content)
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("PUT", &sharee_created_file, resource_type.generate())
            .await
            .with_status(StatusCode::FORBIDDEN);
        owner_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-content", "write-properties", "bind"],
            )
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .request("PUT", &sharee_created_file, resource_type.generate())
            .await
            .with_status(StatusCode::CREATED);

        // Test 11: Unbind without delete is not reported as write
        owner_client
            .acl(
                &owner_folder,
                sharee_principal.as_str(),
                ["read", "write-content", "write-properties", "unbind"],
            )
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .propfind(
                &owner_folder,
                [DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet)],
            )
            .await
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
            .with_values([
                "D:privilege.D:read",
                "D:privilege.D:read-current-user-privilege-set",
                "D:privilege.D:write-content",
                "D:privilege.D:write-properties",
                "D:privilege.D:unbind",
            ]);
        owner_client
            .propfind(&owner_folder, [DavProperty::WebDav(WebDavProperty::Acl)])
            .await
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::Acl))
            .with_values([
                format!("D:ace.D:principal.D:href:{sharee_principal}").as_str(),
                "D:ace.D:grant.D:privilege.D:read",
                "D:ace.D:grant.D:privilege.D:read-current-user-privilege-set",
                "D:ace.D:grant.D:privilege.D:write-content",
                "D:ace.D:grant.D:privilege.D:write-properties",
                "D:ace.D:grant.D:privilege.D:unbind",
            ]);
        sharee_client
            .request_with_headers(
                "MOVE",
                &owner_folder,
                [(
                    "destination",
                    format!("{sharee_base_path}moved-folder/").as_str(),
                )],
                "",
            )
            .await
            .with_status(StatusCode::FORBIDDEN);

        // Test 12: Grant delete access to the sharee and verify
        owner_client
            .acl(&owner_folder, sharee_principal.as_str(), ["read", "write"])
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .propfind(
                &owner_folder,
                [DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet)],
            )
            .await
            .properties(&owner_folder)
            .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
            .with_values([
                "D:privilege.D:read",
                "D:privilege.D:read-current-user-privilege-set",
                "D:privilege.D:write-content",
                "D:privilege.D:write-properties",
                "D:privilege.D:bind",
                "D:privilege.D:unbind",
                "D:privilege.D:write",
            ]);
        if is_file {
            owner_client
                .acl(&owner_file, sharee_principal.as_str(), ["read", "write"])
                .await
                .with_status(StatusCode::OK);
            owner_client
                .acl(
                    &sharee_created_file,
                    sharee_principal.as_str(),
                    ["read", "write"],
                )
                .await
                .with_status(StatusCode::OK);
        }
        sharee_client
            .request_with_headers(
                "MOVE",
                &owner_file,
                [("destination", sharee_file.as_str())],
                "",
            )
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &sharee_created_file, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &owner_folder, "")
            .await
            .with_status(StatusCode::FORBIDDEN);
        owner_client
            .request("DELETE", &owner_folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);

        // Test 12b: Scheduling privileges survive an ACL round trip
        if resource_type == DavResourceName::Cal {
            owner_client
                .request(
                    "ACL",
                    &owner_folder_private,
                    SCHEDULING_ACL.replace("$HREF", sharee_principal.as_str()),
                )
                .await
                .with_status(StatusCode::OK);
            owner_client
                .propfind(
                    &owner_folder_private,
                    [DavProperty::WebDav(WebDavProperty::Acl)],
                )
                .await
                .properties(&owner_folder_private)
                .get(DavProperty::WebDav(WebDavProperty::Acl))
                .with_values([
                    format!("D:ace.D:principal.D:href:{sharee_principal}").as_str(),
                    "D:ace.D:grant.D:privilege.D:read",
                    "D:ace.D:grant.D:privilege.D:read-current-user-privilege-set",
                    "D:ace.D:grant.D:privilege.A:schedule-deliver-invite",
                ]);
            owner_client
                .acl(&owner_folder_private, sharee_principal.as_str(), [])
                .await
                .with_status(StatusCode::OK);
        }

        // Test 13: Share and unshare a resource
        owner_client
            .acl(&owner_folder_private, sharee_principal.as_str(), ["read"])
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str(), owner_base_path.as_str()]);
        sharee_client
            .propfind_with_headers(
                &owner_base_path,
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([owner_folder_private.as_str()]);
        owner_client
            .acl(&owner_folder_private, sharee_principal.as_str(), [])
            .await
            .with_status(StatusCode::OK);
        sharee_client
            .propfind_with_headers(
                resource_type.collection_path(),
                [DavProperty::WebDav(WebDavProperty::GetETag)],
                [("prefer", "depth-noroot")],
            )
            .await
            .with_hrefs([sharee_base_path.as_str()]);

        // Delete resources
        owner_client
            .request("DELETE", &owner_folder_private, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &sharee_folder, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
        sharee_client
            .request("DELETE", &format!("{sharee_base_path}copied/"), "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }

    let member_client = test.account("jane@example.com").webdav_client();
    let principal_path = DavResourceName::Principal.base_path();
    let sharee_principal = format!("{principal_path}/john%40example.com/");
    let owner_calendars = format!("{}/bill%40example.com/", DavResourceName::Cal.base_path());
    let sharee_calendars = format!("{}/john%40example.com/", DavResourceName::Cal.base_path());
    let group_folder = format!("{owner_calendars}group-shared/");
    let group_event = format!("{group_folder}event.ics");
    let group_event_content = DavResourceName::Cal.generate();
    owner_client
        .request("MKCOL", &group_folder, "")
        .await
        .with_status(StatusCode::CREATED);
    owner_client
        .request("PUT", &group_event, &group_event_content)
        .await
        .with_status(StatusCode::CREATED);
    owner_client
        .request(
            "ACL",
            &group_folder,
            GROUP_AND_MEMBER_ACL
                .replace(
                    "$GROUP",
                    &format!("{principal_path}/support%40example.com/"),
                )
                .replace("$MEMBER", &format!("{principal_path}/jane%40example.com/")),
        )
        .await
        .with_status(StatusCode::OK);
    member_client
        .request("PUT", &group_event, &group_event_content)
        .await
        .with_status(StatusCode::NO_CONTENT);
    owner_client
        .request("DELETE", &group_folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);

    let ephemeral_folder = format!("{owner_calendars}ephemeral/");
    owner_client
        .request("MKCOL", &ephemeral_folder, "")
        .await
        .with_status(StatusCode::CREATED);
    owner_client
        .acl(&ephemeral_folder, sharee_principal.as_str(), ["read"])
        .await
        .with_status(StatusCode::OK);
    sharee_client
        .propfind_with_headers(
            DavResourceName::Cal.collection_path(),
            [DavProperty::WebDav(WebDavProperty::GetETag)],
            [("prefer", "depth-noroot")],
        )
        .await
        .with_hrefs([sharee_calendars.as_str(), owner_calendars.as_str()]);
    owner_client
        .request("DELETE", &ephemeral_folder, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    sharee_client
        .propfind_with_headers(
            DavResourceName::Cal.collection_path(),
            [DavProperty::WebDav(WebDavProperty::GetETag)],
            [("prefer", "depth-noroot")],
        )
        .await
        .with_hrefs([sharee_calendars.as_str()]);

    sharee_client.delete_default_containers().await;
    owner_client.delete_default_containers().await;
    test.account("bill@example.com")
        .destroy_all_event_notifications()
        .await;
    test.account("john@example.com")
        .destroy_all_event_notifications()
        .await;
    test.assert_is_empty().await;
}

const SCHEDULING_ACL: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:ace>
       <D:principal>
         <D:href>$HREF</D:href>
       </D:principal>
       <D:grant>
         <D:privilege><D:read/></D:privilege>
         <D:privilege><C:schedule-deliver-invite/></D:privilege>
       </D:grant>
     </D:ace>
   </D:acl>"#;

const GROUP_AND_MEMBER_ACL: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl xmlns:D="DAV:">
     <D:ace>
       <D:principal>
         <D:href>$GROUP</D:href>
       </D:principal>
       <D:grant>
         <D:privilege><D:read/></D:privilege>
       </D:grant>
     </D:ace>
     <D:ace>
       <D:principal>
         <D:href>$MEMBER</D:href>
       </D:principal>
       <D:grant>
         <D:privilege><D:read/></D:privilege>
         <D:privilege><D:write-content/></D:privilege>
       </D:grant>
     </D:ace>
   </D:acl>"#;

const ACL_PRINCIPAL_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:acl-principal-prop-set xmlns:D="DAV:">
     <D:prop>
       <D:displayname/>
     </D:prop>
   </D:acl-principal-prop-set>"#;

const CALENDAR_QUERY_ANY_VEVENT: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:comp-filter name="VCALENDAR">
         <C:comp-filter name="VEVENT"/>
       </C:comp-filter>
     </C:filter>
   </C:calendar-query>"#;

const ADDRESSBOOK_QUERY_ANY_FN: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
     <D:prop><D:getetag/></D:prop>
     <C:filter>
       <C:prop-filter name="FN"/>
     </C:filter>
   </C:addressbook-query>"#;
