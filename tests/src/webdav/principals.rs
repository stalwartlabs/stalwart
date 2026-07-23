/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::server::TestServer;
use crate::webdav::prop::ALL_DAV_PROPERTIES;
use dav_proto::schema::property::{DavProperty, PrincipalProperty, WebDavProperty};
use groupware::DavResourceName;
use hyper::StatusCode;

pub async fn test(test: &TestServer, assisted_discovery: bool) {
    println!("Running principals tests...");
    let client = test.account("jane@example.com").webdav_client();
    let principal_path = format!("D:href:{}/", DavResourceName::Principal.base_path());
    let jane_principal_path = format!(
        "D:href:{}/jane%40example.com/",
        DavResourceName::Principal.base_path()
    );

    let path_support_card = format!(
        "D:href:{}/support%40example.com/",
        DavResourceName::Card.base_path()
    );
    let path_support_cal = format!(
        "D:href:{}/support%40example.com/",
        DavResourceName::Cal.base_path()
    );

    // Test 1: PROPFIND on /dav/pal should return all principals
    let response = client
        .propfind(
            DavResourceName::Principal.collection_path(),
            ALL_DAV_PROPERTIES,
        )
        .await;
    for account_ in test.accounts.values().filter(|a| a.name().contains('@')) {
        let account_name = account_.name().replace('@', "%40");
        let email = account_.name();
        let description = account_.description();

        let props = response.properties(&format!(
            "{}/{}/",
            DavResourceName::Principal.base_path(),
            account_name
        ));
        let path_pal = format!(
            "D:href:{}/{}/",
            DavResourceName::Principal.base_path(),
            account_name
        );
        let path_card = format!(
            "D:href:{}/{}/",
            DavResourceName::Card.base_path(),
            account_name
        );
        let path_cal = format!(
            "D:href:{}/{}/",
            DavResourceName::Cal.base_path(),
            account_name
        );
        props
            .get(DavProperty::WebDav(WebDavProperty::DisplayName))
            .with_values([description])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal))
            .with_values([jane_principal_path.as_str()])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::Principal(PrincipalProperty::PrincipalURL))
            .with_values([path_pal.as_str()])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::WebDav(WebDavProperty::Owner))
            .with_values([path_pal.as_str()])
            .with_status(StatusCode::OK);
        if account_name == "jane%40example.com" && !assisted_discovery {
            props
                .get(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
                .with_values([path_cal.as_str(), path_support_cal.as_str()])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::Principal(
                    PrincipalProperty::AddressbookHomeSet,
                ))
                .with_values([path_card.as_str(), path_support_card.as_str()])
                .with_status(StatusCode::OK);
        } else {
            props
                .get(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
                .with_values([path_cal.as_str()])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::Principal(
                    PrincipalProperty::AddressbookHomeSet,
                ))
                .with_values([path_card.as_str()])
                .with_status(StatusCode::OK);
        }
        props
            .get(DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet))
            .with_values([principal_path.as_str()])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::WebDav(WebDavProperty::SupportedReportSet))
            .with_values([
                "D:supported-report.D:report.D:principal-property-search",
                "D:supported-report.D:report.D:principal-search-property-set",
                "D:supported-report.D:report.D:principal-match",
            ])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::WebDav(WebDavProperty::ResourceType))
            .with_values(["D:principal", "D:collection"])
            .with_status(StatusCode::OK);

        // Scheduling properties
        props
            .get(DavProperty::Principal(
                PrincipalProperty::CalendarUserAddressSet,
            ))
            .with_values([format!("D:href:mailto:{email}",).as_str()])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::Principal(PrincipalProperty::CalendarUserType))
            .with_values([if account_name == "support%40example.com" {
                "GROUP"
            } else {
                "INDIVIDUAL"
            }])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::Principal(PrincipalProperty::ScheduleInboxURL))
            .with_values([format!(
                "D:href:{}/{account_name}/inbox/",
                DavResourceName::Scheduling.base_path()
            )
            .as_str()])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::Principal(PrincipalProperty::ScheduleOutboxURL))
            .with_values([format!(
                "D:href:{}/{account_name}/outbox/",
                DavResourceName::Scheduling.base_path()
            )
            .as_str()])
            .with_status(StatusCode::OK);
    }

    // Test 2: PROPFIND on /dav/[resource] should return user and shared resources
    for resource_type in [
        DavResourceName::File,
        DavResourceName::Cal,
        DavResourceName::Card,
    ] {
        let supported_reports = match resource_type {
            DavResourceName::File => [
                "D:supported-report.D:report.D:sync-collection",
                "D:supported-report.D:report.D:acl-principal-prop-set",
                "D:supported-report.D:report.D:principal-match",
            ]
            .as_slice(),
            DavResourceName::Cal => [
                "D:supported-report.D:report.A:free-busy-query",
                "D:supported-report.D:report.A:calendar-query",
                "D:supported-report.D:report.D:expand-property",
                "D:supported-report.D:report.D:sync-collection",
                "D:supported-report.D:report.D:acl-principal-prop-set",
                "D:supported-report.D:report.D:principal-match",
                "D:supported-report.D:report.A:calendar-multiget",
            ]
            .as_slice(),
            DavResourceName::Card => [
                "D:supported-report.D:report.B:addressbook-query",
                "D:supported-report.D:report.D:acl-principal-prop-set",
                "D:supported-report.D:report.D:expand-property",
                "D:supported-report.D:report.B:addressbook-multiget",
                "D:supported-report.D:report.D:principal-match",
                "D:supported-report.D:report.D:sync-collection",
            ]
            .as_slice(),
            _ => unreachable!(),
        };
        let privilege_set = if resource_type == DavResourceName::Cal {
            [
                "D:privilege.D:read-current-user-privilege-set",
                "D:privilege.D:write-acl",
                "D:privilege.A:read-free-busy",
                "D:privilege.D:read-acl",
                "D:privilege.D:write-properties",
                "D:privilege.D:write",
                "D:privilege.D:write-content",
                "D:privilege.D:unlock",
                "D:privilege.D:all",
                "D:privilege.D:read",
                "D:privilege.D:bind",
                "D:privilege.D:unbind",
            ]
            .as_slice()
        } else {
            [
                "D:privilege.D:all",
                "D:privilege.D:read",
                "D:privilege.D:write",
                "D:privilege.D:write-properties",
                "D:privilege.D:write-content",
                "D:privilege.D:unlock",
                "D:privilege.D:read-acl",
                "D:privilege.D:read-current-user-privilege-set",
                "D:privilege.D:write-acl",
                "D:privilege.D:bind",
                "D:privilege.D:unbind",
            ]
            .as_slice()
        };

        let response = client
            .propfind(resource_type.collection_path(), ALL_DAV_PROPERTIES)
            .await;
        let props = response.properties(resource_type.collection_path());
        props
            .get(DavProperty::WebDav(WebDavProperty::SupportedReportSet))
            .with_values(supported_reports.iter().copied())
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::WebDav(WebDavProperty::ResourceType))
            .with_values(["D:collection"])
            .with_status(StatusCode::OK);
        props
            .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal))
            .with_values([jane_principal_path.as_str()])
            .with_status(StatusCode::OK);
        if assisted_discovery {
            props
                .get(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
                .with_values([format!(
                    "D:href:{}/jane%40example.com/",
                    DavResourceName::Cal.base_path()
                )
                .as_str()])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::Principal(
                    PrincipalProperty::AddressbookHomeSet,
                ))
                .with_values([format!(
                    "D:href:{}/jane%40example.com/",
                    DavResourceName::Card.base_path()
                )
                .as_str()])
                .with_status(StatusCode::OK);
        } else {
            props
                .get(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
                .with_values([
                    format!(
                        "D:href:{}/jane%40example.com/",
                        DavResourceName::Cal.base_path()
                    )
                    .as_str(),
                    format!(
                        "D:href:{}/support%40example.com/",
                        DavResourceName::Cal.base_path()
                    )
                    .as_str(),
                ])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::Principal(
                    PrincipalProperty::AddressbookHomeSet,
                ))
                .with_values([
                    format!(
                        "D:href:{}/jane%40example.com/",
                        DavResourceName::Card.base_path()
                    )
                    .as_str(),
                    format!(
                        "D:href:{}/support%40example.com/",
                        DavResourceName::Card.base_path()
                    )
                    .as_str(),
                ])
                .with_status(StatusCode::OK);
        }

        for account_ in test
            .accounts
            .values()
            .filter(|account| ["jane@example.com", "support@example.com"].contains(&account.name()))
        {
            let account_name = account_.name().replace('@', "%40");
            let description = account_.description();

            let path_card = format!(
                "D:href:{}/{}/",
                DavResourceName::Card.base_path(),
                account_name
            );
            let path_cal = format!(
                "D:href:{}/{}/",
                DavResourceName::Cal.base_path(),
                account_name
            );
            let path_pal = format!(
                "D:href:{}/{}/",
                DavResourceName::Principal.base_path(),
                account_name
            );
            let props =
                response.properties(&format!("{}/{account_name}/", resource_type.base_path()));

            props
                .get(DavProperty::WebDav(WebDavProperty::DisplayName))
                .with_values([description])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::WebDav(WebDavProperty::ResourceType))
                .with_values(["D:collection"])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrincipal))
                .with_values([jane_principal_path.as_str()])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::WebDav(WebDavProperty::CurrentUserPrivilegeSet))
                .with_values(privilege_set.iter().copied())
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::WebDav(WebDavProperty::SupportedReportSet))
                .with_values(supported_reports.iter().copied())
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::Principal(PrincipalProperty::PrincipalURL))
                .with_values([path_pal.as_str()])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::WebDav(WebDavProperty::PrincipalCollectionSet))
                .with_values([principal_path.as_str()])
                .with_status(StatusCode::OK);
            props
                .get(DavProperty::WebDav(WebDavProperty::Owner))
                .with_values([path_pal.as_str()])
                .with_status(StatusCode::OK);
            if account_name == "jane%40example.com" && !assisted_discovery {
                props
                    .get(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
                    .with_values([path_cal.as_str(), path_support_cal.as_str()])
                    .with_status(StatusCode::OK);
                props
                    .get(DavProperty::Principal(
                        PrincipalProperty::AddressbookHomeSet,
                    ))
                    .with_values([path_card.as_str(), path_support_card.as_str()])
                    .with_status(StatusCode::OK);
            } else {
                props
                    .get(DavProperty::Principal(PrincipalProperty::CalendarHomeSet))
                    .with_values([path_cal.as_str()])
                    .with_status(StatusCode::OK);
                props
                    .get(DavProperty::Principal(
                        PrincipalProperty::AddressbookHomeSet,
                    ))
                    .with_values([path_card.as_str()])
                    .with_status(StatusCode::OK);
            }
            props
                .get(DavProperty::WebDav(WebDavProperty::SyncToken))
                .with_status(StatusCode::OK)
                .is_not_empty();
            props
                .get(DavProperty::WebDav(WebDavProperty::QuotaAvailableBytes))
                .with_status(StatusCode::OK)
                .is_not_empty();
            props
                .get(DavProperty::WebDav(WebDavProperty::QuotaUsedBytes))
                .with_status(StatusCode::OK)
                .is_not_empty();
        }

        // Test 3: principal-match-query on resources
        let response = client
            .request(
                "REPORT",
                resource_type.collection_path(),
                PRINCIPAL_MATCH_QUERY,
            )
            .await
            .with_status(StatusCode::MULTI_STATUS)
            .into_propfind_response(None);
        response.with_hrefs([
            format!("{}/jane%40example.com/", resource_type.base_path()).as_str(),
            format!("{}/support%40example.com/", resource_type.base_path()).as_str(),
        ]);
    }

    // Test 4: principal-match-query on principals
    let response = client
        .request(
            "REPORT",
            DavResourceName::Principal.collection_path(),
            PRINCIPAL_MATCH_QUERY,
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .into_propfind_response(None);
    response.with_hrefs([
        format!(
            "{}/jane%40example.com/",
            DavResourceName::Principal.base_path()
        )
        .as_str(),
        format!(
            "{}/support%40example.com/",
            DavResourceName::Principal.base_path()
        )
        .as_str(),
    ]);

    // Test 5: principal-search-property-set REPORT
    let response = client
        .request(
            "REPORT",
            DavResourceName::Principal.collection_path(),
            PRINCIPAL_SEARCH_PROPERTY_SET_QUERY,
        )
        .await
        .with_status(StatusCode::OK);
    response
        .with_value(
            "D:principal-search-property-set.D:principal-search-property.D:prop.D:displayname",
            "",
        )
        .with_value(
            "D:principal-search-property-set.D:principal-search-property.D:description",
            "Account or Group name",
        );

    // Test 6: principal-property-search REPORT
    let response = client
        .request(
            "REPORT",
            DavResourceName::Principal.collection_path(),
            PRINCIPAL_PROPERTY_SEARCH_QUERY.replace("$NAME", "doe"),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .into_propfind_response(None);
    response.with_hrefs([
        format!(
            "{}/jane%40example.com/",
            DavResourceName::Principal.base_path()
        )
        .as_str(),
        format!(
            "{}/john%40example.com/",
            DavResourceName::Principal.base_path()
        )
        .as_str(),
    ]);
    response
        .properties(&format!(
            "{}/jane%40example.com/",
            DavResourceName::Principal.base_path()
        ))
        .get(DavProperty::WebDav(WebDavProperty::DisplayName))
        .with_values([test.account("jane@example.com").description()])
        .with_status(StatusCode::OK);
    client
        .request(
            "REPORT",
            DavResourceName::Principal.collection_path(),
            PRINCIPAL_PROPERTY_SEARCH_QUERY.replace("$NAME", "support"),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .into_propfind_response(None)
        .with_hrefs([format!(
            "{}/support%40example.com/",
            DavResourceName::Principal.base_path()
        )
        .as_str()]);

    client.delete_default_containers().await;
    client
        .delete_default_containers_by_account("support@example.com")
        .await;
    test.assert_is_empty().await;
}

const PRINCIPAL_MATCH_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
<D:principal-match xmlns:D="DAV:">
<D:principal-property>
<D:owner/>
<D:displayname/>
</D:principal-property>
</D:principal-match>"#;

const PRINCIPAL_SEARCH_PROPERTY_SET_QUERY: &str =
    r#"<?xml version="1.0" encoding="utf-8" ?><D:principal-search-property-set xmlns:D="DAV:"/>"#;

const PRINCIPAL_PROPERTY_SEARCH_QUERY: &str = r#"<?xml version="1.0" encoding="utf-8" ?>
   <D:principal-property-search xmlns:D="DAV:">
     <D:property-search>
       <D:prop>
         <D:displayname/>
       </D:prop>
       <D:match>$NAME</D:match>
     </D:property-search>
     <D:prop xmlns:B="http://www.example.com/ns/">
       <D:displayname/>
     </D:prop>
</D:principal-property-search>"#;
