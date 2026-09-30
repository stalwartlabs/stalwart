/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{DavKind, DavResource, home};
use crate::utils::{
    dav_xml::{DAV_NS, XmlElement},
    server::TestServer,
    webdav::DummyWebDavClient,
};
use hyper::StatusCode;

const NS_A: &str = "urn:example:a";
const NS_B: &str = "urn:example:b";
const NS_NESTED: &str = "urn:example:nested";
const NS_MKCOL: &str = "urn:example:mkcol";
const CS_CANONICAL: &str = "http://calendarserver.org/ns/";
const CS_LEGACY: &str = "http://calendarserver.org/ns";

const NESTED_VALUE: &str = concat!(
    "<N:tree xmlns:N=\"urn:example:nested\" xmlns:Q=\"urn:example:attr\">",
    "<N:branch Q:weight=\"3\" plain=\"yes\">",
    "<leaf xmlns=\"\">  two  spaces  </leaf>",
    "<N:twig><N:bud>x &amp; y <![CDATA[<raw> & ]]>z</N:bud></N:twig>",
    "</N:branch>   </N:tree>"
);

const NESTED_EXPECTED: &str = concat!(
    "<N:tree xmlns:N=\"urn:example:nested\" xmlns:Q=\"urn:example:attr\" xml:lang=\"en-US\">",
    "<N:branch Q:weight=\"3\" plain=\"yes\">",
    "<leaf xmlns=\"\">  two  spaces  </leaf>",
    "<N:twig><N:bud>x &amp; y &lt;raw&gt; &amp; z</N:bud></N:twig>",
    "</N:branch>   </N:tree>"
);

pub async fn test(test: &TestServer) {
    println!("Running WebDAV dead property tests...");
    let client = test.account("john@example.com").webdav_client();

    for kind in DavKind::ALL {
        let resource =
            DavResource::create(&client, kind, &format!("meta-dead-{kind:?}").to_lowercase()).await;
        two_namespaces(&client, &resource).await;
        nested_value(&client, &resource).await;
        propname(&client, &resource).await;
        if kind == DavKind::Calendar {
            calendar_server_source(&client, &resource).await;
        }
        deleted_with_resource(&client, &resource).await;
        resource.delete(&client).await;
    }

    initial_properties(&client).await;

    super::cleanup(test, &[&client]).await;
}

async fn two_namespaces(client: &DummyWebDavClient, resource: &DavResource) {
    let path = resource.path.as_str();
    let response = client
        .proppatch_xml(
            path,
            concat!(
                "<D:set><D:prop>",
                "<A:color xmlns:A=\"urn:example:a\">red</A:color>",
                "<B:color xmlns:B=\"urn:example:b\">blue</B:color>",
                "</D:prop></D:set>"
            ),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    for namespace in [NS_A, NS_B] {
        response
            .expect_property(path, namespace, "color")
            .with_status(StatusCode::OK);
    }

    for (namespace, prefix, value) in [(NS_A, "A", "red"), (NS_B, "B", "blue")] {
        let tree = client
            .propfind_named(
                path,
                "0",
                &format!("<{prefix}:color xmlns:{prefix}=\"{namespace}\"/>"),
            )
            .await;
        let prop = tree.expect_property(path, namespace, "color");
        prop.with_status(StatusCode::OK);
        assert_eq!(
            prop.element.text(),
            value,
            "{:?} {namespace}",
            resource.kind
        );
        let other = if namespace == NS_A { NS_B } else { NS_A };
        assert!(
            tree.property(path, other, "color").is_none(),
            "{:?}: a named PROPFIND for {{{namespace}}}color returned {{{other}}}color: {tree}",
            resource.kind
        );
    }

    let response = client
        .proppatch_xml(
            path,
            "<D:remove><D:prop><A:color xmlns:A=\"urn:example:a\"/></D:prop></D:remove>",
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree();
    assert!(
        response
            .expect_property(path, NS_A, "color")
            .status
            .is_success(),
        "{:?}: removal failed: {response}",
        resource.kind
    );

    let tree = client
        .propfind_named(
            path,
            "0",
            concat!(
                "<A:color xmlns:A=\"urn:example:a\"/>",
                "<B:color xmlns:B=\"urn:example:b\"/>"
            ),
        )
        .await;
    tree.expect_property(path, NS_A, "color")
        .with_status(StatusCode::NOT_FOUND);
    let remaining = tree.expect_property(path, NS_B, "color");
    remaining.with_status(StatusCode::OK);
    assert_eq!(remaining.element.text(), "blue");

    let tree = client.propfind_allprop(path, "0").await;
    tree.assert_property_absent(path, NS_A, "color");
    assert_eq!(
        tree.expect_property(path, NS_B, "color").element.text(),
        "blue"
    );
}

async fn nested_value(client: &DummyWebDavClient, resource: &DavResource) {
    let path = resource.path.as_str();
    client
        .proppatch_xml(
            path,
            &format!("<D:set><D:prop xml:lang=\"en-US\">{NESTED_VALUE}</D:prop></D:set>"),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS)
        .xml_tree()
        .expect_property(path, NS_NESTED, "tree")
        .with_status(StatusCode::OK);

    let expected = XmlElement::parse(NESTED_EXPECTED);
    let allprop = client.propfind_allprop(path, "0").await;
    let named = client
        .propfind_named(path, "0", "<N:tree xmlns:N=\"urn:example:nested\"/>")
        .await;
    for (label, tree) in [("allprop", &allprop), ("named", &named)] {
        let prop = tree.expect_property(path, NS_NESTED, "tree");
        prop.with_status(StatusCode::OK);
        prop.element
            .assert_equivalent(&expected, &format!("{:?} {label}", resource.kind));
    }

    let depth_one = client
        .propfind_named(
            &resource.collection,
            "1",
            "<N:tree xmlns:N=\"urn:example:nested\"/>",
        )
        .await;
    depth_one
        .expect_property(path, NS_NESTED, "tree")
        .element
        .assert_equivalent(&expected, &format!("{:?} depth 1", resource.kind));
}

async fn propname(client: &DummyWebDavClient, resource: &DavResource) {
    let path = resource.path.as_str();
    let tree = client.propfind_propname(path, "0").await;
    for (namespace, name) in [(NS_B, "color"), (NS_NESTED, "tree"), (DAV_NS, "getetag")] {
        let prop = tree.expect_property(path, namespace, name);
        assert!(
            prop.element.is_empty(),
            "{:?}: propname must return empty elements: {}",
            resource.kind,
            prop.element
        );
    }
    tree.assert_property_absent(path, NS_A, "color");
}

async fn calendar_server_source(client: &DummyWebDavClient, resource: &DavResource) {
    let path = resource.path.as_str();
    client
        .proppatch_xml(
            path,
            concat!(
                "<D:set><D:prop>",
                "<CS:source xmlns:CS=\"http://calendarserver.org/ns/\">",
                "<D:href>https://example.com/feeds/holidays.ics</D:href></CS:source>",
                "<CL:source xmlns:CL=\"http://calendarserver.org/ns\">",
                "<D:href>https://example.com/feeds/legacy.ics</D:href></CL:source>",
                "</D:prop></D:set>"
            ),
        )
        .await
        .with_status(StatusCode::MULTI_STATUS);

    for (namespace, prefix, expected) in [
        (CS_CANONICAL, "CS", "https://example.com/feeds/holidays.ics"),
        (CS_LEGACY, "CL", "https://example.com/feeds/legacy.ics"),
    ] {
        let tree = client
            .propfind_named(
                path,
                "0",
                &format!("<{prefix}:source xmlns:{prefix}=\"{namespace}\"/>"),
            )
            .await;
        let prop = tree.expect_property(path, namespace, "source");
        prop.with_status(StatusCode::OK);
        let href = prop
            .element
            .child(DAV_NS, "href")
            .unwrap_or_else(|| panic!("source without href: {}", prop.element));
        assert_eq!(href.text(), expected);
    }
}

async fn deleted_with_resource(client: &DummyWebDavClient, resource: &DavResource) {
    if resource.kind.is_collection() {
        return;
    }
    client
        .request("DELETE", &resource.path, "")
        .await
        .with_status(StatusCode::NO_CONTENT);
    super::put_item(client, resource.kind, &resource.path, "meta-dead-recreated").await;
    let tree = client.propfind_allprop(&resource.path, "0").await;
    for (namespace, name) in [(NS_B, "color"), (NS_NESTED, "tree")] {
        tree.assert_property_absent(&resource.path, namespace, name);
    }
}

async fn initial_properties(client: &DummyWebDavClient) {
    for (kind, method, body) in [
        (
            DavKind::Folder,
            "MKCOL",
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<D:mkcol xmlns:D=\"DAV:\"><D:set><D:prop>",
                "<D:resourcetype><D:collection/></D:resourcetype>",
                "<M:initial xmlns:M=\"urn:example:mkcol\">first</M:initial>",
                "<M:initial xmlns:M=\"urn:example:mkcol\">second</M:initial>",
                "</D:prop></D:set></D:mkcol>"
            ),
        ),
        (
            DavKind::AddressBook,
            "MKCOL",
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<D:mkcol xmlns:D=\"DAV:\" xmlns:B=\"urn:ietf:params:xml:ns:carddav\">",
                "<D:set><D:prop>",
                "<D:resourcetype><D:collection/><B:addressbook/></D:resourcetype>",
                "<M:initial xmlns:M=\"urn:example:mkcol\">first</M:initial>",
                "<M:initial xmlns:M=\"urn:example:mkcol\">second</M:initial>",
                "</D:prop></D:set></D:mkcol>"
            ),
        ),
        (
            DavKind::Calendar,
            "MKCALENDAR",
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<C:mkcalendar xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">",
                "<D:set><D:prop>",
                "<M:initial xmlns:M=\"urn:example:mkcol\">first</M:initial>",
                "<M:initial xmlns:M=\"urn:example:mkcol\">second</M:initial>",
                "</D:prop></D:set></C:mkcalendar>"
            ),
        ),
    ] {
        let path = format!("{}/meta-initial/", home(kind, client.name));
        client
            .request(method, &path, body)
            .await
            .with_status(StatusCode::CREATED);
        let tree = client.propfind_allprop(&path, "0").await;
        let values = tree
            .props(&path)
            .filter(|prop| prop.element.is(NS_MKCOL, "initial"))
            .map(|prop| prop.element.text())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            vec!["second".to_string()],
            "{kind:?}: duplicate initial properties must resolve last-wins: {tree}"
        );
        client
            .request("DELETE", &path, "")
            .await
            .with_status(StatusCode::NO_CONTENT);
    }
}
