/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::utils::{
    imap::{AssertResult, ImapConnection, Type},
    server::TestServer,
};
use imap_proto::ResponseType;
use registry::schema::{prelude::Property, structs::Metadata};
use std::fmt::Write;

const SERVER_COMMENT: &str = "Stalwart metadata test server";
const SERVER_ADMIN: &str = "mailto:postmaster@example.com";
const BOX: &str = "Meta Box";
const EMPTY_BOX: &str = "Meta Empty";
const SHARED_BOX: &str = "Shared Folders/jdoe@example.com/Meta Box";

pub async fn test(test: &TestServer) {
    println!("Running IMAP METADATA tests...");
    configure(test, Some(SERVER_COMMENT), Some(SERVER_ADMIN)).await;

    let mut john = test.account("jdoe@example.com").imap_client().await;
    capabilities(&mut john).await;
    enable(&mut john).await;
    server_annotations(&mut john).await;

    for mailbox in [BOX, EMPTY_BOX] {
        john.send_ok(&format!("CREATE \"{mailbox}\"")).await;
    }
    mailbox_annotations(&mut john).await;
    depth_and_maxsize(&mut john).await;
    binary_values(&mut john).await;
    set_limits(test, &mut john).await;
    invalid_names(&mut john).await;
    list_metadata(&mut john).await;
    rights(test, &mut john).await;
    special_use(&mut john).await;
    rename_and_delete(&mut john).await;

    for mailbox in [EMPTY_BOX] {
        john.send_ok(&format!("DELETE \"{mailbox}\"")).await;
    }
    configure(test, None, None).await;
}

async fn configure(test: &TestServer, comment: Option<&str>, admin: Option<&str>) {
    let registry = test.account("admin");
    registry
        .registry_update_setting(
            Metadata {
                imap_server_comment: comment.map(str::to_string),
                imap_server_admin: admin.map(str::to_string),
                ..Default::default()
            },
            &[Property::ImapServerComment, Property::ImapServerAdmin],
        )
        .await;
    registry.reload_settings().await;
}

fn tokens(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .flat_map(|line| line.split_ascii_whitespace())
        .collect()
}

async fn capabilities(imap: &mut ImapConnection) {
    imap.send("CAPABILITY").await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let tokens = tokens(&lines);
    for capability in ["METADATA", "LIST-METADATA"] {
        assert!(
            tokens.contains(&capability),
            "{capability} not announced: {lines:?}"
        );
    }
}

async fn enable(imap: &mut ImapConnection) {
    for capability in ["METADATA", "METADATA-SERVER"] {
        imap.send(&format!("ENABLE {capability}")).await;
        let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
        for line in lines.iter().filter(|line| line.starts_with("* ENABLED")) {
            assert!(
                !line.contains("METADATA"),
                "{capability} must be accepted and ignored: {lines:?}"
            );
        }
    }
}

async fn server_annotations(imap: &mut ImapConnection) {
    imap.send("GETMETADATA \"\" /shared/comment").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("/shared/comment \"{SERVER_COMMENT}\""));

    imap.send("GETMETADATA \"\" (/shared/comment /shared/admin)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("\"{SERVER_COMMENT}\""))
        .assert_contains(&format!("/shared/admin \"{SERVER_ADMIN}\""));

    for entry in [
        "/shared/admin",
        "/shared/comment",
        "/shared/vendor/test/key",
    ] {
        imap.send(&format!("SETMETADATA \"\" ({entry} \"changed\")"))
            .await;
        imap.assert_read(Type::Tagged, ResponseType::No).await;
    }
    imap.send("GETMETADATA \"\" (/shared/comment /shared/admin)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("changed")
        .assert_contains(SERVER_ADMIN);

    imap.send_ok(
        "SETMETADATA \"\" (/private/comment \"my server note\" /private/vendor/test/pref \"dark\")",
    )
    .await;
    imap.send("GETMETADATA \"\" (/private/comment /private/vendor/test/pref)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/comment \"my server note\"")
        .assert_contains("/private/vendor/test/pref \"dark\"");

    imap.send_ok("SETMETADATA \"\" (/private/comment NIL /private/vendor/test/pref NIL)")
        .await;
    imap.send("GETMETADATA \"\" (/private/comment /private/vendor/test/pref)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("my server note")
        .assert_not_contains("\"dark\"");
}

async fn mailbox_annotations(imap: &mut ImapConnection) {
    imap.send_ok(&format!(
        "SETMETADATA \"{BOX}\" (/shared/comment \"Shared note\" /private/comment \"My note\")"
    ))
    .await;
    imap.send(&format!(
        "GETMETADATA \"{BOX}\" (/shared/comment /private/comment)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/comment \"Shared note\"")
        .assert_contains("/private/comment \"My note\"");

    imap.send(&format!("GETMETADATA \"{BOX}\" /SHARED/Comment"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/comment \"Shared note\"");

    imap.send_ok(&format!(
        "SETMETADATA \"{BOX}\" (/Shared/Vendor/Test/Color \"#b71c1c\")"
    ))
    .await;
    imap.send(&format!("GETMETADATA \"{BOX}\" /shared/vendor/test/color"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/vendor/test/color \"#b71c1c\"");

    let multi_line = "line one\r\nline two";
    imap.send(&format!(
        "SETMETADATA \"{BOX}\" (/shared/vendor/test/multi {{{}+}}\r\n{multi_line})",
        multi_line.len()
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send(&format!("GETMETADATA \"{BOX}\" /shared/vendor/test/multi"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.assert_last_contains_bytes(multi_line.as_bytes());

    imap.send_ok(&format!(
        "SETMETADATA \"{BOX}\" (/private/comment NIL /shared/vendor/test/multi NIL)"
    ))
    .await;
    imap.send(&format!(
        "GETMETADATA \"{BOX}\" (/private/comment /shared/vendor/test/multi /shared/comment)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("My note")
        .assert_not_contains("line one")
        .assert_contains("Shared note");
}

async fn depth_and_maxsize(imap: &mut ImapConnection) {
    imap.send_ok(&format!(
        concat!(
            "SETMETADATA \"{}\" (/shared/vendor/test/a \"1\" ",
            "/shared/vendor/test/a/b \"2\" /shared/vendor/test/a/b/c \"3\" ",
            "/shared/vendor/test/ab \"sibling\")"
        ),
        BOX
    ))
    .await;

    for (depth, present, absent) in [
        (
            "",
            &["/shared/vendor/test/a \"1\""][..],
            &["/shared/vendor/test/a/b ", "/shared/vendor/test/ab "][..],
        ),
        (
            "(DEPTH 0) ",
            &["/shared/vendor/test/a \"1\""][..],
            &["/shared/vendor/test/a/b ", "/shared/vendor/test/ab "][..],
        ),
        (
            "(DEPTH 1) ",
            &[
                "/shared/vendor/test/a \"1\"",
                "/shared/vendor/test/a/b \"2\"",
            ][..],
            &["/shared/vendor/test/a/b/c ", "/shared/vendor/test/ab "][..],
        ),
        (
            "(DEPTH infinity) ",
            &[
                "/shared/vendor/test/a \"1\"",
                "/shared/vendor/test/a/b \"2\"",
                "/shared/vendor/test/a/b/c \"3\"",
            ][..],
            &["/shared/vendor/test/ab "][..],
        ),
    ] {
        imap.send(&format!(
            "GETMETADATA {depth}\"{BOX}\" /shared/vendor/test/a"
        ))
        .await;
        let mut lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
        for expected in present {
            lines = lines.assert_contains(expected);
        }
        for unexpected in absent {
            lines = lines.assert_not_contains(unexpected);
        }
    }

    let big = "x".repeat(100);
    imap.send_ok(&format!(
        "SETMETADATA \"{BOX}\" (/shared/vendor/test/big \"{big}\")"
    ))
    .await;
    imap.send(&format!(
        "GETMETADATA (MAXSIZE 50) \"{BOX}\" (/shared/vendor/test/big /shared/vendor/test/color)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_response_code("METADATA LONGENTRIES 100")
        .assert_contains("/shared/vendor/test/color \"#b71c1c\"")
        .assert_not_contains(&big);

    imap.send(&format!(
        "GETMETADATA (MAXSIZE 200 DEPTH 1) \"{BOX}\" /shared/vendor/test/big"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&big)
        .assert_not_contains("LONGENTRIES");
}

async fn binary_values(imap: &mut ImapConnection) {
    let value: &[u8] = b"\x00\x01\x02\xff\xfe";
    let mut command = format!(
        "SETMETADATA \"{BOX}\" (/shared/vendor/test/bin ~{{{}+}}\r\n",
        value.len()
    )
    .into_bytes();
    command.extend_from_slice(value);
    command.push(b')');
    imap.send_bytes(&command).await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    imap.send(&format!("GETMETADATA \"{BOX}\" /shared/vendor/test/bin"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let mut expected = format!("~{{{}}}\r\n", value.len()).into_bytes();
    expected.extend_from_slice(value);
    imap.assert_last_contains_bytes(&expected);
}

async fn set_limits(test: &TestServer, imap: &mut ImapConnection) {
    let limits = &test.server.core.metadata;
    let huge = "h".repeat(limits.max_entry_size + 16);
    imap.send(&format!(
        "SETMETADATA \"{BOX}\" (/shared/vendor/test/applied \"no\" /shared/vendor/test/huge {{{}+}}\r\n{huge})",
        huge.len()
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_contains("[METADATA MAXSIZE ");

    let mut command = format!("SETMETADATA \"{BOX}\" (");
    for n in 0..=limits.max_entries {
        let _ = write!(command, "/shared/vendor/test/many{n} \"{n}\" ");
    }
    command.push_str("/shared/vendor/test/applied \"no\")");
    imap.send(&command).await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("METADATA TOOMANY");

    imap.send(&format!(
        "GETMETADATA (DEPTH 1) \"{BOX}\" (/shared/vendor/test/applied /shared/vendor/test/many0)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("\"no\"")
        .assert_not_contains("many0 \"0\"");
}

async fn invalid_names(imap: &mut ImapConnection) {
    for entry in [
        "/foo/bar",
        "/shared",
        "/shared//comment",
        "/shared/comment/",
        "/shared/comment*",
        "/shared/comm%nt",
        "\"/shared/c\u{f6}mment\"",
        "comment",
    ] {
        imap.send(&format!("GETMETADATA \"{BOX}\" {entry}")).await;
        imap.assert_read(Type::Tagged, ResponseType::Bad).await;
        imap.send(&format!("SETMETADATA \"{BOX}\" ({entry} \"value\")"))
            .await;
        imap.assert_read(Type::Tagged, ResponseType::Bad).await;
    }
    imap.send(&format!("GETMETADATA \"{BOX}\" /shared/comment"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("Shared note");
}

async fn list_metadata(imap: &mut ImapConnection) {
    imap.send_ok(&format!(
        "SETMETADATA \"{BOX}\" (/private/comment \"listed private\")"
    ))
    .await;
    imap.send("LIST \"\" \"Meta*\" RETURN (METADATA (/shared/comment /private/comment /shared/vendor/test/color))")
        .await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let list_line = lines
        .iter()
        .position(|line| line.starts_with("* LIST") && line.contains(&format!("\"{BOX}\"")))
        .unwrap_or_else(|| panic!("LIST response for {BOX} missing: {lines:?}"));
    let metadata_line = lines
        .iter()
        .position(|line| line.starts_with("* METADATA") && line.contains(BOX))
        .unwrap_or_else(|| panic!("METADATA response for {BOX} missing: {lines:?}"));
    assert!(
        metadata_line > list_line,
        "METADATA must follow the LIST response of its mailbox: {lines:?}"
    );
    let metadata = lines[metadata_line..]
        .iter()
        .take_while(|line| !line.starts_with("* LIST"))
        .cloned()
        .collect::<Vec<_>>();
    metadata
        .assert_contains("/shared/comment \"Shared note\"")
        .assert_contains("/private/comment \"listed private\"")
        .assert_contains("/shared/vendor/test/color \"#b71c1c\"");
    for line in lines
        .iter()
        .filter(|line| line.starts_with("* METADATA") && line.contains(EMPTY_BOX))
    {
        for value in ["Shared note", "listed private", "#b71c1c"] {
            assert!(
                !line.contains(value),
                "a mailbox without annotations returned values: {line}"
            );
        }
    }

    imap.send("LIST \"\" \"Meta*\" RETURN (METADATA (/shared/comment*))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Bad).await;
}

async fn rights(test: &TestServer, john: &mut ImapConnection) {
    let mut jane = test.account("jane.smith@example.com").imap_client().await;
    let mut bill = test.account("foobar@example.com").imap_client().await;

    john.send_ok(&format!("SETACL \"{BOX}\" jane.smith@example.com lr"))
        .await;

    jane.send(&format!("GETMETADATA \"{SHARED_BOX}\" /shared/comment"))
        .await;
    jane.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/comment \"Shared note\"");

    jane.send(&format!(
        "SETMETADATA \"{SHARED_BOX}\" (/shared/comment \"from jane\")"
    ))
    .await;
    jane.assert_read(Type::Tagged, ResponseType::No).await;

    jane.send_ok(&format!(
        "SETMETADATA \"{SHARED_BOX}\" (/private/comment \"jane private\")"
    ))
    .await;
    jane.send(&format!("GETMETADATA \"{SHARED_BOX}\" /private/comment"))
        .await;
    jane.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/comment \"jane private\"")
        .assert_not_contains("listed private");

    john.send(&format!("GETMETADATA \"{BOX}\" /private/comment"))
        .await;
    john.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/comment \"listed private\"")
        .assert_not_contains("jane private");

    john.send_ok(&format!("SETACL \"{BOX}\" jane.smith@example.com lrw"))
        .await;
    jane.send_ok(&format!(
        "SETMETADATA \"{SHARED_BOX}\" (/shared/comment \"from jane\")"
    ))
    .await;
    john.send(&format!("GETMETADATA \"{BOX}\" /shared/comment"))
        .await;
    john.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/comment \"from jane\"");

    bill.send(&format!("GETMETADATA \"{SHARED_BOX}\" /shared/comment"))
        .await;
    bill.assert_read(Type::Tagged, ResponseType::No).await;
    bill.send(&format!(
        "SETMETADATA \"{SHARED_BOX}\" (/private/comment \"bill\")"
    ))
    .await;
    bill.assert_read(Type::Tagged, ResponseType::No).await;

    john.send_ok(&format!("DELETEACL \"{BOX}\" jane.smith@example.com"))
        .await;
    jane.send(&format!("GETMETADATA \"{SHARED_BOX}\" /private/comment"))
        .await;
    jane.assert_read(Type::Tagged, ResponseType::No).await;

    for imap in [&mut jane, &mut bill] {
        imap.send("LOGOUT").await;
        imap.assert_read(Type::Untagged, ResponseType::Bye).await;
    }
}

async fn special_use(imap: &mut ImapConnection) {
    let mailbox = "Meta Archive";
    imap.send_ok(&format!("CREATE \"{mailbox}\"")).await;

    imap.send(&format!("GETMETADATA \"{mailbox}\" /private/specialuse"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("\\Archive");

    imap.send_ok(&format!(
        "SETMETADATA \"{mailbox}\" (/private/specialuse \"\\\\Archive\")"
    ))
    .await;
    imap.send(&format!("GETMETADATA \"{mailbox}\" /private/specialuse"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/specialuse")
        .assert_contains("\\Archive");
    imap.send(&format!("LIST \"\" \"{mailbox}\" RETURN (SPECIAL-USE)"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("\\Archive");

    imap.send(&format!(
        "SETMETADATA \"{mailbox}\" (/private/specialuse \"\\\\NotAUse\")"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;

    imap.send_ok(&format!(
        "SETMETADATA \"{mailbox}\" (/private/specialuse NIL)"
    ))
    .await;
    imap.send(&format!("LIST \"\" \"{mailbox}\" RETURN (SPECIAL-USE)"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("\\Archive");

    imap.send_ok(&format!("DELETE \"{mailbox}\"")).await;
}

async fn rename_and_delete(imap: &mut ImapConnection) {
    let renamed = "Meta Box Renamed";
    imap.send_ok(&format!("RENAME \"{BOX}\" \"{renamed}\""))
        .await;
    imap.send(&format!(
        "GETMETADATA \"{renamed}\" (/shared/comment /private/comment)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/comment \"from jane\"")
        .assert_contains("/private/comment \"listed private\"");

    imap.send_ok(&format!("DELETE \"{renamed}\"")).await;
    imap.send_ok(&format!("CREATE \"{renamed}\"")).await;
    imap.send(&format!(
        concat!(
            "GETMETADATA (DEPTH infinity) \"{}\" ",
            "(/shared/comment /private/comment /shared/vendor/test/color /shared/vendor/test/a)"
        ),
        renamed
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_not_contains("from jane")
        .assert_not_contains("listed private")
        .assert_not_contains("#b71c1c");
    imap.send_ok(&format!("DELETE \"{renamed}\"")).await;
}
