/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    jmap::metadata::fixture::{Ctx, MetaType, Using},
    utils::{
        account::Account,
        imap::{AssertResult, ImapConnection, Type},
        server::TestServer,
    },
};
use imap_proto::ResponseType;
use registry::schema::{prelude::Property, structs::Metadata};
use serde_json::{Value, json};
use std::{fmt::Write, str::FromStr};
use store::dispatch::StoreOps;
use types::{collection::Collection, id::Id};

const SERVER_COMMENT: &str = "Stalwart metadata test server";
const SERVER_ADMIN: &str = "mailto:postmaster@example.com";
const BOX: &str = "Meta Box";
const EMPTY_BOX: &str = "Meta Empty";
const SHARED_BOX: &str = "Shared Folders/jdoe@example.com/Meta Box";
const SHARED_EMPTY_BOX: &str = "Shared Folders/jdoe@example.com/Meta Empty";
const MODIFIED_ELSEWHERE: &str = "NO Metadata was modified by another process.";
const MEASURE_RUNS: usize = 4;
const RACE_ROUNDS: usize = 25;
const MESSAGE_BOX: &str = "Meta Messages";
const INBOUND_BOX: &str = "Meta Inbound";
const SHARED_INBOUND_BOX: &str = "Shared Folders/jane.smith@example.com/Meta Inbound";
const MOVED_BOX: &str = "Meta Moved";
const MESSAGES: usize = 8;
const COPY_RUNS: usize = 3;

struct StoreReads {
    list: usize,
    list_metadata: usize,
    list_private: usize,
    get_unflagged: usize,
    get_shared: usize,
    get_private: usize,
    get_special_use: usize,
    status: usize,
    noop: usize,
    myrights: usize,
}

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
    let unannotated = StoreReads::measure(test, &mut john).await;
    mailbox_annotations(&mut john).await;
    depth_and_maxsize(&mut john).await;
    binary_values(&mut john).await;
    set_limits(test, &mut john).await;
    atomic_failures(test, &mut john).await;
    invalid_names(&mut john).await;
    nil_names_and_values(&mut john).await;
    list_metadata(&mut john).await;
    list_combinations(&mut john).await;
    store_reads(test, &mut john, unannotated).await;
    concurrent_writers(test, &mut john).await;
    rights(test, &mut john).await;
    special_use(&mut john).await;
    special_use_rules(&mut john).await;
    private_gate(test).await;
    rename_and_delete(&mut john).await;
    message_metadata(test).await;

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

async fn atomic_failures(test: &TestServer, imap: &mut ImapConnection) {
    let limits = &test.server.core.metadata;
    let value = "p".repeat(limits.max_entry_size);
    let mut command = format!("SETMETADATA \"{BOX}\" (/shared/vendor/test/atomic \"shared\"");
    for n in 0..=limits.max_private_size / limits.max_entry_size {
        let _ = write!(
            command,
            " /private/vendor/test/atomic{n} {{{}+}}\r\n{value}",
            value.len()
        );
    }
    command.push(')');
    imap.send(&command).await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_contains("[METADATA MAXSIZE ");

    imap.send(&format!(
        concat!(
            "SETMETADATA \"{}\" (/shared/vendor/test/atomic \"shared\" ",
            "/private/vendor/test/atomic0 \"mine\" /private/specialuse \"\\\\Bogus\")"
        ),
        BOX
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("USEATTR");

    imap.send(&format!(
        "GETMETADATA \"{BOX}\" (/shared/vendor/test/atomic /private/vendor/test/atomic0)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/shared/vendor/test/atomic NIL")
        .assert_contains("/private/vendor/test/atomic0 NIL");

    imap.send(
        "SETMETADATA \"\" (/private/vendor/test/atomic \"mine\" /shared/comment \"changed\")",
    )
    .await;
    imap.assert_read(Type::Tagged, ResponseType::No).await;
    imap.send("GETMETADATA \"\" (/private/vendor/test/atomic /shared/comment)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/vendor/test/atomic NIL")
        .assert_not_contains("changed");
}

async fn nil_names_and_values(imap: &mut ImapConnection) {
    imap.send_ok("CREATE nil").await;
    imap.send_ok("SETMETADATA nil (/shared/comment \"NIL\" /private/comment nil)")
        .await;
    imap.send("GETMETADATA nil (/shared/comment /private/comment)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* METADATA \"nil\" (")
        .assert_contains("/shared/comment \"NIL\"")
        .assert_contains("/private/comment NIL");

    imap.send_ok("SETMETADATA nil (/shared/comment NIL)").await;
    imap.send("LIST \"\" nil RETURN (METADATA (/shared/comment))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* METADATA \"nil\" (/shared/comment NIL)");
    imap.send_ok("DELETE nil").await;
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

async fn list_combinations(imap: &mut ImapConnection) {
    imap.send(concat!(
        "LIST \"\" \"Meta*\" RETURN (CHILDREN STATUS (MESSAGES) ",
        "METADATA (/shared/comment /private/specialuse))"
    ))
    .await;
    let lines = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    for mailbox in [BOX, EMPTY_BOX] {
        let quoted = format!("\"{mailbox}\"");
        let list_line = lines
            .iter()
            .position(|line| line.starts_with("* LIST") && line.contains(&quoted))
            .unwrap_or_else(|| panic!("LIST response for {mailbox} missing: {lines:?}"));
        for (offset, response) in [(1, "* METADATA"), (2, "* STATUS")] {
            assert!(
                lines
                    .get(list_line + offset)
                    .is_some_and(|line| line.starts_with(response) && line.contains(&quoted)),
                "{response} for {mailbox} must follow its LIST response: {lines:?}"
            );
        }
        assert!(
            lines[list_line].contains("\\HasNoChildren"),
            "CHILDREN missing for {mailbox}: {lines:?}"
        );
    }
    lines
        .assert_contains(&format!(
            "* METADATA \"{BOX}\" (/shared/comment \"Shared note\" /private/specialuse NIL)"
        ))
        .assert_contains(&format!(
            "* METADATA \"{EMPTY_BOX}\" (/shared/comment NIL /private/specialuse NIL)"
        ));

    imap.send_ok(&format!("SUBSCRIBE \"{BOX}\"")).await;
    imap.send("LIST (SUBSCRIBED) \"\" \"Meta*\" RETURN (METADATA (/shared/comment))")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!(
            "* METADATA \"{BOX}\" (/shared/comment \"Shared note\")"
        ))
        .assert_not_contains(EMPTY_BOX);
    imap.send_ok(&format!("UNSUBSCRIBE \"{BOX}\"")).await;
}

impl StoreReads {
    async fn measure(test: &TestServer, imap: &mut ImapConnection) -> Self {
        StoreReads {
            list: min_reads(test, imap, "LIST \"\" \"Meta*\"").await,
            list_metadata: min_reads(
                test,
                imap,
                "LIST \"\" \"Meta*\" RETURN (METADATA (/shared/comment /private/specialuse))",
            )
            .await,
            list_private: min_reads(
                test,
                imap,
                "LIST \"\" \"Meta*\" RETURN (METADATA (/private/comment))",
            )
            .await,
            get_unflagged: min_reads(
                test,
                imap,
                &format!("GETMETADATA \"{EMPTY_BOX}\" /shared/comment"),
            )
            .await,
            get_shared: min_reads(
                test,
                imap,
                &format!("GETMETADATA \"{BOX}\" /shared/comment"),
            )
            .await,
            get_private: min_reads(
                test,
                imap,
                &format!("GETMETADATA \"{BOX}\" /private/comment"),
            )
            .await,
            get_special_use: min_reads(
                test,
                imap,
                &format!("GETMETADATA \"{BOX}\" /private/specialuse"),
            )
            .await,
            status: min_reads(test, imap, &format!("STATUS \"{BOX}\" (MESSAGES UNSEEN)")).await,
            noop: min_reads(test, imap, "NOOP").await,
            myrights: min_reads(test, imap, &format!("MYRIGHTS \"{BOX}\"")).await,
        }
    }
}

async fn min_reads(test: &TestServer, imap: &mut ImapConnection, command: &str) -> usize {
    test.wait_for_tasks().await;
    let mut lowest = usize::MAX;
    for _ in 0..MEASURE_RUNS {
        StoreOps::take();
        imap.send(command).await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
        lowest = lowest.min(StoreOps::take().total());
    }
    lowest
}

async fn store_reads(test: &TestServer, imap: &mut ImapConnection, unannotated: StoreReads) {
    let annotated = StoreReads::measure(test, imap).await;

    for (path, without, with) in [
        ("LIST", unannotated.list, unannotated.list),
        (
            "LIST RETURN (METADATA) without annotations",
            unannotated.list,
            unannotated.list_metadata,
        ),
        (
            "LIST RETURN (METADATA (/private)) without annotations",
            unannotated.list,
            unannotated.list_private,
        ),
        (
            "GETMETADATA /private without annotations",
            unannotated.get_shared,
            unannotated.get_private,
        ),
        ("LIST with annotations", unannotated.list, annotated.list),
        (
            "STATUS with annotations",
            unannotated.status,
            annotated.status,
        ),
        ("NOOP with annotations", unannotated.noop, annotated.noop),
        (
            "MYRIGHTS pays the LIST synchronization plus its archive read",
            unannotated.list + 1,
            unannotated.myrights,
        ),
        (
            "GETMETADATA on a mailbox without annotations",
            unannotated.get_unflagged,
            annotated.get_unflagged,
        ),
        (
            "GETMETADATA /private/specialuse",
            unannotated.get_special_use,
            annotated.get_special_use,
        ),
        (
            "GETMETADATA /shared on an annotated mailbox",
            unannotated.get_shared + 1,
            annotated.get_shared,
        ),
        (
            "GETMETADATA /private on an annotated mailbox",
            unannotated.get_private + 1,
            annotated.get_private,
        ),
        (
            "LIST RETURN (METADATA (/shared /private/specialuse)) with annotations",
            unannotated.list_metadata + 1,
            annotated.list_metadata,
        ),
        (
            "LIST RETURN (METADATA (/private)) with annotations",
            unannotated.list_private + 1,
            annotated.list_private,
        ),
    ] {
        assert_eq!(without, with, "{path}: unexpected store reads");
    }
}

async fn concurrent_writers(test: &TestServer, john: &mut ImapConnection) {
    let mut other = test.account("jdoe@example.com").imap_client().await;
    for round in 0..RACE_ROUNDS {
        john.send(&format!(
            "SETMETADATA \"{BOX}\" (/shared/vendor/test/race \"a{round}\")"
        ))
        .await;
        other
            .send(&format!(
                "SETMETADATA \"{BOX}\" (/shared/vendor/test/race \"b{round}\")"
            ))
            .await;
    }
    let mut conflicts = 0;
    for imap in [&mut *john, &mut other] {
        for _ in 0..RACE_ROUNDS {
            let lines = imap.read(Type::Tagged).await;
            let response = lines.last().map(String::as_str).unwrap_or_default();
            if response.contains(MODIFIED_ELSEWHERE) {
                conflicts += 1;
            } else {
                assert!(
                    response.starts_with("_x OK"),
                    "a lost race must answer a plain NO: {lines:?}"
                );
            }
        }
    }
    println!(
        "Concurrent SETMETADATA conflicts: {conflicts} of {}",
        RACE_ROUNDS * 2
    );

    john.send(&format!("GETMETADATA \"{BOX}\" /shared/vendor/test/race"))
        .await;
    john.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains_any(&[
            "/shared/vendor/test/race \"a",
            "/shared/vendor/test/race \"b",
        ]);
    john.send_ok(&format!(
        "SETMETADATA \"{BOX}\" (/shared/vendor/test/race NIL)"
    ))
    .await;
    other.send("LOGOUT").await;
    other.assert_read(Type::Untagged, ResponseType::Bye).await;
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

    john.send_ok(&format!("SETACL \"{EMPTY_BOX}\" jane.smith@example.com l"))
        .await;
    jane.send("LIST \"\" (\"Shared Folders\" \"Shared Folders/jdoe@example.com*\") RETURN (METADATA (/shared/comment /private/comment))")
        .await;
    let lines = jane.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("* METADATA"))
            .collect::<Vec<_>>(),
        vec![&format!(
            "* METADATA \"{SHARED_BOX}\" (/shared/comment \"Shared note\" /private/comment NIL)"
        )],
        "only readable mailboxes return METADATA: {lines:?}"
    );
    lines
        .assert_contains(&format!("\"{SHARED_EMPTY_BOX}\""))
        .assert_contains("\"Shared Folders\"");
    jane.send(&format!(
        "GETMETADATA \"{SHARED_EMPTY_BOX}\" /shared/comment"
    ))
    .await;
    jane.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("NOPERM");
    john.send_ok(&format!("DELETEACL \"{EMPTY_BOX}\" jane.smith@example.com"))
        .await;

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

async fn special_use_rules(imap: &mut ImapConnection) {
    imap.send("SETMETADATA INBOX (/private/specialuse \"\\\\Archive\")")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("USEATTR");
    imap.send_ok("SETMETADATA INBOX (/private/specialuse NIL)")
        .await;
    imap.send("GETMETADATA INBOX /private/specialuse").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/specialuse NIL");

    let (first, second) = ("Meta Use A", "Meta Use B");
    for mailbox in [first, second] {
        imap.send_ok(&format!("CREATE \"{mailbox}\"")).await;
    }
    imap.send_ok(&format!(
        "SETMETADATA \"{first}\" (/private/specialuse \"\\\\archive \\\\Archive\")"
    ))
    .await;
    for (mailbox, value) in [
        (second, "\\\\Archive"),
        (first, "\\\\Archive \\\\Important"),
        (first, "\\\\All"),
    ] {
        imap.send(&format!(
            "SETMETADATA \"{mailbox}\" (/shared/comment \"not applied\" /private/specialuse \"{value}\")"
        ))
        .await;
        imap.assert_read(Type::Tagged, ResponseType::No)
            .await
            .assert_response_code("USEATTR");
    }
    imap.send_ok(&format!(
        "SETMETADATA \"{first}\" (/private/specialuse NIL /shared/comment \"kept\")"
    ))
    .await;
    imap.send(&format!(
        "GETMETADATA \"{first}\" (/private/specialuse /shared/comment)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/specialuse NIL")
        .assert_contains("/shared/comment \"kept\"")
        .assert_not_contains("not applied");
    imap.send_ok(&format!(
        "SETMETADATA \"{second}\" (/private/specialuse \"\\\\Archive\")"
    ))
    .await;
    imap.send("LIST \"\" \"Meta Use*\" RETURN (SPECIAL-USE)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_count("\\Archive", 1);

    for mailbox in [first, second] {
        imap.send_ok(&format!("DELETE \"{mailbox}\"")).await;
    }
}

async fn private_gate(test: &TestServer) {
    set_private_metadata(test, false).await;
    let mut imap = test.account("jdoe@example.com").imap_client().await;

    for command in [
        format!("SETMETADATA \"{BOX}\" (/private/comment \"gated\")"),
        format!(
            "SETMETADATA \"{BOX}\" (/shared/vendor/test/gate \"gated\" /private/comment \"gated\")"
        ),
        "SETMETADATA \"\" (/private/comment \"gated\")".to_string(),
    ] {
        imap.send(&command).await;
        imap.assert_read(Type::Tagged, ResponseType::No)
            .await
            .assert_response_code("METADATA NOPRIVATE");
    }
    imap.send(&format!(
        "GETMETADATA \"{BOX}\" (/private/comment /private/specialuse /shared/comment /shared/vendor/test/gate)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/specialuse NIL")
        .assert_contains("/shared/vendor/test/gate NIL")
        .assert_contains("/shared/comment \"")
        .assert_not_contains("/private/comment");
    imap.send("GETMETADATA \"\" (/private/comment /shared/comment)")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(SERVER_COMMENT)
        .assert_not_contains("/private/comment");

    imap.send_ok(&format!(
        "SETMETADATA \"{EMPTY_BOX}\" (/private/specialuse \"\\\\Archive\")"
    ))
    .await;
    imap.send(&format!(
        "LIST \"\" \"{EMPTY_BOX}\" RETURN (METADATA (/private/comment /private/specialuse))"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!(
            "* METADATA \"{EMPTY_BOX}\" (/private/specialuse \"\\\\Archive\")"
        ));
    imap.send_ok(&format!(
        "SETMETADATA \"{EMPTY_BOX}\" (/private/specialuse NIL)"
    ))
    .await;
    imap.send("LOGOUT").await;
    imap.assert_read(Type::Untagged, ResponseType::Bye).await;

    set_private_metadata(test, true).await;
    let mut imap = test.account("jdoe@example.com").imap_client().await;
    imap.send(&format!("GETMETADATA \"{BOX}\" /private/comment"))
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("/private/comment \"listed private\"");
    imap.send("LOGOUT").await;
    imap.assert_read(Type::Untagged, ResponseType::Bye).await;
}

async fn message_metadata(test: &TestServer) {
    let ctx = Ctx::new(test);
    let john = ctx.account("jdoe@example.com");
    let jane = ctx.account("jane.smith@example.com");

    let mut jane_imap = jane.imap_client().await;
    jane_imap
        .send_ok(&format!("CREATE \"{INBOUND_BOX}\""))
        .await;
    jane_imap
        .send_ok(&format!("SETACL \"{INBOUND_BOX}\" jdoe@example.com lrswi"))
        .await;

    let quota_before = ctx.used_quota(john).await;
    let mut imap = john.imap_client().await;
    for mailbox in [MESSAGE_BOX, MOVED_BOX] {
        imap.send_ok(&format!("CREATE \"{mailbox}\"")).await;
    }
    for n in 0..MESSAGES {
        imap.append(
            MESSAGE_BOX,
            &format!("From: meta@example.com\r\nSubject: meta message {n}\r\n\r\nbody {n}\r\n"),
        )
        .await;
    }
    let messages = mailbox_messages(&ctx, john, MESSAGE_BOX).await;
    assert_eq!(messages.len(), MESSAGES, "{messages:?}");
    for (subject, id, _) in messages.iter().step_by(2) {
        ctx.update_ok(
            john,
            john,
            MetaType::Email,
            id,
            json!({"metadata/x.example": {"subject": subject}}),
        )
        .await;
    }
    imap.send_ok(&format!("SELECT \"{MESSAGE_BOX}\"")).await;

    let plain = copy_metadata_reads(test, &mut imap, "2,4").await;
    let flagged = copy_metadata_reads(test, &mut imap, "1,3").await;
    assert_eq!(
        (plain, flagged),
        (0, 1),
        "a cross-account COPY reads the flagged containers in one bulk read"
    );

    imap.send_ok(&format!("UID MOVE 5:6 \"{SHARED_INBOUND_BOX}\""))
        .await;
    imap.send_ok("UID STORE 1:4 +FLAGS.SILENT (\\Deleted)")
        .await;
    imap.send_ok("EXPUNGE").await;
    imap.send_ok(&format!("UID MOVE 7:8 \"{MOVED_BOX}\"")).await;

    for (n, (subject, id, _)) in messages.iter().enumerate() {
        let document_id = Id::from_str(id)
            .unwrap_or_else(|_| panic!("invalid id {id}"))
            .document_id();
        let container = test
            .server
            .metadata_container(john.id().document_id(), Collection::Email, document_id)
            .await
            .expect("container read");
        assert_eq!(
            container.is_some(),
            n == 6,
            "{subject}: only the message moved within the account keeps its container"
        );
    }

    let inbound = mailbox_messages(&ctx, jane, INBOUND_BOX).await;
    assert_eq!(inbound.len(), COPY_RUNS * 4 + 2, "{inbound:?}");
    for (subject, _, metadata) in &inbound {
        let number = subject
            .rsplit_once(' ')
            .and_then(|(_, number)| number.parse::<usize>().ok())
            .unwrap_or_else(|| panic!("unexpected subject {subject}"));
        if number % 2 == 0 {
            assert_eq!(
                metadata,
                &json!({"x.example": {"subject": subject}}),
                "{subject}: the shared container travels with a cross-account copy"
            );
        } else {
            assert!(
                metadata
                    .as_object()
                    .is_none_or(|entries| entries.is_empty()),
                "{subject}: unexpected metadata {metadata}"
            );
        }
    }

    let (_, moved_id, _) = &messages[6];
    let (shared, _) = ctx.metadata(john, john, MetaType::Email, moved_id).await;
    assert_eq!(
        shared,
        json!({"x.example": {"subject": "meta message 6"}}),
        "a MOVE within the account keeps the message and its container"
    );
    imap.send_ok("UNSELECT").await;
    for mailbox in [MESSAGE_BOX, MOVED_BOX] {
        imap.send_ok(&format!("DELETE \"{mailbox}\"")).await;
    }
    test.wait_for_tasks().await;
    assert_eq!(
        ctx.used_quota(john).await,
        quota_before,
        "EXPUNGE and MOVE release the message containers"
    );

    jane_imap
        .send_ok(&format!("DELETE \"{INBOUND_BOX}\""))
        .await;
    for imap in [&mut imap, &mut jane_imap] {
        imap.send("LOGOUT").await;
        imap.assert_read(Type::Untagged, ResponseType::Bye).await;
    }
}

async fn copy_metadata_reads(test: &TestServer, imap: &mut ImapConnection, uids: &str) -> usize {
    let mut lowest = usize::MAX;
    for _ in 0..COPY_RUNS {
        test.wait_for_tasks().await;
        StoreOps::take();
        imap.send(&format!("UID COPY {uids} \"{SHARED_INBOUND_BOX}\""))
            .await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
        lowest = lowest.min(StoreOps::take().metadata);
    }
    lowest
}

async fn mailbox_messages(
    ctx: &Ctx<'_>,
    owner: &Account,
    mailbox: &str,
) -> Vec<(String, String, Value)> {
    let response = ctx
        .method(
            owner,
            Using::Plain,
            "Mailbox/query",
            json!({"accountId": owner.id_string(), "filter": {"name": mailbox}}),
        )
        .await;
    let mailbox_id = response
        .pointer("/methodResponses/0/1/ids/0")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{mailbox} not found: {response:?}"))
        .to_string();
    let response = ctx
        .call(
            owner,
            Using::Metadata,
            json!([
                [
                    "Email/query",
                    {
                        "accountId": owner.id_string(),
                        "filter": {"inMailbox": mailbox_id},
                        "sort": [{"property": "subject"}]
                    },
                    "0"
                ],
                [
                    "Email/get",
                    {
                        "accountId": owner.id_string(),
                        "#ids": {"resultOf": "0", "name": "Email/query", "path": "/ids"},
                        "properties": ["id", "subject", "metadata"]
                    },
                    "1"
                ]
            ]),
        )
        .await;
    let mut messages = response
        .pointer("/methodResponses/1/1/list")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("Email/get failed: {response:?}"))
        .iter()
        .map(|email| {
            (
                email
                    .get("subject")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                email
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                email.get("metadata").cloned().unwrap_or(Value::Null),
            )
        })
        .collect::<Vec<_>>();
    messages.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    messages
}

async fn set_private_metadata(test: &TestServer, private_metadata: bool) {
    let registry = test.account("admin");
    registry
        .registry_update_setting(
            Metadata {
                private_metadata,
                ..Default::default()
            },
            &[Property::PrivateMetadata],
        )
        .await;
    registry.reload_settings().await;
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
