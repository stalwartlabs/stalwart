/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AssertResult, ImapConnection, Type};
use crate::utils::account::Account;
use email::message::metadata::MAX_VALUE_LEN;
use imap_proto::ResponseType;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};

pub async fn test(imap: &mut ImapConnection, imap_check: &mut ImapConnection) {
    println!("Running FETCH tests...");

    // Examine INBOX
    imap.send("EXAMINE INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("10 EXISTS")
        .assert_contains("[UIDNEXT 11]");

    // Fetch all properties available from JMAP
    imap.send(concat!(
        "FETCH 10 (FLAGS INTERNALDATE PREVIEW OBJECTID ",
        "RFC822.SIZE UID ENVELOPE BODYSTRUCTURE)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($hasattachment Flag_009)")
        .assert_contains("RFC822.SIZE 1457")
        .assert_contains("UID 10")
        .assert_contains("INTERNALDATE")
        .assert_contains("OBJECTID (")
        .assert_contains("EMAILID ")
        .assert_contains("THREADID ")
        .assert_contains("but then I thought, why not do both?")
        .assert_contains(concat!(
            "ENVELOPE (\"Sat, 20 Nov 2021 14:22:01 -0800\" ",
            "\"Why not both importing AND exporting? ☺\" ",
            "((\"Art Vandelay (Vandelay Industries)\" NIL \"art\" \"vandelay.com\")) ",
            "((\"Art Vandelay (Vandelay Industries)\" NIL \"art\" \"vandelay.com\")) ",
            "((\"Art Vandelay (Vandelay Industries)\" NIL \"art\" \"vandelay.com\")) ",
            "((NIL NIL \"Colleagues\" NIL)",
            "(\"James Smythe\" NIL \"james\" \"vandelay.com\")",
            "(NIL NIL NIL NIL)(NIL NIL \"Friends\" NIL)",
            "(NIL NIL \"jane\" \"example.com\")",
            "(\"John Smîth\" NIL \"john\" \"example.com\")",
            "(NIL NIL NIL NIL)) NIL NIL NIL NIL)"
        ))
        .assert_contains(concat!(
            "BODYSTRUCTURE ((\"text\" \"html\" (\"charset\" \"us-ascii\") NIL NIL ",
            "\"base64\" 239 3 NIL NIL NIL NIL)",
            "(\"message\" \"rfc822\" NIL NIL NIL \"7bit\" 723 ",
            "(NIL \"Exporting my book about coffee tables\" ",
            "((\"Cosmo Kramer\" NIL \"kramer\" \"kramerica.com\")) ",
            "((\"Cosmo Kramer\" NIL \"kramer\" \"kramerica.com\")) ",
            "((\"Cosmo Kramer\" NIL \"kramer\" \"kramerica.com\")) ",
            "NIL NIL NIL NIL NIL) ",
            "((\"text\" \"plain\" (\"charset\" \"utf-16\") NIL NIL ",
            "\"quoted-printable\" 228 3 NIL NIL NIL NIL)",
            "(\"image\" \"gif\" (\"name\" \"Book about ☕ tables.gif\") ",
            "NIL NIL \"Base64\" 56 NIL ",
            "(\"attachment\" NIL) NIL NIL) \"mixed\" (\"boundary\" \"giddyup\") NIL NIL NIL)",
            " 19 NIL NIL NIL NIL) ",
            "\"mixed\" (\"boundary\" \"festivus\") NIL NIL NIL)"
        ));

    imap_check.send("EXAMINE INBOX").await;
    imap_check.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap_check.send("FETCH 10 (ENVELOPE BODYSTRUCTURE)").await;
    imap_check
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(
            "\"=?utf-8?B?V2h5IG5vdCBib3RoIGltcG9ydGluZyBBTkQgZXhwb3J0aW5nPyDimLo=?=\" ",
        )
        .assert_contains("(\"=?utf-8?B?Sm9obiBTbcOudGg=?=\" NIL \"john\" \"example.com\")")
        .assert_contains("(\"name\" \"=?utf-8?B?Qm9vayBhYm91dCDimJUgdGFibGVzLmdpZg==?=\")");

    // Fetch bodyparts
    imap.send(concat!(
        "UID FETCH 10 (BINARY[1] BINARY.SIZE[1] BODY[1.TEXT] BODY[2.1.HEADER] ",
        "BINARY[2.1] BODY[2.MIME] BODY[HEADER.FIELDS (From)]<10.8>)"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("BINARY[1] ~{175}")
        .assert_contains("BINARY.SIZE[1] 175")
        .assert_contains("BODY[1.TEXT] {239}")
        .assert_contains("BODY[2.1.HEADER] {88}")
        .assert_contains("BINARY[2.1] ~{108}")
        .assert_contains("BODY[2.MIME] {30}")
        .assert_contains("BODY[HEADER.FIELDS (FROM)]<10> {8}")
        .assert_contains("&ldquo;exporting&rdquo;")
        .assert_contains("PGh0bWw+PHA+")
        .assert_contains("Content-Transfer-Encoding: quoted-printable")
        .assert_contains("Vandelay");
    let fraktur_utf16_le: Vec<u8> = "ℌ𝔢𝔩𝔭 𝔪𝔢 𝔢𝔵𝔭𝔬𝔯𝔱 𝔪𝔶 𝔟𝔬𝔬𝔨"
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    imap.assert_last_contains_bytes(&fraktur_utf16_le);

    imap.send("UID FETCH 10 (BODY[MIME])").await;
    imap.assert_read(Type::Tagged, ResponseType::Bad).await;

    // We are in EXAMINE mode, fetching body should not set \Seen
    imap.send("UID FETCH 10 (FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($hasattachment Flag_009)");

    // Switch to SELECT mode
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // Peek bodyparts
    imap.send("UID FETCH 10 (BINARY.PEEK[1] BINARY.SIZE[1] BODY.PEEK[1.TEXT])")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("BINARY[1] ~{175}")
        .assert_contains("BINARY.SIZE[1] 175")
        .assert_contains("BODY[1.TEXT] {239}");

    // PEEK was used, \Seen should not be set
    imap.send("UID FETCH 10 (FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS ($hasattachment Flag_009)");

    // Fetching a body section should set the \Seen flag
    imap.send("UID FETCH 10 (BODY[1.TEXT])").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FLAGS")
        .assert_contains("\\Seen");

    // Fetch a sequence
    imap.send("FETCH 1:5,7:10 (UID FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (UID 1 ")
        .assert_contains("* 2 FETCH (UID 2 ")
        .assert_contains("* 3 FETCH (UID 3 ")
        .assert_contains("* 4 FETCH (UID 4 ")
        .assert_contains("* 5 FETCH (UID 5 ")
        .assert_contains("* 7 FETCH (UID 7 ")
        .assert_contains("* 8 FETCH (UID 8 ")
        .assert_contains("* 9 FETCH (UID 9 ")
        .assert_contains("* 10 FETCH (UID 10 ")
        .assert_count("\\Recent", 0);

    imap.send("FETCH 7:* (UID FLAGS)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 7 FETCH (UID 7 ")
        .assert_contains("* 8 FETCH (UID 8 ")
        .assert_contains("* 9 FETCH (UID 9 ")
        .assert_contains("* 10 FETCH (UID 10 ");

    // Fetch using a saved search
    imap.send("UID SEARCH RETURN (SAVE) FROM \"nathaniel\"")
        .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("FETCH $ (UID PREVIEW)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* 1 FETCH (UID 1 ")
        .assert_contains("* 4 FETCH (UID 4 ")
        .assert_contains("* 6 FETCH (UID 6 ")
        .assert_contains("Some text appears here")
        .assert_contains("plain text version of message goes here")
        .assert_contains("This is implicitly typed plain US-ASCII text.");

    // A failing command in a pipelined batch does not swallow the tagged completion of the commands queued behind it
    imap.send_raw(concat!(
        "_p UID FETCH 1:* (UID) (CHANGEDSINCE 1 VANISHED)\r\n",
        "_x FETCH 1 (UID)\r\n"
    ))
    .await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("_p BAD")
        .assert_contains("* 1 FETCH (UID 1");

    let subject = "s".repeat(MAX_VALUE_LEN + 1);
    let to = (0..1_100)
        .map(|index| format!("r{index}@example.com"))
        .collect::<Vec<_>>()
        .join(",\r\n ");
    let capped = format!(
        "From: a@example.com\r\nTo: {to}\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbody\r\n"
    );
    let forwarded = concat!(
        "From: a@example.com\r\n",
        "Subject: fwd\r\n",
        "Content-Type: message/rfc822\r\n",
        "Content-Description: forwarded\r\n",
        "\r\n",
        "From: inner@example.com\r\n",
        "Subject: inner\r\n",
        "\r\n",
        "inner body\r\n"
    );
    imap.send("CREATE \"Fetch Limits\"").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    for message in [capped.as_str(), forwarded] {
        imap.send(&format!("APPEND \"Fetch Limits\" {{{}}}", message.len()))
            .await;
        imap.assert_read(Type::Continuation, ResponseType::Ok).await;
        imap.send_untagged(message).await;
        imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    }
    imap.send("EXAMINE \"Fetch Limits\"").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("FETCH 1 (ENVELOPE)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains(&format!("\"{}\"", &subject[..MAX_VALUE_LEN]))
        .assert_contains("(NIL NIL \"r0\" \"example.com\")")
        .assert_contains("(NIL NIL \"r1099\" \"example.com\")");
    imap.send("FETCH 1 (BODY.PEEK[1.MIME])").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("BODY[1.MIME] {43}")
        .assert_contains("Content-Type: text/plain; charset=utf-8");
    imap.send("FETCH 2 (BODY.PEEK[1.MIME])").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("BODY[1.MIME] {64}")
        .assert_contains("Content-Description: forwarded");
    imap.send("DELETE \"Fetch Limits\"").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
}

pub async fn test_large_headers(account: &Account) {
    println!("Running large header FETCH tests...");

    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut message = String::with_capacity(LARGE_HEADERS_LEN + 1024);
    message.push_str("From: a@example.com\r\nSubject: padded headers\r\n");
    for pad in 0..LARGE_HEADERS_LEN / LARGE_HEADER_VALUE_LEN {
        let mut bytes = Vec::with_capacity(LARGE_HEADER_VALUE_LEN);
        while bytes.len() < LARGE_HEADER_VALUE_LEN * 3 / 4 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            bytes.extend_from_slice(&seed.to_le_bytes());
        }
        let encoded = encodify::base64::STANDARD.encode(&bytes);
        message.push_str(&format!("X-Pad-{pad}:"));
        for line in encoded.as_bytes().chunks(76) {
            message.push_str("\r\n ");
            message.push_str(std::str::from_utf8(line).unwrap());
        }
        message.push_str("\r\n");
    }
    message.push_str("Content-Type: text/plain\r\n\r\nshort body\r\n");

    let mut client = RawClient::connect().await;
    client
        .command(&format!(
            "LOGIN \"{}\" \"{}\"",
            account.name(),
            account.secret()
        ))
        .await;
    client.command("CREATE \"Large Headers\"").await;
    client
        .command(&format!(
            "APPEND \"Large Headers\" {{{}+}}\r\n{message}",
            message.len()
        ))
        .await;
    client.command("SELECT \"Large Headers\"").await;

    for (command, expected) in [
        (
            "UID FETCH 1 (BODYSTRUCTURE)",
            "BODYSTRUCTURE (\"text\" \"plain\"",
        ),
        ("UID FETCH 1 (ENVELOPE)", "\"padded headers\""),
        (
            "UID FETCH 1 (BODY.PEEK[HEADER.FIELDS (SUBJECT X-PAD-0)])",
            "Subject: padded headers",
        ),
    ] {
        let response = client.response(command).await;
        assert!(
            response.contains(expected),
            "{command}: {}",
            response.get(..512).unwrap_or(&response)
        );
    }
    let header = client
        .literal("UID FETCH 1 (BODY.PEEK[HEADER])")
        .await
        .unwrap_or_default();
    assert_eq!(
        header.len(),
        message.find("\r\n\r\n").unwrap() + 4,
        "full header section"
    );

    client.command("DELETE \"Large Headers\"").await;
    client.command("LOGOUT").await;
}

const LARGE_HEADERS_LEN: usize = 256 * 1024;
const LARGE_HEADER_VALUE_LEN: usize = 4096;

struct RawClient {
    stream: BufReader<TcpStream>,
    line: Vec<u8>,
}

impl RawClient {
    async fn connect() -> Self {
        let mut client = RawClient {
            stream: BufReader::new(TcpStream::connect("127.0.0.1:9991").await.unwrap()),
            line: Vec::new(),
        };
        client.read_line().await;
        client
    }

    async fn read_line(&mut self) {
        self.line.clear();
        let read = self.stream.read_until(b'\n', &mut self.line).await.unwrap();
        assert!(read > 0, "connection closed");
    }

    async fn send(&mut self, command: &str) {
        let request = format!("C1 {command}\r\n");
        self.stream
            .get_mut()
            .write_all(request.as_bytes())
            .await
            .unwrap();
    }

    async fn command(&mut self, command: &str) {
        self.send(command).await;
        loop {
            self.read_line().await;
            if self.line.starts_with(b"C1 ") {
                assert!(
                    self.line.starts_with(b"C1 OK"),
                    "{command}: {}",
                    String::from_utf8_lossy(&self.line)
                );
                return;
            }
        }
    }

    async fn response(&mut self, command: &str) -> String {
        self.send(command).await;
        let mut response = Vec::new();
        loop {
            self.read_line().await;
            if self.line.starts_with(b"C1 ") {
                assert!(
                    self.line.starts_with(b"C1 OK"),
                    "{command}: {}",
                    String::from_utf8_lossy(&self.line)
                );
                return String::from_utf8_lossy(&response).into_owned();
            }
            response.extend_from_slice(&self.line);
        }
    }

    async fn literal(&mut self, command: &str) -> Option<Vec<u8>> {
        self.send(command).await;
        let mut literal = None;
        loop {
            self.read_line().await;
            if self.line.starts_with(b"C1 ") {
                assert!(
                    self.line.starts_with(b"C1 OK"),
                    "{command}: {}",
                    String::from_utf8_lossy(&self.line)
                );
                return literal;
            }
            let Some(size) = self
                .line
                .strip_suffix(b"}\r\n")
                .and_then(|head| {
                    head.iter()
                        .rposition(|byte| *byte == b'{')
                        .map(|pos| (head, pos))
                })
                .and_then(|(head, pos)| head.get(pos + 1..))
                .and_then(|digits| std::str::from_utf8(digits).ok()?.parse::<usize>().ok())
            else {
                continue;
            };
            let mut bytes = vec![0; size];
            self.stream.read_exact(&mut bytes).await.unwrap();
            literal = Some(bytes);
        }
    }
}
