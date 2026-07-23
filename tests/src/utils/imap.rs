/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use imap_proto::ResponseType;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf},
    net::TcpStream,
};

pub struct ImapConnection {
    tag: &'static [u8],
    reader: BufReader<ReadHalf<TcpStream>>,
    writer: WriteHalf<TcpStream>,
    last_raw: Vec<u8>,
}

async fn read_lossy_line(
    reader: &mut BufReader<ReadHalf<TcpStream>>,
) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let mut buf = Vec::new();
    let n = reader.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    let mut trimmed = buf.as_slice();
    if trimmed.last() == Some(&b'\n') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    if trimmed.last() == Some(&b'\r') {
        trimmed = &trimmed[..trimmed.len() - 1];
    }
    Ok(Some((String::from_utf8_lossy(trimmed).into_owned(), buf)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Tagged,
    Untagged,
    Continuation,
    Status,
}

impl ImapConnection {
    pub async fn connect(tag: &'static [u8]) -> Self {
        Self::connect_to(tag, "127.0.0.1:9991").await
    }

    pub async fn connect_to(tag: &'static [u8], addr: impl AsRef<str>) -> Self {
        let (reader, writer) = tokio::io::split(TcpStream::connect(addr.as_ref()).await.unwrap());
        ImapConnection {
            tag,
            reader: BufReader::new(reader),
            writer,
            last_raw: Vec::new(),
        }
    }

    pub fn assert_last_contains_bytes(&self, pattern: &[u8]) -> &Self {
        if !self.last_raw.windows(pattern.len()).any(|w| w == pattern) {
            panic!(
                "Expected byte sequence {:02x?} not found in last response ({} bytes).",
                pattern,
                self.last_raw.len()
            );
        }
        self
    }

    pub async fn assert_read(&mut self, t: Type, rt: ResponseType) -> Vec<String> {
        let lines = self.read(t).await;
        let mut buf = Vec::with_capacity(10);
        buf.extend_from_slice(match t {
            Type::Tagged => self.tag,
            Type::Untagged | Type::Status => b"* ",
            Type::Continuation => b"+ ",
        });
        if !matches!(t, Type::Continuation | Type::Status) {
            rt.serialize(&mut buf);
        }
        if lines
            .last()
            .unwrap()
            .starts_with(&String::from_utf8(buf).unwrap())
        {
            lines
        } else {
            panic!("Expected {:?}/{:?} from server but got: {:?}", t, rt, lines);
        }
    }

    pub async fn assert_disconnect(&mut self) {
        match tokio::time::timeout(
            Duration::from_millis(1500),
            read_lossy_line(&mut self.reader),
        )
        .await
        {
            Ok(Ok(None)) => {}
            Ok(Ok(Some((line, _)))) => {
                panic!("Expected connection to be closed, but got {:?}", line);
            }
            Ok(Err(err)) => {
                panic!("Connection broken: {:?}", err);
            }
            Err(_) => panic!("Timeout while waiting for server response."),
        }
    }

    pub async fn read(&mut self, t: Type) -> Vec<String> {
        let mut lines = Vec::new();
        self.last_raw.clear();
        loop {
            match tokio::time::timeout(
                Duration::from_millis(1500),
                read_lossy_line(&mut self.reader),
            )
            .await
            {
                Ok(Ok(Some((line, raw)))) => {
                    self.last_raw.extend_from_slice(&raw);
                    let is_done = line.starts_with(match t {
                        Type::Tagged => std::str::from_utf8(self.tag).unwrap(),
                        Type::Untagged | Type::Status => "* ",
                        Type::Continuation => "+ ",
                    });
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        return lines;
                    }
                }
                Ok(Ok(None)) => {
                    panic!("Invalid response: {:?}.", lines);
                }
                Ok(Err(err)) => {
                    panic!("Connection broken: {} ({:?})", err, lines);
                }
                Err(_) => panic!("Timeout while waiting for server response: {:?}", lines),
            }
        }
    }

    pub async fn authenticate(&mut self, user: &str, pass: &str) {
        let creds = general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        self.send(&format!(
            "AUTHENTICATE PLAIN {{{}+}}\r\n{creds}",
            creds.len()
        ))
        .await;
        self.assert_read(Type::Tagged, ResponseType::Ok).await;
    }

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {}{:?}", std::str::from_utf8(self.tag).unwrap(), text);
        self.writer.write_all(self.tag).await.unwrap();
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_untagged(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }

    pub async fn append(&mut self, mailbox: &str, message: &str) {
        self.send_ok(&format!(
            "APPEND {:?} {{{}+}}\r\n{}",
            mailbox,
            message.len(),
            message
        ))
        .await;
    }

    pub async fn send_ok(&mut self, cmd: &str) {
        self.send(cmd).await;
        self.assert_read(Type::Tagged, ResponseType::Ok).await;
    }
}

pub trait AssertResult: Sized {
    fn assert_folders<'x>(
        self,
        expected: impl IntoIterator<Item = (&'x str, impl IntoIterator<Item = &'x str>)>,
        match_all: bool,
    ) -> Self;

    fn assert_response_code(self, code: &str) -> Self;
    fn assert_contains(self, text: &str) -> Self;
    fn assert_contains_any(self, expected_texts: &[&str]) -> Self;
    fn assert_not_contains(self, expected_text: &str) -> Self;
    fn assert_count(self, text: &str, occurrences: usize) -> Self;
    fn assert_equals(self, text: &str) -> Self;
    fn into_response_code(self) -> String;
    fn into_highest_modseq(self) -> String;
    fn into_uid_validity(self) -> String;
    fn into_append_uid(self) -> String;
    fn into_copy_uid(self) -> String;
    fn into_modseq(self) -> String;
}

impl AssertResult for Vec<String> {
    fn assert_folders<'x>(
        self,
        expected: impl IntoIterator<Item = (&'x str, impl IntoIterator<Item = &'x str>)>,
        match_all: bool,
    ) -> Self {
        let mut match_count = 0;
        'outer: for (mailbox_name, flags) in expected.into_iter() {
            for result in self.iter() {
                if result.contains(&format!("\"{}\"", mailbox_name)) {
                    for flag in flags {
                        if !flag.is_empty() && !result.contains(flag) {
                            panic!("Expected mailbox {} to have flag {}", mailbox_name, flag);
                        }
                    }
                    match_count += 1;
                    continue 'outer;
                }
            }
            panic!("Mailbox {} is not present.", mailbox_name);
        }
        if match_all && match_count != self.len() - 1 {
            panic!(
                "Expected {} mailboxes, but got {}: {:?}",
                match_count,
                self.len() - 1,
                self.iter().collect::<Vec<_>>()
            );
        }
        self
    }

    fn assert_response_code(self, code: &str) -> Self {
        if !self.last().unwrap().contains(&format!("[{}]", code)) {
            panic!(
                "Response code {:?} not found, got {:?}",
                code,
                self.last().unwrap()
            );
        }
        self
    }

    fn assert_contains(self, expected_text: &str) -> Self {
        if self.iter().any(|line| line.contains(expected_text)) {
            self
        } else {
            panic!("Expected {:?} but got {}.", expected_text, self.join("\n"));
        }
    }

    fn assert_contains_any(self, expected_texts: &[&str]) -> Self {
        if self
            .iter()
            .any(|line| expected_texts.iter().any(|text| line.contains(text)))
        {
            self
        } else {
            panic!(
                "Expected any of {:?} but got {}.",
                expected_texts,
                self.join("\n")
            );
        }
    }

    fn assert_not_contains(self, expected_text: &str) -> Self {
        if !self.iter().any(|line| line.contains(expected_text)) {
            self
        } else {
            panic!(
                "Not expecting {:?} but got it {}.",
                expected_text,
                self.join("\n")
            );
        }
    }

    fn assert_count(self, text: &str, occurrences: usize) -> Self {
        assert_eq!(
            self.iter().filter(|l| l.contains(text)).count(),
            occurrences,
            "Expected {} occurrences of {:?}, found {} in {:?}.",
            occurrences,
            text,
            self.iter().filter(|l| l.contains(text)).count(),
            self
        );
        self
    }

    fn assert_equals(self, text: &str) -> Self {
        for line in &self {
            if line == text {
                return self;
            }
        }
        panic!("Expected response to be {:?}, got {:?}", text, self);
    }

    fn into_response_code(self) -> String {
        if let Some((_, code)) = self.last().unwrap().split_once('[')
            && let Some((code, _)) = code.split_once(']')
        {
            return code.to_string();
        }
        panic!("No response code found in {:?}", self.last().unwrap());
    }

    fn into_append_uid(self) -> String {
        if let Some((_, code)) = self.last().unwrap().split_once("[APPENDUID ")
            && let Some((code, _)) = code.split_once(']')
            && let Some((_, uid)) = code.split_once(' ')
        {
            return uid.to_string();
        }
        panic!("No APPENDUID found in {:?}", self.last().unwrap());
    }

    fn into_copy_uid(self) -> String {
        for line in &self {
            if let Some((_, code)) = line.split_once("[COPYUID ")
                && let Some((code, _)) = code.split_once(']')
                && let Some((_, uid)) = code.rsplit_once(' ')
            {
                return uid.to_string();
            }
        }
        panic!("No COPYUID found in {:?}", self);
    }

    fn into_highest_modseq(self) -> String {
        for line in &self {
            if let Some((_, value)) = line.split_once("HIGHESTMODSEQ ") {
                if let Some((value, _)) = value.split_once(']') {
                    return value.to_string();
                } else if let Some((value, _)) = value.split_once(')') {
                    return value.to_string();
                } else {
                    panic!("No HIGHESTMODSEQ delimiter found in {:?}", line);
                }
            }
        }
        panic!("No HIGHESTMODSEQ entries found in {:?}", self);
    }

    fn into_modseq(self) -> String {
        for line in &self {
            if let Some((_, value)) = line.split_once("MODSEQ (") {
                if let Some((value, _)) = value.split_once(')') {
                    return value.to_string();
                } else {
                    panic!("No MODSEQ delimiter found in {:?}", line);
                }
            }
        }
        panic!("No MODSEQ entries found in {:?}", self);
    }

    fn into_uid_validity(self) -> String {
        for line in &self {
            if let Some((_, value)) = line.split_once("UIDVALIDITY ") {
                if let Some((value, _)) = value.split_once(']') {
                    return value.to_string();
                } else if let Some((value, _)) = value.split_once(')') {
                    return value.to_string();
                } else {
                    panic!("No UIDVALIDITY delimiter found in {:?}", line);
                }
            }
        }
        panic!("No UIDVALIDITY entries found in {:?}", self);
    }
}
