/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use imap_proto::ResponseType;
use rustls_pki_types::ServerName;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;
use utils::tls::build_tls_connector;

pub struct SieveConnection {
    reader: Lines<BufReader<ReadHalf<TlsStream<TcpStream>>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

impl SieveConnection {
    pub async fn connect() -> Self {
        let (reader, writer) = tokio::io::split(
            build_tls_connector(true)
                .unwrap()
                .connect(
                    ServerName::try_from("imap.example.org").unwrap().to_owned(),
                    TcpStream::connect("127.0.0.1:4190").await.unwrap(),
                )
                .await
                .unwrap(),
        );
        SieveConnection {
            reader: BufReader::new(reader).lines(),
            writer,
        }
    }

    pub async fn authenticate(&mut self, user: &str, pass: &str) {
        let creds = general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        self.send(&format!(
            "AUTHENTICATE PLAIN {{{}+}}\r\n{creds}",
            creds.len()
        ))
        .await;
        self.assert_read(ResponseType::Ok).await;
    }

    pub async fn assert_read(&mut self, rt: ResponseType) -> Vec<String> {
        let lines = self.read().await;
        let mut buf = Vec::with_capacity(10);
        rt.serialize(&mut buf);
        if lines
            .last()
            .unwrap()
            .starts_with(&String::from_utf8(buf).unwrap())
        {
            lines
        } else {
            panic!("Expected {:?} from server but got: {:?}", rt, lines);
        }
    }

    pub async fn read(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done =
                        line.starts_with("OK") || line.starts_with("NO") || line.starts_with("BYE");
                    //println!("<- {:?}", line);
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

    pub async fn send(&mut self, text: &str) {
        //println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }

    pub async fn send_literal(&mut self, text: &str, literal: &str) {
        self.send(&format!("{}{{{}+}}\r\n{}", text, literal.len(), literal))
            .await;
    }
}
