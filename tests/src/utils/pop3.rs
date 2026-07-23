/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose};
use rustls_pki_types::ServerName;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;
use utils::tls::build_tls_connector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseType {
    Ok,
    Multiline,
    Err,
}

pub struct Pop3Connection {
    reader: Lines<BufReader<ReadHalf<TlsStream<TcpStream>>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
}

impl Pop3Connection {
    pub async fn connect() -> Self {
        let (reader, writer) = tokio::io::split(
            build_tls_connector(true)
                .unwrap()
                .connect(
                    ServerName::try_from("pop3.example.org").unwrap().to_owned(),
                    TcpStream::connect("127.0.0.1:4110").await.unwrap(),
                )
                .await
                .unwrap(),
        );

        let mut conn = Pop3Connection {
            reader: BufReader::new(reader).lines(),
            writer,
        };

        conn.assert_read(ResponseType::Ok).await;
        conn
    }

    pub async fn authenticate(&mut self, user: &str, pass: &str) {
        let creds = general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"));
        self.send(&format!("AUTH PLAIN {creds}")).await;
        self.assert_read(ResponseType::Ok).await;
    }

    pub async fn assert_read(&mut self, rt: ResponseType) -> Vec<String> {
        let lines = self.read(matches!(rt, ResponseType::Multiline)).await;
        if lines.last().unwrap().starts_with(match rt {
            ResponseType::Ok => "+OK",
            ResponseType::Multiline => ".",
            ResponseType::Err => "-ERR",
        }) {
            lines
        } else {
            panic!("Expected {:?} from server but got: {:?}", rt, lines);
        }
    }

    pub async fn read(&mut self, is_multiline: bool) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = (!is_multiline && line.starts_with("+OK"))
                        || (is_multiline && line == ".")
                        || line.starts_with("-ERR");
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

    pub async fn send(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
        self.writer.write_all(b"\r\n").await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}
