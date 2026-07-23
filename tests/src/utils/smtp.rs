/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, ReadHalf, WriteHalf},
    net::TcpStream,
};

pub struct SmtpConnection {
    reader: Lines<BufReader<ReadHalf<TcpStream>>>,
    writer: WriteHalf<TcpStream>,
}

impl SmtpConnection {
    pub async fn ingest_with_code(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &str,
        code: u8,
    ) -> Vec<String> {
        self.mail_from(from, 2).await;
        for recipient in recipients {
            self.rcpt_to(recipient, 2).await;
        }
        self.data(3).await;
        let result = self.data_bytes(message, recipients.len(), code).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        result
    }

    pub async fn ingest(&mut self, from: &str, recipients: &[&str], message: &str) {
        self.ingest_with_code(from, recipients, message, 2).await;
    }

    pub async fn ingest_chunked(
        &mut self,
        from: &str,
        recipients: &[&str],
        message: &str,
        chunk_size: usize,
    ) {
        self.mail_from(from, 2).await;
        for recipient in recipients {
            self.rcpt_to(recipient, 2).await;
        }
        for chunk in message.as_bytes().chunks(chunk_size) {
            self.bdat(std::str::from_utf8(chunk).unwrap(), 2).await;
        }
        self.bdat_last("", recipients.len(), 2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    pub async fn connect() -> Self {
        SmtpConnection::connect_port(11200).await
    }

    pub async fn connect_port(port: u16) -> Self {
        let (reader, writer) = tokio::io::split(
            TcpStream::connect(&format!("127.0.0.1:{port}"))
                .await
                .unwrap(),
        );
        let mut conn = SmtpConnection {
            reader: BufReader::new(reader).lines(),
            writer,
        };
        conn.read(1, 2).await;
        conn.lhlo().await;
        conn
    }

    pub async fn lhlo(&mut self) -> Vec<String> {
        self.send("LHLO localhost").await;
        self.read(1, 2).await
    }

    pub async fn mail_from(&mut self, sender: &str, code: u8) -> Vec<String> {
        self.send(&format!("MAIL FROM:<{}>", sender)).await;
        self.read(1, code).await
    }

    pub async fn rcpt_to(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("RCPT TO:<{}>", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn vrfy(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("VRFY {}", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn expn(&mut self, rcpt: &str, code: u8) -> Vec<String> {
        self.send(&format!("EXPN {}", rcpt)).await;
        self.read(1, code).await
    }

    pub async fn data(&mut self, code: u8) -> Vec<String> {
        self.send("DATA").await;
        self.read(1, code).await
    }

    pub async fn data_bytes(
        &mut self,
        message: &str,
        num_responses: usize,
        code: u8,
    ) -> Vec<String> {
        self.send_raw(message).await;
        self.send_raw("\r\n.\r\n").await;
        self.read(num_responses, code).await
    }

    pub async fn bdat(&mut self, chunk: &str, code: u8) -> Vec<String> {
        self.send_raw(&format!("BDAT {}\r\n{}", chunk.len(), chunk))
            .await;
        self.read(1, code).await
    }

    pub async fn bdat_last(&mut self, chunk: &str, num_responses: usize, code: u8) -> Vec<String> {
        self.send_raw(&format!("BDAT {} LAST\r\n{}", chunk.len(), chunk))
            .await;
        self.read(num_responses, code).await
    }

    pub async fn rset(&mut self) -> Vec<String> {
        self.send("RSET").await;
        self.read(1, 2).await
    }

    pub async fn noop(&mut self) -> Vec<String> {
        self.send("NOOP").await;
        self.read(1, 2).await
    }

    pub async fn quit(&mut self) -> Vec<String> {
        self.send("QUIT").await;
        self.read(1, 2).await
    }

    pub async fn read(&mut self, mut num_responses: usize, code: u8) -> Vec<String> {
        let mut lines = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(1500), self.reader.next_line()).await {
                Ok(Ok(Some(line))) => {
                    let is_done = line.as_bytes()[3] == b' ';
                    //let c = println!("<- {:?}", line);
                    lines.push(line);
                    if is_done {
                        num_responses -= 1;
                        if num_responses != 0 {
                            continue;
                        }

                        if code != u8::MAX {
                            for line in &lines {
                                if line.as_bytes()[0] - b'0' != code {
                                    panic!("Expected completion code {}, got {:?}.", code, lines);
                                }
                            }
                        }
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
        self.writer.flush().await.unwrap();
    }

    pub async fn send_raw(&mut self, text: &str) {
        //let c = println!("-> {:?}", text);
        self.writer.write_all(text.as_bytes()).await.unwrap();
    }
}
