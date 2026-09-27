/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#![allow(dead_code)]

use flate2::{Compress, Compression, FlushCompress, Status};
use std::{collections::BTreeMap, fmt::Write as _};

pub const HEADER: &[u8] = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n";

#[derive(Debug, Clone, Copy)]
enum Slot {
    Offset(usize),
    Compressed(u32, u32),
    Free,
}

pub struct Pdf {
    pub data: Vec<u8>,
    pending: BTreeMap<u32, Slot>,
    previous: Option<usize>,
    sections: usize,
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut compressor = Compress::new(Compression::default(), true);
    let mut out = Vec::with_capacity(data.len() / 2 + 64);
    loop {
        out.reserve(data.len() / 2 + 1024);
        let consumed = compressor.total_in() as usize;
        let status = compressor
            .compress_vec(
                data.get(consumed..).unwrap_or_default(),
                &mut out,
                FlushCompress::Finish,
            )
            .unwrap_or_else(|err| panic!("zlib: {err}"));
        if status == Status::StreamEnd {
            return out;
        }
    }
}

pub fn run_length(data: &[u8]) -> Vec<u8> {
    const MAX_RUN: usize = 128;
    const REPEAT_BASE: usize = 257;
    let mut out = Vec::with_capacity(data.len() / 64 + 16);
    let mut rest = data;
    while let Some(&first) = rest.first() {
        let repeated = rest
            .iter()
            .take(MAX_RUN)
            .take_while(|&&byte| byte == first)
            .count();
        if repeated > 1 {
            out.extend_from_slice(&[(REPEAT_BASE - repeated) as u8, first]);
            rest = rest.get(repeated..).unwrap_or_default();
        } else {
            let literal = rest.get(..1).unwrap_or_default();
            out.push(0);
            out.extend_from_slice(literal);
            rest = rest.get(1..).unwrap_or_default();
        }
    }
    out.push(128);
    out
}

impl Default for Pdf {
    fn default() -> Self {
        Pdf::new()
    }
}

impl Pdf {
    pub fn new() -> Self {
        Pdf::with_prefix(b"")
    }

    pub fn with_prefix(prefix: &[u8]) -> Self {
        let mut data = prefix.to_vec();
        data.extend_from_slice(HEADER);
        Pdf {
            data,
            pending: BTreeMap::new(),
            previous: None,
            sections: 0,
        }
    }

    pub fn offset(&self) -> usize {
        self.data.len()
    }

    pub fn raw(&mut self, bytes: &[u8]) -> &mut Self {
        self.data.extend_from_slice(bytes);
        self
    }

    pub fn object(&mut self, num: u32, body: &str) -> &mut Self {
        self.object_bytes(num, body.as_bytes())
    }

    pub fn object_bytes(&mut self, num: u32, body: &[u8]) -> &mut Self {
        self.pending.insert(num, Slot::Offset(self.data.len()));
        self.data
            .extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        self.data.extend_from_slice(body);
        self.data.extend_from_slice(b"\nendobj\n");
        self
    }

    pub fn free(&mut self, num: u32) -> &mut Self {
        self.pending.insert(num, Slot::Free);
        self
    }

    pub fn stream(&mut self, num: u32, dict: &str, data: &[u8]) -> &mut Self {
        self.stream_with_length(num, dict, data, &data.len().to_string())
    }

    pub fn flate_stream(&mut self, num: u32, dict: &str, data: &[u8]) -> &mut Self {
        let compressed = zlib(data);
        self.stream(num, &format!("{dict} /Filter /FlateDecode"), &compressed)
    }

    pub fn stream_with_length(
        &mut self,
        num: u32,
        dict: &str,
        data: &[u8],
        length: &str,
    ) -> &mut Self {
        let mut body = format!("<< {dict} /Length {length} >>\nstream\n").into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\nendstream");
        self.object_bytes(num, &body)
    }

    pub fn object_stream(
        &mut self,
        num: u32,
        members: &[(u32, &str)],
        compress: bool,
    ) -> &mut Self {
        let (dict, data) = self.object_stream_body(num, members);
        if compress {
            self.flate_stream(num, &dict, &data)
        } else {
            self.stream(num, &dict, &data)
        }
    }

    pub fn run_length_object_stream(&mut self, num: u32, members: &[(u32, &str)]) -> &mut Self {
        let (dict, data) = self.object_stream_body(num, members);
        self.stream(
            num,
            &format!("{dict} /Filter /RunLengthDecode"),
            &run_length(&data),
        )
    }

    fn object_stream_body(&mut self, num: u32, members: &[(u32, &str)]) -> (String, Vec<u8>) {
        let mut header = String::new();
        let mut body = Vec::new();
        for (index, (member, text)) in members.iter().enumerate() {
            let _ = write!(header, "{member} {} ", body.len());
            body.extend_from_slice(text.as_bytes());
            body.push(b' ');
            self.pending
                .insert(*member, Slot::Compressed(num, index as u32));
        }
        let first = header.len();
        let mut data = header.into_bytes();
        data.extend_from_slice(&body);
        (
            format!("/Type /ObjStm /N {} /First {first}", members.len()),
            data,
        )
    }

    fn entries(&mut self) -> Vec<(u32, Slot)> {
        let mut entries: Vec<(u32, Slot)> = std::mem::take(&mut self.pending).into_iter().collect();
        if self.sections == 0 && entries.first().is_none_or(|(num, _)| *num != 0) {
            entries.insert(0, (0, Slot::Free));
        }
        entries
    }

    pub fn xref_table(&mut self, trailer: &str) -> &mut Self {
        let entries = self.entries();
        let start = self.data.len();
        let mut text = String::from("xref\n");
        for run in entries.chunk_by(|left, right| right.0 == left.0 + 1) {
            let first = run.first().map_or(0, |(num, _)| *num);
            let _ = writeln!(text, "{first} {}", run.len());
            for (num, slot) in run {
                match slot {
                    Slot::Offset(offset) => {
                        let _ = write!(text, "{offset:010} 00000 n\r\n");
                    }
                    _ => {
                        let generation = if *num == 0 { 65535 } else { 0 };
                        let _ = write!(text, "0000000000 {generation:05} f\r\n");
                    }
                }
            }
        }
        let prev = self
            .previous
            .map(|prev| format!(" /Prev {prev}"))
            .unwrap_or_default();
        let _ = write!(
            text,
            "trailer\n<< /Size {} {trailer}{prev} >>\nstartxref\n{start}\n%%EOF\n",
            self.size_hint(&entries)
        );
        self.data.extend_from_slice(text.as_bytes());
        self.previous = Some(start);
        self.sections += 1;
        self
    }

    pub fn xref_stream(&mut self, num: u32, trailer: &str) -> &mut Self {
        let start = self.data.len();
        self.pending.insert(num, Slot::Offset(start));
        let entries = self.entries();
        let mut rows = Vec::new();
        let mut index = String::new();
        for (entry, slot) in &entries {
            let _ = write!(index, "{entry} 1 ");
            let (kind, second, third) = match slot {
                Slot::Offset(offset) => (1u8, *offset as u32, 0u16),
                Slot::Compressed(stream, position) => (2, *stream, *position as u16),
                Slot::Free => (0, 0, 0),
            };
            rows.push(kind);
            rows.extend_from_slice(&second.to_be_bytes());
            rows.extend_from_slice(&third.to_be_bytes());
        }
        let prev = self
            .previous
            .map(|prev| format!(" /Prev {prev}"))
            .unwrap_or_default();
        let compressed = zlib(&rows);
        let mut body = format!(
            "<< /Type /XRef /Size {} /W [1 4 2] /Index [{index}] /Filter /FlateDecode /Length {} {trailer}{prev} >>\nstream\n",
            self.size_hint(&entries),
            compressed.len()
        )
        .into_bytes();
        body.extend_from_slice(&compressed);
        body.extend_from_slice(b"\nendstream");
        self.data
            .extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        self.data.extend_from_slice(&body);
        self.data
            .extend_from_slice(format!("\nendobj\nstartxref\n{start}\n%%EOF\n").as_bytes());
        self.previous = Some(start);
        self.sections += 1;
        self
    }

    fn size_hint(&self, entries: &[(u32, Slot)]) -> u32 {
        entries.iter().map(|(num, _)| num + 1).max().unwrap_or(1)
    }

    pub fn build(&self) -> Vec<u8> {
        self.data.clone()
    }
}

pub struct Document {
    pub pages: Vec<Vec<u8>>,
    pub compress: bool,
    pub object_streams: bool,
    pub xref_stream: bool,
}

impl Document {
    pub fn new(pages: &[&[u8]]) -> Self {
        Document {
            pages: pages.iter().map(|page| page.to_vec()).collect(),
            compress: false,
            object_streams: false,
            xref_stream: false,
        }
    }

    pub fn content_bytes(&self) -> u64 {
        self.pages.iter().map(|page| page.len() as u64).sum()
    }

    pub fn build(&self) -> Vec<u8> {
        let mut pdf = Pdf::new();
        let count = self.pages.len() as u32;
        let kids: String = (0..count)
            .map(|index| format!("{} 0 R ", 3 + index * 2))
            .collect();
        let mut dicts = vec![
            (1u32, "<< /Type /Catalog /Pages 2 0 R >>".to_string()),
            (
                2,
                format!("<< /Type /Pages /Kids [{kids}] /Count {count} >>"),
            ),
        ];
        for index in 0..count {
            dicts.push((
                3 + index * 2,
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R >>",
                    4 + index * 2
                ),
            ));
        }
        if self.object_streams {
            let members: Vec<(u32, &str)> = dicts
                .iter()
                .map(|(num, text)| (*num, text.as_str()))
                .collect();
            pdf.object_stream(5 + count * 2, &members, self.compress);
        } else {
            for (num, text) in &dicts {
                pdf.object(*num, text);
            }
        }
        for (index, page) in self.pages.iter().enumerate() {
            let num = 4 + index as u32 * 2;
            if self.compress {
                pdf.flate_stream(num, "", page);
            } else {
                pdf.stream(num, "", page);
            }
        }
        if self.xref_stream || self.object_streams {
            pdf.xref_stream(6 + count * 2, "/Root 1 0 R");
        } else {
            pdf.xref_table("/Root 1 0 R");
        }
        pdf.build()
    }
}
