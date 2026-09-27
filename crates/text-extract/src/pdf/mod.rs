/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod content;
mod crypt;
mod decode;
mod document;
mod filter;
mod font;
mod forms;
mod layout;
mod lexer;
mod object;
mod objstm;
mod pages;
mod repair;
mod seek;
mod source;
mod tables;
mod text_string;
mod xref;

#[cfg(test)]
mod tests;

use self::{
    content::Interpreter,
    document::{DocScratch, Document, OpenError},
    forms::FormScratch,
    pages::{Pages, Visited},
};
use crate::{Error, Failure, Limits, output::Output, xml::stream::Budget};
use memchr::memmem;

const SIGNATURE: &[u8] = b"%PDF-";
const SIGNATURE_WINDOW: usize = 1024;
const ZIP_LOCAL_HEADER: &[u8] = b"PK\x03\x04";
const MAX_RETAINED_SCRATCH: usize = 1 << 20;

#[derive(Default)]
pub(crate) struct Scratch {
    document: DocScratch,
    visited: Visited,
    contents: Vec<u8>,
    interpreter: Interpreter,
    forms: FormScratch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) used_bytes: u64,
    pub(crate) truncated: bool,
}

pub(crate) fn is_pdf(data: &[u8]) -> bool {
    !data.starts_with(ZIP_LOCAL_HEADER)
        && memmem::find(data.get(..SIGNATURE_WINDOW).unwrap_or(data), SIGNATURE).is_some()
}

impl Scratch {
    fn shrink(&mut self) {
        self.document.shrink(MAX_RETAINED_SCRATCH);
        self.visited.shrink(MAX_RETAINED_SCRATCH);
        self.contents.clear();
        self.contents.shrink_to(MAX_RETAINED_SCRATCH);
        self.interpreter.shrink();
        self.forms.shrink();
    }
}

pub(crate) fn extract(
    data: &[u8],
    scratch: &mut Scratch,
    limits: &Limits,
    out: &mut Output<'_>,
) -> Result<Summary, Failure> {
    let budget = Budget {
        part_bytes: limits.max_part_bytes,
        total_bytes: limits.max_total_bytes,
        parts: usize::MAX,
        used_bytes: 0,
        used_parts: 0,
        truncated: false,
    };
    let Scratch {
        document: document_scratch,
        visited,
        contents,
        interpreter,
        forms,
    } = scratch;
    let result = match Document::open(data, document_scratch, budget, limits.max_pdf_objects) {
        Ok(document) => {
            interpreter.begin_document();
            for page in Pages::new(&document, visited) {
                if out.is_full() {
                    break;
                }
                let (content, _) = page.contents(&document, contents);
                let media_box = page.media_box(&document);
                interpreter.run_page(&document, content, page.resources, media_box, out);
                forms::annotations(&document, &page, interpreter.layout(), out, forms);
                interpreter.layout().end_page(out);
            }
            if !out.is_full() {
                forms::acroform(&document, interpreter.layout(), out, forms, visited);
                interpreter.layout().end_page(out);
            }
            let budget = document.finish();
            Ok(Summary {
                used_bytes: budget.used_bytes,
                truncated: budget.truncated,
            })
        }
        Err(failure) => Err(Failure {
            error: match failure.error {
                OpenError::Encrypted | OpenError::Unusable => Error::Unsupported,
            },
            bytes_decompressed: failure.used_bytes,
        }),
    };
    scratch.shrink();
    result
}
