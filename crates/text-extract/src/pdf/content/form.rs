/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    Frame, Interpreter, MAX_FORM_DEPTH, MAX_MARKED_DEPTH, MAX_TEXTLESS, ops::Operand, state::Matrix,
};
use crate::{
    output::Output,
    pdf::{
        decode::DecodeOutcome,
        document::Document,
        layout::GlyphCounts,
        object::{Name, ObjRef, Object},
        text_string::decode_text_string,
    },
};

const MATRIX_LEN: usize = 6;

impl Interpreter {
    pub(super) fn form<'d>(
        &mut self,
        doc: &'d Document<'_>,
        frame: &Frame<'d>,
        name: Name<'_>,
        out: &mut Output<'_>,
    ) {
        if frame.depth >= MAX_FORM_DEPTH || doc.exhausted() {
            return;
        }
        let Some(id) = self.resources.xobject(doc, frame.resources, name) else {
            return;
        };
        let key = (
            id,
            self.state.fingerprint(&self.text_matrix, &self.line_matrix),
        );
        if self.textless.contains(&id)
            || self.suppressed.contains(&key)
            || self.ancestors.contains(&id)
        {
            return;
        }
        let Object::Stream(stream) = doc.get(id) else {
            return;
        };
        if !doc
            .get_name(stream.dict, b"Subtype")
            .is_some_and(|subtype| subtype.is(b"Form"))
        {
            return;
        }
        let matrix = doc
            .get_array(stream.dict, b"Matrix")
            .and_then(|array| {
                let mut values = [0f64; MATRIX_LEN];
                let mut count = 0;
                for (slot, value) in values.iter_mut().zip(doc.array_iter(array)) {
                    *slot = value.as_f64()?;
                    count += 1;
                }
                (count == MATRIX_LEN).then(|| Matrix::new(values))
            })
            .unwrap_or(Matrix::IDENTITY);
        let resources = doc.get_dict(stream.dict, b"Resources").or(frame.resources);
        let mut buf = self.pooled_buffer();
        let (data, outcome) = doc.stream_bytes(stream, &mut buf);
        if !outcome.is_failure() {
            let saved = (self.state, self.text_matrix, self.line_matrix);
            let mark = self.stack.enter();
            self.state.ctm = matrix.then(&self.state.ctm);
            let before = self.layout.counts();
            self.ancestors.push(id);
            self.run(doc, data, resources, frame.depth + 1, out);
            self.ancestors.pop();
            self.stack.leave(mark);
            (self.state, self.text_matrix, self.line_matrix) = saved;
            self.continued = false;
            if outcome == DecodeOutcome::Complete && !out.is_full() && !doc.exhausted() {
                self.remember_textless(key, before);
            }
        }
        buf.clear();
        self.pool.push(buf);
    }

    fn remember_textless(&mut self, key: (ObjRef, u64), before: GlyphCounts) {
        let after = self.layout.counts();
        if after.candidates == before.candidates {
            if self.textless.len() < MAX_TEXTLESS {
                self.textless.insert(key.0);
            }
        } else if after.placed == before.placed
            && !before.in_actual_text
            && self.suppressed.len() < MAX_TEXTLESS
        {
            self.suppressed.insert(key);
        }
    }

    fn pooled_buffer(&mut self) -> Vec<u8> {
        self.pool
            .iter()
            .enumerate()
            .max_by_key(|(_, buffer)| buffer.capacity())
            .map(|(index, _)| index)
            .map(|index| self.pool.swap_remove(index))
            .unwrap_or_default()
    }

    pub(super) fn begin_marked(&mut self, frame: &mut Frame<'_>, actual: bool) {
        if self.marked.len() >= MAX_MARKED_DEPTH {
            frame.marked_overflow = frame.marked_overflow.saturating_add(1);
        } else {
            self.marked.push(actual);
        }
    }

    pub(super) fn begin_marked_properties<'d>(
        &mut self,
        doc: &'d Document<'_>,
        frame: &mut Frame<'d>,
        properties: Operand<'_>,
    ) {
        let value = match properties {
            Operand::Dict(dict) => dict.get(b"ActualText").map(|value| doc.resolve(value)),
            Operand::Name(name) => self.resources.actual_text(doc, frame.resources, name),
            _ => None,
        };
        let mut actual = false;
        if let Some(Object::Str(value)) = value {
            self.actual_text.clear();
            decode_text_string(&doc.string(value), &mut self.actual_text);
            actual = self.layout.begin_actual_text(&self.actual_text);
        }
        self.begin_marked(frame, actual);
    }

    pub(super) fn end_marked(&mut self, frame: &mut Frame<'_>, out: &mut Output<'_>) {
        if frame.marked_overflow > 0 {
            frame.marked_overflow -= 1;
        } else if self.marked.len() > frame.marked_base && self.marked.pop() == Some(true) {
            self.layout.end_actual_text(out);
        }
    }
}
