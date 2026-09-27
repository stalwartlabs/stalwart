/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod form;
mod inline;
mod ops;
mod resources;
mod state;
mod text;

use self::{
    ops::{Op, Operand, Operands},
    resources::{Lookup, ResourceCache},
    state::{GraphicsState, Matrix, StateStack, finite},
};
use super::{
    document::Document,
    font::FontCache,
    layout::Layout,
    lexer::{Lexer, Token},
    object::{Dict, Name, ObjRef, Object, Str},
};
use crate::output::Output;
use std::collections::HashSet;

pub(crate) const MAX_FORM_DEPTH: usize = 16;
pub(crate) const MAX_CONSECUTIVE_ERRORS: usize = 1024;
pub(crate) const MAX_MARKED_DEPTH: usize = 1024;
const MAX_TEXTLESS: usize = 1 << 16;
const MAX_RETAINED: usize = 1 << 20;
const MAX_POOLED: usize = 2;

#[derive(Default)]
pub(crate) struct Interpreter {
    fonts: FontCache,
    resources: ResourceCache,
    textless: HashSet<ObjRef>,
    suppressed: HashSet<(ObjRef, u64)>,
    ancestors: Vec<ObjRef>,
    stack: StateStack,
    state: GraphicsState,
    text_matrix: Matrix,
    line_matrix: Matrix,
    continued: bool,
    marked: Vec<bool>,
    pool: Vec<Vec<u8>>,
    font_buf: Vec<u8>,
    glyph_text: String,
    string_buf: Vec<u8>,
    actual_text: String,
    layout: Layout,
}

struct Frame<'d> {
    resources: Option<Dict<'d>>,
    depth: usize,
    marked_base: usize,
    marked_overflow: usize,
    inline: inline::Markers,
}

impl Default for Matrix {
    fn default() -> Self {
        Matrix::IDENTITY
    }
}

impl Interpreter {
    pub(crate) fn begin_document(&mut self) {
        self.fonts.clear();
        self.resources.clear();
        self.textless.clear();
        self.suppressed.clear();
    }

    pub(crate) fn shrink(&mut self) {
        self.fonts.shrink();
        self.resources.shrink();
        self.textless = HashSet::new();
        self.suppressed = HashSet::new();
        self.stack.shrink();
        self.pool.truncate(MAX_POOLED);
        for buffer in self
            .pool
            .iter_mut()
            .chain(std::iter::once(&mut self.font_buf))
        {
            buffer.clear();
            buffer.shrink_to(MAX_RETAINED);
        }
        self.glyph_text = String::new();
        self.string_buf = Vec::new();
        self.actual_text = String::new();
        self.layout.shrink();
    }

    pub(crate) fn layout(&mut self) -> &mut Layout {
        &mut self.layout
    }

    pub(crate) fn run_page<'d>(
        &mut self,
        doc: &'d Document<'_>,
        content: &[u8],
        resources: Option<Dict<'d>>,
        media_box: Option<[f64; 4]>,
        out: &mut Output<'_>,
    ) {
        self.layout.begin_page(media_box);
        self.suppressed.clear();
        self.state = GraphicsState::default();
        self.stack.clear();
        self.text_matrix = Matrix::IDENTITY;
        self.line_matrix = Matrix::IDENTITY;
        self.continued = false;
        self.marked.clear();
        self.ancestors.clear();
        self.run(doc, content, resources, 0, out);
        self.fonts.end_page();
    }

    fn run<'d>(
        &mut self,
        doc: &'d Document<'_>,
        content: &[u8],
        resources: Option<Dict<'d>>,
        depth: usize,
        out: &mut Output<'_>,
    ) {
        let mut frame = Frame {
            resources,
            depth,
            marked_base: self.marked.len(),
            marked_overflow: 0,
            inline: inline::Markers::default(),
        };
        let mut lexer = Lexer::new(content);
        let mut operands = Operands::default();
        let mut errors = 0usize;
        while !out.is_full() && errors < MAX_CONSECUTIVE_ERRORS {
            let before = lexer.pos();
            let Some(token) = lexer.next() else {
                break;
            };
            match token {
                Token::Int(value) => operands.push(Operand::Number(value as f64)),
                Token::Real(value) => operands.push(Operand::Number(finite(value))),
                Token::Name(raw) => operands.push(Operand::Name(Name::new(raw))),
                Token::Literal(raw) => operands.push(Operand::Str(Str::literal(raw, None))),
                Token::Hex(raw) => operands.push(Operand::Str(Str::hex(raw, None))),
                Token::ArrayOpen | Token::DictOpen => {
                    lexer.set_pos(before);
                    match Object::read(&mut lexer, None) {
                        Some(object) => operands.push(Operand::from_object(object)),
                        None => {
                            lexer.next();
                            errors += 1;
                        }
                    }
                }
                Token::Keyword(b"true" | b"false" | b"null") => operands.push(Operand::Other),
                Token::Keyword(b"obj" | b"endobj" | b"endstream") => break,
                Token::Keyword(keyword) => {
                    let op = Op::parse(keyword);
                    if op != Op::Unknown
                        && self.execute(op, &operands, &mut lexer, doc, &mut frame, out)
                    {
                        errors = 0;
                    } else {
                        errors += 1;
                    }
                    operands.clear();
                }
                Token::ArrayClose
                | Token::DictClose
                | Token::BraceOpen
                | Token::BraceClose
                | Token::Error => errors += 1,
            }
        }
        while self.marked.len() > frame.marked_base {
            if self.marked.pop() == Some(true) {
                self.layout.end_actual_text(out);
            }
        }
    }

    fn execute<'d>(
        &mut self,
        op: Op,
        operands: &Operands<'_>,
        lexer: &mut Lexer<'_>,
        doc: &'d Document<'_>,
        frame: &mut Frame<'d>,
        out: &mut Output<'_>,
    ) -> bool {
        match op {
            Op::Save => self.stack.save(&self.state),
            Op::Restore => self.stack.restore(&mut self.state),
            Op::Concat => {
                let Some(values) = operands.numbers::<6>() else {
                    return false;
                };
                self.state.ctm = Matrix::new(values).then(&self.state.ctm);
            }
            Op::SetState => {
                let Some([Operand::Name(name)]) = operands.last::<1>() else {
                    return false;
                };
                let lookup = Lookup {
                    doc,
                    fonts: &mut self.fonts,
                    buf: &mut self.font_buf,
                };
                if let Some((font, size)) = self.resources.state_font(lookup, frame.resources, name)
                {
                    self.state.text.font = font;
                    self.state.text.size = finite(size);
                }
            }
            Op::BeginText => {
                self.text_matrix = Matrix::IDENTITY;
                self.line_matrix = Matrix::IDENTITY;
                self.continued = false;
            }
            Op::EndText | Op::Ignored | Op::Unknown => {}
            Op::CharSpacing | Op::WordSpacing | Op::HorizontalScale | Op::Leading | Op::Rise => {
                let Some([value]) = operands.numbers::<1>() else {
                    return false;
                };
                let value = finite(value);
                let text = &mut self.state.text;
                match op {
                    Op::CharSpacing => text.char_spacing = value,
                    Op::WordSpacing => text.word_spacing = value,
                    Op::HorizontalScale => text.set_scale(value),
                    Op::Leading => text.leading = value,
                    _ => text.rise = value,
                }
            }
            Op::Font => {
                let Some([Operand::Name(name), Operand::Number(size)]) = operands.last::<2>()
                else {
                    return false;
                };
                let lookup = Lookup {
                    doc,
                    fonts: &mut self.fonts,
                    buf: &mut self.font_buf,
                };
                if let Some(font) = self.resources.font(lookup, frame.resources, name) {
                    self.state.text.font = font;
                }
                self.state.text.size = finite(size);
            }
            Op::MoveText | Op::MoveTextLeading => {
                let Some([x, y]) = operands.numbers::<2>() else {
                    return false;
                };
                if op == Op::MoveTextLeading {
                    self.state.text.leading = -finite(y);
                }
                self.line_matrix.translate(x, y);
                self.text_matrix = self.line_matrix;
                self.continued = false;
            }
            Op::TextMatrix => {
                let Some(values) = operands.numbers::<6>() else {
                    return false;
                };
                self.line_matrix = Matrix::new(values);
                self.text_matrix = self.line_matrix;
                self.continued = false;
            }
            Op::NextLine => self.next_line(),
            Op::Show | Op::NextLineShow => {
                let Some([Operand::Str(value)]) = operands.last::<1>() else {
                    return false;
                };
                if op == Op::NextLineShow {
                    self.next_line();
                }
                self.show_str(value, out);
            }
            Op::NextLineShowSpaced => {
                let Some(
                    [
                        Operand::Number(word),
                        Operand::Number(char),
                        Operand::Str(value),
                    ],
                ) = operands.last::<3>()
                else {
                    return false;
                };
                self.state.text.word_spacing = finite(word);
                self.state.text.char_spacing = finite(char);
                self.next_line();
                self.show_str(value, out);
            }
            Op::ShowArray => {
                let Some([Operand::Array(array)]) = operands.last::<1>() else {
                    return false;
                };
                self.show_array(array, out);
            }
            Op::XObject => {
                let Some([Operand::Name(name)]) = operands.last::<1>() else {
                    return false;
                };
                self.form(doc, frame, name, out);
            }
            Op::BeginImage => inline::skip(lexer, &mut frame.inline),
            Op::BeginMarked => self.begin_marked(frame, false),
            Op::BeginMarkedProperties => {
                let Some([_, properties]) = operands.last::<2>() else {
                    return false;
                };
                self.begin_marked_properties(doc, frame, properties);
            }
            Op::EndMarked => self.end_marked(frame, out),
        }
        true
    }

    fn next_line(&mut self) {
        self.line_matrix.translate(0.0, -self.state.text.leading);
        self.text_matrix = self.line_matrix;
        self.continued = false;
    }
}
