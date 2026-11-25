/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub const MAX_KQL_DEPTH: usize = 8;
pub const MAX_KQL_TERMS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KqlProperty {
    From,
    To,
    Cc,
    Bcc,
    Participants,
    Recipients,
    Subject,
    Body,
    Attachment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KqlNode<'a> {
    And,
    Or,
    Not,
    End,
    Term {
        property: Option<KqlProperty>,
        value: &'a str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreeText<'a> {
    Keywords(&'a str),
    Query(Vec<KqlNode<'a>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lexeme<'a> {
    Open,
    Close,
    And,
    Or,
    Not,
    Property(Option<KqlProperty>),
    Value(&'a str),
}

struct Lexer<'a> {
    rest: &'a str,
}

struct TooDeep;

struct Parser<'a, F> {
    lexer: Lexer<'a>,
    peeked: Option<Lexeme<'a>>,
    nodes: Vec<KqlNode<'a>>,
    terms: usize,
    structured: bool,
    accept: F,
}

impl<'a> FreeText<'a> {
    pub fn parse(text: &'a str, accept: impl Fn(&str) -> bool) -> Self {
        let mut parser = Parser {
            lexer: Lexer { rest: text },
            peeked: None,
            nodes: Vec::new(),
            terms: 0,
            structured: false,
            accept,
        };
        match parser.or_expr(0) {
            Ok(_) if parser.structured => FreeText::Query(parser.nodes),
            Ok(_) | Err(TooDeep) => FreeText::Keywords(text),
        }
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Lexeme<'a>;

    fn next(&mut self) -> Option<Lexeme<'a>> {
        let text = self.rest.trim_start();
        if let Some(rest) = text.strip_prefix('(') {
            self.rest = rest;
            return Some(Lexeme::Open);
        }
        if let Some(rest) = text.strip_prefix(')') {
            self.rest = rest;
            return Some(Lexeme::Close);
        }
        if let Some(body) = text.strip_prefix('"') {
            let (phrase, rest) = body
                .split_once('"')
                .and_then(|(inner, _)| text.split_at_checked(inner.len() + 2))
                .unwrap_or((body, ""));
            self.rest = rest;
            return Some(Lexeme::Value(phrase));
        }
        let (run, rest) = text
            .find(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '"'))
            .and_then(|end| text.split_at_checked(end))
            .unwrap_or((text, ""));
        if run.is_empty() {
            return None;
        }
        self.rest = rest;
        if let Some(keyword) = hashify::map!(
            run.as_bytes(),
            Lexeme<'static>,
            "AND" => Lexeme::And,
            "OR" => Lexeme::Or,
            "NOT" => Lexeme::Not,
        ) {
            return Some(*keyword);
        }
        if let Some((name, _)) = run.split_once(':')
            && let Some(property) = hashify::map_ignore_case!(
                name.as_bytes(),
                Option<KqlProperty>,
                "from" => Some(KqlProperty::From),
                "to" => Some(KqlProperty::To),
                "cc" => Some(KqlProperty::Cc),
                "bcc" => Some(KqlProperty::Bcc),
                "participants" => Some(KqlProperty::Participants),
                "recipients" => Some(KqlProperty::Recipients),
                "subject" => Some(KqlProperty::Subject),
                "body" => Some(KqlProperty::Body),
                "attachment" => Some(KqlProperty::Attachment),
                "attachmentnames" => Some(KqlProperty::Attachment),
                "category" => None,
                "folderid" => None,
                "hasattachment" => None,
                "importance" => None,
                "isread" => None,
                "itemclass" => None,
                "kind" => None,
                "received" => None,
                "sent" => None,
                "size" => None,
            )
        {
            self.rest = text.get(name.len() + 1..).unwrap_or(rest);
            return Some(Lexeme::Property(*property));
        }
        Some(Lexeme::Value(run))
    }
}

impl<'a, F: Fn(&str) -> bool> Parser<'a, F> {
    fn lex(&mut self) -> Option<Lexeme<'a>> {
        if self.terms < MAX_KQL_TERMS {
            self.lexer.next()
        } else {
            None
        }
    }

    fn peek(&mut self) -> Option<Lexeme<'a>> {
        if self.peeked.is_none() {
            self.peeked = self.lex();
        }
        self.peeked
    }

    fn advance(&mut self) -> Option<Lexeme<'a>> {
        self.peeked.take().or_else(|| self.lex())
    }

    fn group(&mut self, start: usize, operands: usize, op: KqlNode<'a>) {
        if operands > 1 {
            self.nodes.insert(start, op);
            self.nodes.push(KqlNode::End);
        }
    }

    fn or_expr(&mut self, depth: usize) -> Result<bool, TooDeep> {
        let start = self.nodes.len();
        let mut operands = 0;
        loop {
            if self.and_expr(depth)? {
                operands += 1;
            }
            if self.peek() != Some(Lexeme::Or) {
                break;
            }
            self.advance();
            self.structured = true;
        }
        self.group(start, operands, KqlNode::Or);
        Ok(operands > 0)
    }

    fn and_expr(&mut self, depth: usize) -> Result<bool, TooDeep> {
        let start = self.nodes.len();
        let mut operands = 0;
        loop {
            match self.peek() {
                None | Some(Lexeme::Or) => break,
                Some(Lexeme::Close) if depth > 0 => break,
                Some(Lexeme::Close) => {
                    self.advance();
                }
                Some(Lexeme::And) => {
                    self.advance();
                    self.structured = true;
                }
                Some(_) => {
                    if self.unary(depth)? {
                        operands += 1;
                    }
                }
            }
        }
        self.group(start, operands, KqlNode::And);
        Ok(operands > 0)
    }

    fn unary(&mut self, depth: usize) -> Result<bool, TooDeep> {
        if matches!(
            self.peek(),
            None | Some(Lexeme::And | Lexeme::Or | Lexeme::Close)
        ) {
            return Ok(false);
        }
        match self.advance() {
            Some(Lexeme::Not) => {
                self.structured = true;
                let depth = nested(depth)?;
                self.nodes.push(KqlNode::Not);
                if self.unary(depth)? {
                    self.nodes.push(KqlNode::End);
                    Ok(true)
                } else {
                    self.nodes.pop();
                    Ok(false)
                }
            }
            Some(Lexeme::Open) => {
                self.structured = true;
                let emitted = self.or_expr(nested(depth)?)?;
                if self.peek() == Some(Lexeme::Close) {
                    self.advance();
                }
                Ok(emitted)
            }
            Some(Lexeme::Property(property)) => {
                self.structured = true;
                match self.peek() {
                    Some(Lexeme::Value(value)) => {
                        self.advance();
                        Ok(property.is_some_and(|property| self.term(Some(property), value)))
                    }
                    _ => Ok(false),
                }
            }
            Some(Lexeme::Value(value)) => Ok(self.term(None, value)),
            Some(Lexeme::And | Lexeme::Or | Lexeme::Close) | None => Ok(false),
        }
    }

    fn term(&mut self, property: Option<KqlProperty>, value: &'a str) -> bool {
        if !(self.accept)(value) {
            return false;
        }
        self.terms += 1;
        self.nodes.push(KqlNode::Term { property, value });
        true
    }
}

fn nested(depth: usize) -> Result<usize, TooDeep> {
    let depth = depth + 1;
    if depth > MAX_KQL_DEPTH {
        Err(TooDeep)
    } else {
        Ok(depth)
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/exchange-proto/src/eas/kql/tests.rs"]
mod tests;
