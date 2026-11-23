/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{path::Path, value::T};
use crate::{
    ews::{
        parser::{Child, ParseErrorKind, Parser, Result},
        schema::{ContainmentComparison, ContainmentMode},
    },
    xml::{XmlWriter, value::parse_hex_or_decimal},
};
use std::{borrow::Cow, ops::Range};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restriction<'a> {
    pub nodes: Vec<SearchNode<'a>>,
    pub children: Vec<NodeIdx>,
    pub root: NodeIdx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeIdx(u16);

impl NodeIdx {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompareOp {
    IsEqualTo,
    IsNotEqualTo,
    IsGreaterThan,
    IsGreaterThanOrEqualTo,
    IsLessThan,
    IsLessThanOrEqualTo,
}

impl CompareOp {
    pub const fn as_str(self) -> &'static str {
        match self {
            CompareOp::IsEqualTo => "IsEqualTo",
            CompareOp::IsNotEqualTo => "IsNotEqualTo",
            CompareOp::IsGreaterThan => "IsGreaterThan",
            CompareOp::IsGreaterThanOrEqualTo => "IsGreaterThanOrEqualTo",
            CompareOp::IsLessThan => "IsLessThan",
            CompareOp::IsLessThanOrEqualTo => "IsLessThanOrEqualTo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareRhs<'a> {
    Constant(Cow<'a, str>),
    Path(Path<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchNode<'a> {
    Exists(Path<'a>),
    Compare {
        op: CompareOp,
        path: Path<'a>,
        rhs: CompareRhs<'a>,
    },
    Contains {
        path: Path<'a>,
        value: Cow<'a, str>,
        mode: ContainmentMode,
        comparison: ContainmentComparison,
    },
    Excludes {
        path: Path<'a>,
        mask: u64,
    },
    Not(NodeIdx),
    And(Range<u16>),
    Or(Range<u16>),
    Near {
        distance: u32,
        ordered: bool,
        children: Range<u16>,
    },
}

#[derive(Clone, Copy)]
enum Compound {
    Not,
    And,
    Or,
    Near,
}

#[derive(Clone, Copy)]
enum Expr {
    Exists,
    Compare(CompareOp),
    Contains,
    Excludes,
    Compound(Compound),
}

fn expression(local: &str) -> Option<Expr> {
    hashify::map!(local.as_bytes(), Expr,
        "Exists" => Expr::Exists,
        "IsEqualTo" => Expr::Compare(CompareOp::IsEqualTo),
        "IsNotEqualTo" => Expr::Compare(CompareOp::IsNotEqualTo),
        "IsGreaterThan" => Expr::Compare(CompareOp::IsGreaterThan),
        "IsGreaterThanOrEqualTo" => Expr::Compare(CompareOp::IsGreaterThanOrEqualTo),
        "IsLessThan" => Expr::Compare(CompareOp::IsLessThan),
        "IsLessThanOrEqualTo" => Expr::Compare(CompareOp::IsLessThanOrEqualTo),
        "Contains" => Expr::Contains,
        "Excludes" => Expr::Excludes,
        "Not" => Expr::Compound(Compound::Not),
        "And" => Expr::Compound(Compound::And),
        "Or" => Expr::Compound(Compound::Or),
        "Near" => Expr::Compound(Compound::Near),
    )
    .copied()
}

struct Frame {
    kind: Compound,
    start: usize,
    distance: u32,
    ordered: bool,
}

impl<'a> Restriction<'a> {
    pub fn parse(p: &mut Parser<'a>) -> Result<Self> {
        let max_nodes = usize::from(p.limits.max_restriction_nodes).saturating_sub(1);
        let max_depth = usize::from(p.limits.max_restriction_depth);
        let mut nodes: Vec<SearchNode<'a>> = Vec::new();
        let mut children: Vec<NodeIdx> = Vec::new();
        let mut pending: Vec<NodeIdx> = Vec::new();
        let mut stack: Vec<Frame> = Vec::new();

        loop {
            let Some(child) = p.child()? else {
                let Some(frame) = stack.pop() else {
                    break;
                };
                let node = close_frame(p, &frame, &mut pending, &mut children)?;
                push_node(&mut nodes, &mut pending, node);
                continue;
            };

            let Some(expr) = expression(child.local) else {
                if let Some(frame) = stack.last_mut()
                    && matches!(frame.kind, Compound::Near)
                {
                    match child.local {
                        "Distance" => {
                            p.expect_types(&child)?;
                            frame.distance = p.value("Distance")?;
                            continue;
                        }
                        "Ordered" => {
                            p.expect_types(&child)?;
                            frame.ordered = p.value("Ordered")?;
                            continue;
                        }
                        _ => {}
                    }
                }
                p.skip()?;
                continue;
            };
            p.expect_types(&child)?;

            if nodes.len() + stack.len() >= max_nodes {
                return Err(p.error(ParseErrorKind::RestrictionTooLong));
            }
            if stack.len() >= max_depth {
                return Err(p.error(ParseErrorKind::RestrictionTooComplex));
            }

            let node = match expr {
                Expr::Compound(kind) => {
                    stack.push(Frame {
                        kind,
                        start: pending.len(),
                        distance: 0,
                        ordered: false,
                    });
                    continue;
                }
                Expr::Exists => SearchNode::Exists(Path::parse_one(p)?),
                Expr::Compare(op) => parse_compare(p, op)?,
                Expr::Contains => parse_contains(p, &child)?,
                Expr::Excludes => parse_excludes(p)?,
            };
            push_node(&mut nodes, &mut pending, node);
        }

        match pending.as_slice() {
            [root] => Ok(Restriction {
                root: *root,
                nodes,
                children,
            }),
            [] => Err(p.error(ParseErrorKind::MissingElement("SearchExpression"))),
            _ => Err(p.error(ParseErrorKind::InvalidValue("Restriction"))),
        }
    }

    pub fn node(&self, idx: NodeIdx) -> Option<&SearchNode<'a>> {
        self.nodes.get(idx.index())
    }

    pub fn range(&self, range: &Range<u16>) -> &[NodeIdx] {
        self.children
            .get(usize::from(range.start)..usize::from(range.end))
            .unwrap_or_default()
    }

    pub fn write_expression(&self, w: &mut XmlWriter<'_>) {
        let mut stack = vec![Visit::Open(self.root)];
        while let Some(visit) = stack.pop() {
            let idx = match visit {
                Visit::Open(idx) => idx,
                Visit::Close(name) => {
                    w.end(T, name);
                    continue;
                }
                Visit::CloseNear { distance, ordered } => {
                    w.leaf_u64(T, "Distance", u64::from(distance));
                    w.leaf_bool(T, "Ordered", ordered);
                    w.end(T, "Near");
                    continue;
                }
            };
            let Some(node) = self.node(idx) else {
                continue;
            };
            match node {
                SearchNode::Exists(path) => {
                    w.start(T, "Exists");
                    path.write(w);
                    w.end(T, "Exists");
                }
                SearchNode::Compare { op, path, rhs } => {
                    w.start(T, op.as_str());
                    path.write(w);
                    w.start(T, "FieldURIOrConstant");
                    match rhs {
                        CompareRhs::Constant(value) => {
                            w.start(T, "Constant").attr("Value", value).empty();
                        }
                        CompareRhs::Path(path) => path.write(w),
                    }
                    w.end(T, "FieldURIOrConstant");
                    w.end(T, op.as_str());
                }
                SearchNode::Contains {
                    path,
                    value,
                    mode,
                    comparison,
                } => {
                    w.start(T, "Contains")
                        .attr("ContainmentMode", mode.as_str())
                        .attr("ContainmentComparison", comparison.as_str());
                    path.write(w);
                    w.start(T, "Constant").attr("Value", value).empty();
                    w.end(T, "Contains");
                }
                SearchNode::Excludes { path, mask } => {
                    w.start(T, "Excludes");
                    path.write(w);
                    w.start(T, "Bitmask").attr_u64("Value", *mask).empty();
                    w.end(T, "Excludes");
                }
                SearchNode::Not(child) => {
                    w.start(T, "Not");
                    stack.push(Visit::Close("Not"));
                    stack.push(Visit::Open(*child));
                }
                SearchNode::And(range) | SearchNode::Or(range) => {
                    let name = if matches!(node, SearchNode::And(_)) {
                        "And"
                    } else {
                        "Or"
                    };
                    w.start(T, name);
                    stack.push(Visit::Close(name));
                    stack.extend(self.range(range).iter().rev().map(|idx| Visit::Open(*idx)));
                }
                SearchNode::Near {
                    distance,
                    ordered,
                    children,
                } => {
                    w.start(T, "Near");
                    stack.push(Visit::CloseNear {
                        distance: *distance,
                        ordered: *ordered,
                    });
                    stack.extend(
                        self.range(children)
                            .iter()
                            .rev()
                            .map(|idx| Visit::Open(*idx)),
                    );
                }
            }
        }
    }
}

enum Visit {
    Open(NodeIdx),
    Close(&'static str),
    CloseNear { distance: u32, ordered: bool },
}

fn push_node<'a>(
    nodes: &mut Vec<SearchNode<'a>>,
    pending: &mut Vec<NodeIdx>,
    node: SearchNode<'a>,
) {
    let idx = NodeIdx(u16::try_from(nodes.len()).unwrap_or(u16::MAX));
    nodes.push(node);
    pending.push(idx);
}

fn close_frame<'a>(
    p: &Parser<'a>,
    frame: &Frame,
    pending: &mut Vec<NodeIdx>,
    children: &mut Vec<NodeIdx>,
) -> Result<SearchNode<'a>> {
    let collected = pending.get(frame.start..).unwrap_or_default();
    if let Compound::Not = frame.kind {
        let [child] = collected else {
            return Err(p.error(ParseErrorKind::InvalidValue("Not")));
        };
        let child = *child;
        pending.truncate(frame.start);
        return Ok(SearchNode::Not(child));
    }
    let start = u16::try_from(children.len()).unwrap_or(u16::MAX);
    children.extend_from_slice(collected);
    let end = u16::try_from(children.len()).unwrap_or(u16::MAX);
    pending.truncate(frame.start);
    Ok(match frame.kind {
        Compound::And => SearchNode::And(start..end),
        Compound::Or => SearchNode::Or(start..end),
        Compound::Near | Compound::Not => SearchNode::Near {
            distance: frame.distance,
            ordered: frame.ordered,
            children: start..end,
        },
    })
}

fn parse_constant<'a>(p: &mut Parser<'a>, child: &Child<'a>) -> Result<Cow<'a, str>> {
    p.expect_types(child)?;
    let value = p.attr_required(&child.attrs, "Value")?;
    p.skip_rest()?;
    Ok(value)
}

fn parse_compare<'a>(p: &mut Parser<'a>, op: CompareOp) -> Result<SearchNode<'a>> {
    let mut path = None;
    let mut rhs = None;
    while let Some(child) = p.child()? {
        if child.local == "FieldURIOrConstant" {
            p.expect_types(&child)?;
            while let Some(operand) = p.child()? {
                if operand.local == "Constant" {
                    rhs = Some(CompareRhs::Constant(parse_constant(p, &operand)?));
                } else if let Some(other) = Path::parse_child(p, &operand)? {
                    rhs = Some(CompareRhs::Path(other));
                } else {
                    p.skip()?;
                }
            }
        } else if let Some(found) = Path::parse_child(p, &child)? {
            path = Some(found);
        } else {
            p.skip()?;
        }
    }
    Ok(SearchNode::Compare {
        op,
        path: path.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Path")))?,
        rhs: rhs.ok_or_else(|| p.error(ParseErrorKind::MissingElement("FieldURIOrConstant")))?,
    })
}

fn parse_comparison(text: &[u8]) -> Option<ContainmentComparison> {
    ContainmentComparison::parse(text).or_else(|| {
        (text == b"IgnoreCaseAndNoneSpacingCharacters")
            .then_some(ContainmentComparison::IgnoreCaseAndNonSpacingCharacters)
    })
}

fn parse_contains<'a>(p: &mut Parser<'a>, child: &Child<'a>) -> Result<SearchNode<'a>> {
    let mode = p
        .attr_enum(&child.attrs, "ContainmentMode", ContainmentMode::parse)?
        .unwrap_or(ContainmentMode::FullString);
    let comparison = p
        .attr_enum(&child.attrs, "ContainmentComparison", parse_comparison)?
        .unwrap_or(ContainmentComparison::Exact);
    let mut path = None;
    let mut value = None;
    while let Some(child) = p.child()? {
        if child.local == "Constant" {
            value = Some(parse_constant(p, &child)?);
        } else if let Some(found) = Path::parse_child(p, &child)? {
            path = Some(found);
        } else {
            p.skip()?;
        }
    }
    Ok(SearchNode::Contains {
        path: path.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Path")))?,
        value: value.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Constant")))?,
        mode,
        comparison,
    })
}

fn parse_excludes<'a>(p: &mut Parser<'a>) -> Result<SearchNode<'a>> {
    let mut path = None;
    let mut mask = None;
    while let Some(child) = p.child()? {
        if matches!(child.local, "Bitmask" | "BitMask") {
            p.expect_types(&child)?;
            let value = p.attr_required(&child.attrs, "Value")?;
            mask = Some(
                parse_hex_or_decimal(&value)
                    .ok_or_else(|| p.error(ParseErrorKind::InvalidValue("Bitmask")))?,
            );
            p.skip_rest()?;
        } else if let Some(found) = Path::parse_child(p, &child)? {
            path = Some(found);
        } else {
            p.skip()?;
        }
    }
    Ok(SearchNode::Excludes {
        path: path.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Path")))?,
        mask: mask.ok_or_else(|| p.error(ParseErrorKind::MissingElement("Bitmask")))?,
    })
}
