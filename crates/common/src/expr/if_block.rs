/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ConstantValue, ExpressionItem,
    parser::ExpressionParser,
    tokenizer::{TokenMap, Tokenizer},
};
use crate::{
    expr::{Constant, Expression},
    manager::bootstrap::Bootstrap,
};
use compact_str::CompactString;
use registry::{
    schema::{prelude::Property, structs},
    types::id::Id,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfThen {
    pub expr: Expression,
    pub then: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfBlock {
    pub property: Property,
    pub if_then: Vec<IfThen>,
    pub default: Expression,
}

impl IfBlock {
    pub fn new_default<T: ConstantValue>(property: Property, expr: structs::Expression) -> Self {
        let token_map = TokenMap::default()
            .with_all_variables()
            .with_constants::<T>();

        Self {
            property,
            if_then: expr
                .match_
                .into_iter()
                .map(|match_| IfThen {
                    expr: Expression::parse(&token_map, &match_.if_),
                    then: Expression::parse(&token_map, &match_.then),
                })
                .collect(),
            default: Expression::parse(&token_map, &expr.else_),
        }
    }

    pub fn empty(property: Property) -> Self {
        Self {
            property,
            if_then: Default::default(),
            default: Expression {
                items: Default::default(),
            },
        }
    }

    pub fn is_empty(&self) -> bool {
        self.default.is_empty() && self.if_then.is_empty()
    }
}

impl Expression {
    fn parse(token_map: &TokenMap, expr: &str) -> Self {
        ExpressionParser::new(Tokenizer::new(expr, token_map))
            .parse()
            .unwrap()
    }
}

impl IfBlock {
    pub fn try_parse(
        bp: &mut Bootstrap,
        id: Id,
        property: Property,
        expr: structs::Expression,
        token_map: &TokenMap,
    ) -> Option<IfBlock> {
        // Parse conditions
        let mut if_block = IfBlock {
            property,
            if_then: Vec::with_capacity(expr.match_.len()),
            default: Expression {
                items: Default::default(),
            },
        };

        if expr.else_.is_empty() {
            if !expr.match_.is_empty() {
                bp.invalid_property(id, property, "Missing 'else' block in 'if' expression");
            }
            return None;
        }

        if expr
            .match_
            .iter()
            .any(|m| m.if_.is_empty() || m.then.is_empty())
        {
            bp.invalid_property(id, property, "All 'if' and 'then' blocks must be non-empty");
            return None;
        }

        match ExpressionParser::new(Tokenizer::new(&expr.else_, token_map)).parse() {
            Ok(expr) => {
                if_block.default = expr;
            }
            Err(err) => {
                bp.invalid_property(
                    id,
                    property,
                    &format!("Error parsing 'else' expression: {}", err),
                );
                return None;
            }
        }

        for (num, match_) in expr.match_.into_iter().enumerate() {
            match ExpressionParser::new(Tokenizer::new(&match_.if_, token_map)).parse() {
                Ok(if_expr) => {
                    match ExpressionParser::new(Tokenizer::new(&match_.then, token_map)).parse() {
                        Ok(then_expr) => {
                            if_block.if_then.push(IfThen {
                                expr: if_expr,
                                then: then_expr,
                            });
                        }
                        Err(err) => {
                            bp.invalid_property(
                                id,
                                property,
                                &format!(
                                    "Error parsing 'then' expression in condition #{}: {}",
                                    num + 1,
                                    err
                                ),
                            );
                            return None;
                        }
                    }
                }
                Err(err) => {
                    bp.invalid_property(
                        id,
                        property,
                        &format!(
                            "Error parsing 'if' expression in condition #{}: {}",
                            num + 1,
                            err
                        ),
                    );
                    return None;
                }
            }
        }

        Some(if_block)
    }

    pub fn into_default(self, property: Property) -> IfBlock {
        IfBlock {
            property,
            if_then: Default::default(),
            default: self.default,
        }
    }

    pub fn default_string(&self) -> Option<&str> {
        for expr_item in &self.default.items {
            if let ExpressionItem::Constant(Constant::String(value)) = expr_item {
                return Some(value.as_str());
            }
        }

        None
    }

    pub fn into_default_string(self) -> Option<CompactString> {
        for expr_item in self.default.items {
            if let ExpressionItem::Constant(Constant::String(value)) = expr_item {
                return Some(value);
            }
        }

        None
    }
}
