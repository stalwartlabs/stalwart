/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ExpressionItem,
    parser::ExpressionParser,
    tokenizer::{TokenMap, Tokenizer},
};
use crate::{
    expr::{Constant, Expression},
    manager::bootstrap::Bootstrap,
};
use compact_str::CompactString;
use registry::{
    schema::{
        prelude::{ExpressionContext, Property},
        structs,
    },
    types::id::Id,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfThen {
    pub expr: Expression,
    pub then: Expression,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfBlock {
    pub id: Id,
    pub property: Property,
    pub if_then: Vec<IfThen>,
    pub default: Expression,
}

impl IfBlock {
    pub fn new_default(id: Id, expr_ctx: ExpressionContext<'_>) -> Self {
        let token_map = TokenMap::default();

        if let Some(default) = &expr_ctx.default {
            Self {
                id,
                property: expr_ctx.property,
                if_then: default
                    .match_
                    .iter()
                    .map(|match_| IfThen {
                        expr: Expression::parse(&token_map, &match_.if_),
                        then: Expression::parse(&token_map, &match_.then),
                    })
                    .collect(),
                default: Expression::parse(&token_map, &default.else_),
            }
        } else {
            Self::empty(id, expr_ctx.property)
        }
    }

    pub fn empty(id: Id, property: Property) -> Self {
        Self {
            id,
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

impl Bootstrap {
    pub fn compile_expr(&mut self, id: Id, expr_ctx: &ExpressionContext<'_>) -> IfBlock {
        if expr_ctx.expr.else_.is_empty() && expr_ctx.expr.match_.is_empty() {
            return IfBlock::empty(id, expr_ctx.property);
        }

        if let Some(if_block) = self.try_compile_expr(id, expr_ctx, &expr_ctx.expr) {
            if_block
        } else {
            self.compile_default_expr(id, expr_ctx)
        }
    }

    pub fn compile_default_expr(&mut self, id: Id, expr_ctx: &ExpressionContext<'_>) -> IfBlock {
        if let Some(default) = &expr_ctx.default {
            self.try_compile_expr(id, expr_ctx, default)
                .expect("Valid default expression")
        } else {
            IfBlock::empty(id, expr_ctx.property)
        }
    }

    pub fn try_compile_expr(
        &mut self,
        id: Id,
        expr_ctx: &ExpressionContext<'_>,
        expr: &structs::Expression,
    ) -> Option<IfBlock> {
        // Parse conditions
        let mut if_block = IfBlock {
            id,
            property: expr_ctx.property,
            if_then: Vec::with_capacity(expr.match_.len()),
            default: Expression {
                items: Default::default(),
            },
        };

        if expr.else_.is_empty() {
            if !expr.match_.is_empty() {
                self.invalid_property(
                    id,
                    expr_ctx.property,
                    "Missing 'else' block in 'if' expression",
                );
            }
            return None;
        }

        if expr
            .match_
            .iter()
            .any(|m| m.if_.is_empty() || m.then.is_empty())
        {
            self.invalid_property(
                id,
                expr_ctx.property,
                "All 'if' and 'then' blocks must be non-empty",
            );
            return None;
        }

        let token_map = TokenMap::default()
            .with_variables(expr_ctx.allowed_variables)
            .with_constants(expr_ctx.allowed_constants);

        match ExpressionParser::new(Tokenizer::new(&expr.else_, &token_map)).parse() {
            Ok(expr) => {
                if_block.default = expr;
            }
            Err(err) => {
                self.invalid_property(
                    id,
                    expr_ctx.property,
                    &format!("Error parsing 'else' expression: {}", err),
                );
                return None;
            }
        }

        for (num, match_) in expr.match_.iter().enumerate() {
            match ExpressionParser::new(Tokenizer::new(&match_.if_, &token_map)).parse() {
                Ok(if_expr) => {
                    match ExpressionParser::new(Tokenizer::new(&match_.then, &token_map)).parse() {
                        Ok(then_expr) => {
                            if_block.if_then.push(IfThen {
                                expr: if_expr,
                                then: then_expr,
                            });
                        }
                        Err(err) => {
                            self.invalid_property(
                                id,
                                expr_ctx.property,
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
                    self.invalid_property(
                        id,
                        expr_ctx.property,
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
}

impl IfBlock {
    pub fn into_default(self, id: Id, property: Property) -> IfBlock {
        IfBlock {
            id,
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
