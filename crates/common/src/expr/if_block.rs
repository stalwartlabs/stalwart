/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    ExpressionItem,
    parser::ExpressionParser,
    program::{Program, ProgramBuilder},
    tokenizer::{TokenMap, Tokenizer},
};
use crate::expr::Expression;
use registry::{
    schema::{
        prelude::{ExpressionContext, Property},
        structs,
    },
    types::id::ObjectId,
};
use store::registry::bootstrap::Bootstrap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfThen {
    pub expr: Expression,
    pub then: Expression,
}

#[derive(Debug, Clone)]
pub struct IfBlock {
    pub id: ObjectId,
    pub property: Property,
    pub if_then: Box<[IfThen]>,
    pub default: Expression,
    pub(crate) program: Program,
}

impl PartialEq for IfBlock {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.property == other.property
            && self.if_then == other.if_then
            && self.default == other.default
    }
}

impl Eq for IfBlock {}

impl IfBlock {
    pub fn empty(id: ObjectId, property: Property) -> Self {
        Self {
            id,
            property,
            if_then: Default::default(),
            default: Expression {
                items: Default::default(),
            },
            program: Program::default(),
        }
    }

    pub fn new(
        id: ObjectId,
        property: Property,
        if_then: Box<[IfThen]>,
        default: Expression,
    ) -> Self {
        let mut block = Self {
            id,
            property,
            if_then,
            default,
            program: Program::default(),
        };
        if !block.is_empty() {
            block.program = block.lower();
        }
        block
    }

    fn lower(&self) -> Program {
        let (ops, widest) = self
            .if_then
            .iter()
            .flat_map(|if_then| [&if_then.expr, &if_then.then])
            .chain([&self.default])
            .fold((2 * self.if_then.len() + 1, 0), |(ops, widest), expr| {
                (ops + expr.items.len(), widest.max(expr.items.len()))
            });
        let mut builder = ProgramBuilder::with_capacity(ops, widest);
        for if_then in &self.if_then {
            builder.push_expression(&if_then.expr.items);
            let test = builder.push_test();
            builder.push_expression(&if_then.then.items);
            builder.push_return();
            builder.patch_test(test);
        }
        builder.push_expression(&self.default.items);
        builder.push_return();
        builder.build()
    }

    pub fn is_empty(&self) -> bool {
        self.default.is_empty() && self.if_then.is_empty()
    }

    pub fn all_items(&self) -> impl Iterator<Item = &ExpressionItem> {
        self.if_then
            .iter()
            .flat_map(|if_then| if_then.expr.items().iter().chain(if_then.then.items()))
            .chain(self.default.items())
    }
}

impl Expression {
    pub fn parse(token_map: &TokenMap, expr: &str) -> Result<Self, String> {
        ExpressionParser::default().parse(Tokenizer::new(expr, token_map))
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn items(&self) -> &[ExpressionItem] {
        &self.items
    }
}

pub trait BootstrapExprExt {
    fn compile_expr(&mut self, id: ObjectId, expr_ctx: &ExpressionContext<'_>) -> IfBlock;
    fn compile_default_expr(&mut self, id: ObjectId, expr_ctx: &ExpressionContext<'_>) -> IfBlock;
    fn try_compile_expr(
        &mut self,
        id: ObjectId,
        expr_ctx: &ExpressionContext<'_>,
        expr: &structs::Expression,
    ) -> Option<IfBlock>;
}

impl BootstrapExprExt for Bootstrap {
    fn compile_expr(&mut self, id: ObjectId, expr_ctx: &ExpressionContext<'_>) -> IfBlock {
        if expr_ctx.expr.else_.is_empty() && expr_ctx.expr.match_.is_empty() {
            return IfBlock::empty(id, expr_ctx.property);
        }

        if let Some(if_block) = self.try_compile_expr(id, expr_ctx, expr_ctx.expr) {
            if_block
        } else {
            self.compile_default_expr(id, expr_ctx)
        }
    }

    fn compile_default_expr(&mut self, id: ObjectId, expr_ctx: &ExpressionContext<'_>) -> IfBlock {
        if let Some(default) = &expr_ctx.default {
            self.try_compile_expr(id, expr_ctx, default)
                .expect("Valid default expression")
        } else {
            IfBlock::empty(id, expr_ctx.property)
        }
    }

    fn try_compile_expr(
        &mut self,
        id: ObjectId,
        expr_ctx: &ExpressionContext<'_>,
        expr: &structs::Expression,
    ) -> Option<IfBlock> {
        // Parse conditions
        let mut if_then = Vec::with_capacity(expr.match_.len());

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

        let mut parser = ExpressionParser::default();
        let default = match parser.parse(Tokenizer::new(&expr.else_, &token_map)) {
            Ok(expr) => expr,
            Err(err) => {
                self.invalid_property(
                    id,
                    expr_ctx.property,
                    format!("Error parsing 'else' expression: {}", err),
                );
                return None;
            }
        };

        for (num, match_) in expr.match_.iter().enumerate() {
            match parser.parse(Tokenizer::new(&match_.if_, &token_map)) {
                Ok(if_expr) => match parser.parse(Tokenizer::new(&match_.then, &token_map)) {
                    Ok(then_expr) => {
                        if_then.push(IfThen {
                            expr: if_expr,
                            then: then_expr,
                        });
                    }
                    Err(err) => {
                        self.invalid_property(
                            id,
                            expr_ctx.property,
                            format!(
                                "Error parsing 'then' expression in condition #{}: {}",
                                num + 1,
                                err
                            ),
                        );
                        return None;
                    }
                },
                Err(err) => {
                    self.invalid_property(
                        id,
                        expr_ctx.property,
                        format!(
                            "Error parsing 'if' expression in condition #{}: {}",
                            num + 1,
                            err
                        ),
                    );
                    return None;
                }
            }
        }

        Some(IfBlock::new(
            id,
            expr_ctx.property,
            if_then.into_boxed_slice(),
            default,
        ))
    }
}

#[cfg(test)]
impl IfBlock {
    pub(crate) fn compile_test(if_then: &[(&str, &str)], default: &str) -> Self {
        use registry::schema::prelude::ObjectType;

        let token_map = TokenMap::default();
        let parse = |expr: &str| Expression::parse(&token_map, expr).expect("expression parses");
        IfBlock::new(
            ObjectType::SpamRule.singleton(),
            Property::Condition,
            if_then
                .iter()
                .map(|(expr, then)| IfThen {
                    expr: parse(expr),
                    then: parse(then),
                })
                .collect(),
            parse(default),
        )
    }
}
