/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    BinaryOperator, Constant, ExpressionItem, UnaryOperator,
    functions::{F_COUNTER_INCR, F_KEY_SET, F_SQL_QUERY, FUNCTIONS, SyncFunction},
    if_block::IfBlock,
};
use ahash::AHashMap;
use registry::schema::enums::ExpressionVariable;

const SIDE_EFFECTS: [u32; 3] = [F_KEY_SET, F_COUNTER_INCR, F_SQL_QUERY];
const MAX_GUARD_ITEMS: usize = 256;

#[derive(Debug, Clone, Default)]
pub struct ScopeRules {
    rules: Box<[IfBlock]>,
    all: Box<[u32]>,
    unguarded: Box<[u32]>,
    by_value: AHashMap<Box<str>, Box<[u32]>>,
}

#[derive(Clone, Copy)]
pub struct Selection<'r> {
    rules: &'r [IfBlock],
    order: &'r [u32],
}

enum Node<'e> {
    Var(ExpressionVariable),
    Str(&'e str),
    Array(Vec<Node<'e>>),
    Contains(Box<Node<'e>>, Box<Node<'e>>),
    Eq(Box<Node<'e>>, Box<Node<'e>>),
    Ne(Box<Node<'e>>, Box<Node<'e>>),
    Not(Box<Node<'e>>),
    And(Box<Node<'e>>, Box<Node<'e>>),
    Or(Box<Node<'e>>, Box<Node<'e>>),
    Other,
}

struct Span<'e> {
    node: Node<'e>,
    start: usize,
    end: usize,
}

impl ScopeRules {
    pub fn new(rules: Vec<IfBlock>, guard: Option<ExpressionVariable>) -> Self {
        let guards = rules
            .iter()
            .map(|rule| guard.and_then(|variable| rule_guard(rule, variable)))
            .collect::<Vec<_>>();

        let select = |accepts: &dyn Fn(Option<&[&str]>) -> bool| {
            guards
                .iter()
                .enumerate()
                .filter(|(_, guard)| accepts(guard.as_deref()))
                .map(|(index, _)| index as u32)
                .collect::<Box<[u32]>>()
        };

        let by_value = distinct(guards.iter().flatten().flatten().copied().collect())
            .iter()
            .map(|value| {
                (
                    Box::<str>::from(*value),
                    select(&|guard| guard.is_none_or(|values| values.contains(value))),
                )
            })
            .collect();

        ScopeRules {
            unguarded: select(&|guard| guard.is_none()),
            all: (0..rules.len() as u32).collect(),
            by_value,
            rules: rules.into_boxed_slice(),
        }
    }

    pub fn select(&self, value: &str) -> Selection<'_> {
        Selection {
            rules: &self.rules,
            order: self.by_value.get(value).unwrap_or(&self.unguarded),
        }
    }

    pub fn all(&self) -> Selection<'_> {
        Selection {
            rules: &self.rules,
            order: &self.all,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
impl ScopeRules {
    fn len(&self) -> usize {
        self.rules.len()
    }

    fn guarded(&self) -> usize {
        self.rules.len() - self.unguarded.len()
    }

    fn blocks(&self) -> &[IfBlock] {
        &self.rules
    }
}

impl<'r> Selection<'r> {
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &'r IfBlock> + use<'r> {
        let (rules, order) = (self.rules, self.order);
        order
            .iter()
            .filter_map(move |index| rules.get(*index as usize))
    }
}

fn rule_guard(block: &IfBlock, variable: ExpressionVariable) -> Option<Vec<&str>> {
    let mut values = Vec::new();
    for if_then in &block.if_then {
        let items = if_then.expr.items();
        if items.len() > MAX_GUARD_ITEMS || items.iter().any(has_side_effects) {
            return None;
        }
        let tree = build_tree(items)?;
        if let Some(guard) = conjunct_guard(&tree, variable) {
            values.extend(guard);
        } else if yields_nothing(if_then.then.items())
            && let Some(exit) = exit_guard(&tree, variable)
        {
            values.extend(exit);
            return Some(distinct(values));
        } else {
            return None;
        }
    }
    yields_nothing(block.default.items()).then(|| distinct(values))
}

fn distinct(mut values: Vec<&str>) -> Vec<&str> {
    values.sort_unstable();
    values.dedup();
    values
}

fn yields_nothing(items: &[ExpressionItem]) -> bool {
    matches!(
        items,
        [ExpressionItem::Constant(
            Constant::Integer(_) | Constant::Float(_) | Constant::Static(_)
        )]
    )
}

fn has_side_effects(item: &ExpressionItem) -> bool {
    match item {
        ExpressionItem::Function { id, .. } => id
            .checked_sub(FUNCTIONS.len() as u32)
            .is_some_and(|id| SIDE_EFFECTS.contains(&id)),
        _ => false,
    }
}

fn build_tree(items: &[ExpressionItem]) -> Option<Node<'_>> {
    let mut stack: Vec<Span<'_>> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let (node, start) = match item {
            ExpressionItem::JmpIf { .. } => continue,
            ExpressionItem::Variable(variable) => (Node::Var(*variable), index),
            ExpressionItem::Constant(Constant::String(value)) => (Node::Str(value.as_str()), index),
            ExpressionItem::Constant(_)
            | ExpressionItem::Global(_)
            | ExpressionItem::System(_)
            | ExpressionItem::Capture(_) => (Node::Other, index),
            ExpressionItem::UnaryOperator(op) => {
                let (mut operands, start) = pop_operands(&mut stack, 1, index)?;
                match (op, operands.pop()) {
                    (UnaryOperator::Not, Some(operand)) => (Node::Not(Box::new(operand)), start),
                    _ => (Node::Other, start),
                }
            }
            ExpressionItem::Regex(_) => (Node::Other, pop_operands(&mut stack, 1, index)?.1),
            ExpressionItem::ArrayAccess => (Node::Other, pop_operands(&mut stack, 2, index)?.1),
            ExpressionItem::ArrayBuild(count) => {
                let (items, start) = pop_operands(&mut stack, *count as usize, index)?;
                (Node::Array(items), start)
            }
            ExpressionItem::Function { id, num_args } => {
                let (mut args, start) = pop_operands(&mut stack, *num_args as usize, index)?;
                let node = match (*id == SyncFunction::Contains as u32, args.pop(), args.pop()) {
                    (true, Some(needle), Some(haystack)) if args.is_empty() => {
                        Node::Contains(Box::new(haystack), Box::new(needle))
                    }
                    _ => Node::Other,
                };
                (node, start)
            }
            ExpressionItem::BinaryOperator(op) => {
                let right = stack.pop()?;
                let left = stack.pop()?;
                let short_circuit = match op {
                    BinaryOperator::And => Some(false),
                    BinaryOperator::Or => Some(true),
                    _ => None,
                };
                let well_formed = right.end == index
                    && match short_circuit {
                        Some(val) => {
                            right.start == left.end + 1
                                && matches!(items.get(left.end), Some(ExpressionItem::JmpIf { val: v, pos })
                                    if *v == val && left.end + *pos as usize == index)
                        }
                        None => right.start == left.end,
                    };
                if !well_formed {
                    return None;
                }
                let (left_node, right_node) = (Box::new(left.node), Box::new(right.node));
                let node = match op {
                    BinaryOperator::And => Node::And(left_node, right_node),
                    BinaryOperator::Or => Node::Or(left_node, right_node),
                    BinaryOperator::Eq => Node::Eq(left_node, right_node),
                    BinaryOperator::Ne => Node::Ne(left_node, right_node),
                    _ => Node::Other,
                };
                (node, left.start)
            }
        };
        stack.push(Span {
            node,
            start,
            end: index + 1,
        });
    }
    match (stack.pop(), stack.is_empty()) {
        (
            Some(Span {
                node,
                start: 0,
                end,
            }),
            true,
        ) if end == items.len() => Some(node),
        _ => None,
    }
}

fn pop_operands<'e>(
    stack: &mut Vec<Span<'e>>,
    count: usize,
    index: usize,
) -> Option<(Vec<Node<'e>>, usize)> {
    let base = stack.len().checked_sub(count)?;
    let operands = stack.get(base..)?;
    let contiguous = operands.windows(2).all(|pair| match pair {
        [left, right] => left.end == right.start,
        _ => false,
    }) && operands.last().is_none_or(|last| last.end == index);
    if !contiguous {
        return None;
    }
    let start = operands.first().map_or(index, |first| first.start);
    Some((stack.drain(base..).map(|span| span.node).collect(), start))
}

fn compared_value<'e>(
    left: &Node<'e>,
    right: &Node<'e>,
    variable: ExpressionVariable,
) -> Option<Vec<&'e str>> {
    match (left, right) {
        (Node::Var(v), Node::Str(value)) | (Node::Str(value), Node::Var(v)) if *v == variable => {
            Some(vec![*value])
        }
        _ => None,
    }
}

fn guard_values<'e>(node: &Node<'e>, variable: ExpressionVariable) -> Option<Vec<&'e str>> {
    match node {
        Node::Eq(left, right) => compared_value(left, right, variable),
        Node::Contains(haystack, needle) => match (haystack.as_ref(), needle.as_ref()) {
            (Node::Array(items), Node::Var(v)) if *v == variable => items
                .iter()
                .map(|item| match item {
                    Node::Str(value) => Some(*value),
                    _ => None,
                })
                .collect(),
            _ => None,
        },
        Node::Or(left, right) => {
            let mut values = guard_values(left, variable)?;
            values.extend(guard_values(right, variable)?);
            Some(values)
        }
        _ => None,
    }
}

fn exit_guard<'e>(node: &Node<'e>, variable: ExpressionVariable) -> Option<Vec<&'e str>> {
    match node {
        Node::Not(inner) => guard_values(inner, variable),
        Node::Ne(left, right) => compared_value(left, right, variable),
        Node::Or(left, right) => match (exit_guard(left, variable), exit_guard(right, variable)) {
            (Some(left), Some(right)) => {
                Some(left.into_iter().filter(|v| right.contains(v)).collect())
            }
            (Some(values), None) | (None, Some(values)) => Some(values),
            (None, None) => None,
        },
        _ => None,
    }
}

fn conjunct_guard<'e>(node: &Node<'e>, variable: ExpressionVariable) -> Option<Vec<&'e str>> {
    if let Some(values) = guard_values(node, variable) {
        return Some(values);
    }
    match node {
        Node::And(left, right) => {
            match (
                conjunct_guard(left, variable),
                conjunct_guard(right, variable),
            ) {
                (Some(left), Some(right)) => {
                    Some(left.into_iter().filter(|v| right.contains(v)).collect())
                }
                (Some(values), None) | (None, Some(values)) => Some(values),
                (None, None) => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(branches: &[(&str, &str)], default: &str) -> IfBlock {
        IfBlock::compile_test(branches, default)
    }

    fn guard(
        branches: &[(&str, &str)],
        default: &str,
        variable: ExpressionVariable,
    ) -> Option<Vec<String>> {
        rule_guard(&block(branches, default), variable)
            .map(|values| values.into_iter().map(str::to_string).collect())
    }

    fn names(branches: &[(&str, &str)], default: &str) -> Option<Vec<String>> {
        guard(branches, default, ExpressionVariable::NameLower)
    }

    fn locations(branches: &[(&str, &str)], default: &str) -> Option<Vec<String>> {
        guard(branches, default, ExpressionVariable::Location)
    }

    fn some(values: &[&str]) -> Option<Vec<String>> {
        Some(values.iter().map(|v| v.to_string()).collect())
    }

    #[test]
    fn extracts_simple_guards() {
        assert_eq!(
            names(
                &[("name_lower == 'x-mailer' && contains(value, 'a')", "'T'")],
                "false"
            ),
            some(&["x-mailer"])
        );
        assert_eq!(
            names(&[("'x-mailer' == name_lower", "'T'")], "false"),
            some(&["x-mailer"])
        );
        assert_eq!(
            names(
                &[(
                    "contains(['to', 'cc', 'bcc'], name_lower) && contains(raw_lower, 'u')",
                    "'T'"
                )],
                "false"
            ),
            some(&["bcc", "cc", "to"])
        );
        assert_eq!(
            names(
                &[(
                    "contains(value_lower, 'eval()') && contains(['x-php', 'x-php-script'], name_lower)",
                    "'T'"
                )],
                "false"
            ),
            some(&["x-php", "x-php-script"])
        );
        assert_eq!(
            names(
                &[(
                    "(name_lower == 'user_agent' || name_lower == 'x-mailer') && !is_empty(value)",
                    "'T'"
                )],
                "false"
            ),
            some(&["user_agent", "x-mailer"])
        );
        assert_eq!(
            names(
                &[(
                    "contains(value, 'a') && (name_lower == 'a' || name_lower == 'b') && name_lower == 'b'",
                    "'T'"
                )],
                "false"
            ),
            some(&["b"])
        );
        assert_eq!(
            names(
                &[
                    ("name_lower == 'a'", "'A'"),
                    ("name_lower == 'b' && is_empty(value)", "'B'")
                ],
                "0"
            ),
            some(&["a", "b"])
        );
        assert_eq!(names(&[], "false"), some(&[]));
    }

    #[test]
    fn rejects_unsafe_shapes() {
        assert_eq!(names(&[("name_lower == 'x'", "'T'")], "'D'"), None);
        assert_eq!(names(&[("name_lower == 'x'", "'T'")], "''"), None);
        assert_eq!(names(&[("name_lower == 'x'", "'T'")], "name"), None);
        assert_eq!(
            names(&[("name_lower == 'x'", "'T'"), ("true", "'U'")], "false"),
            None
        );
        assert_eq!(
            names(
                &[("name_lower == 'x' || contains(value, 'y')", "'T'")],
                "false"
            ),
            None
        );
        assert_eq!(names(&[("!(name_lower == 'x')", "'T'")], "false"), None);
        assert_eq!(names(&[("name_lower != 'x'", "'T'")], "false"), None);
        assert_eq!(
            names(&[("contains(name_lower, 'x')", "'T'")], "false"),
            None
        );
        assert_eq!(
            names(&[("contains(['x', 1], name_lower)", "'T'")], "false"),
            None
        );
        assert_eq!(names(&[("name_lower == 5", "'T'")], "false"), None);
        assert_eq!(names(&[("name == 'X'", "'T'")], "false"), None);
        assert_eq!(names(&[("(name_lower == 'x') == 1", "'T'")], "false"), None);
        assert_eq!(
            names(
                &[(
                    "counter_incr('c', name_lower, 1) > 0 && name_lower == 'x'",
                    "'T'"
                )],
                "false"
            ),
            None
        );
        assert_eq!(
            names(
                &[("key_set('k', name_lower, 1) && name_lower == 'x'", "'T'")],
                "false"
            ),
            None
        );
        assert_eq!(
            names(
                &[
                    ("name_lower == 'x'", "'T'"),
                    ("sql_query('sql', 'x', []) && name_lower == 'y'", "'U'")
                ],
                "false"
            ),
            None
        );
        assert_eq!(
            names(
                &[("key_exists('k', value) && name_lower == 'x'", "'T'")],
                "false"
            ),
            some(&["x"])
        );
    }

    #[test]
    fn extracts_early_exit_guards() {
        assert_eq!(
            locations(
                &[
                    (
                        "!contains(['from', 'to'], location) || is_empty(sld)",
                        "false"
                    ),
                    (
                        "key_exists('free', domain)",
                        "'FREE_' + to_uppercase(location)"
                    ),
                ],
                "false"
            ),
            some(&["from", "to"])
        );
        assert_eq!(
            locations(
                &[
                    ("location == 'cc'", "'C'"),
                    ("is_empty(sld) || location != 'to'", "0"),
                    ("counter_incr('c', domain, 1)", "'T'"),
                ],
                "'D'"
            ),
            some(&["cc", "to"])
        );
        assert_eq!(
            locations(
                &[
                    ("!(location == 'a' || location == 'b')", "false"),
                    ("true", "'T'")
                ],
                "'D'"
            ),
            some(&["a", "b"])
        );
        assert_eq!(
            locations(
                &[
                    ("location != 'a' || location != 'b'", "false"),
                    ("true", "'T'")
                ],
                "'D'"
            ),
            some(&[])
        );
        assert_eq!(
            locations(&[("!contains(['a'], location)", "'T'")], "false"),
            None
        );
        assert_eq!(
            locations(
                &[("!contains(['a'], location) && is_empty(sld)", "false")],
                "false"
            ),
            None
        );
        assert_eq!(
            locations(&[("true", "'T'"), ("location != 'a'", "false")], "false"),
            None
        );
        assert_eq!(
            locations(
                &[
                    ("key_set('k', domain, 1) && location == 'a'", "'A'"),
                    ("location != 'b'", "false"),
                ],
                "'D'"
            ),
            None
        );
        assert_eq!(
            locations(&[("!contains(['a', 1], location)", "false")], "'D'"),
            None
        );
    }

    #[test]
    fn refuses_oversized_expressions() {
        let condition = |terms: usize| {
            let mut condition = String::from("name_lower == 'x'");
            for _ in 0..terms {
                condition.push_str(" && contains(value, 'a')");
            }
            condition
        };
        let mut guarded = 0;
        let mut refused = 0;
        for terms in 0..80 {
            let condition = condition(terms);
            let block = block(&[(condition.as_str(), "'T'")], "false");
            let items = block
                .if_then
                .iter()
                .map(|if_then| if_then.expr.items().len())
                .sum::<usize>();
            let guard = rule_guard(&block, ExpressionVariable::NameLower);
            if items > MAX_GUARD_ITEMS {
                assert_eq!(guard, None, "{items} items");
                refused += 1;
            } else {
                assert_eq!(guard, Some(vec!["x"]), "{items} items");
                guarded += 1;
            }
        }
        assert!(guarded > 0 && refused > 0);
    }

    #[test]
    fn selects_rules_in_original_order() {
        let rules = vec![
            block(
                &[(
                    "name_lower == 'x-mailer' && contains(value_lower, 'php')",
                    "'A'",
                )],
                "false",
            ),
            block(
                &[(
                    "contains(['to', 'cc'], name_lower) && is_empty(value)",
                    "'B'",
                )],
                "false",
            ),
            block(&[("contains(raw_lower, 'spam')", "'C'")], "false"),
            block(
                &[("name_lower == 'to' && contains(name, 'T')", "'D'")],
                "false",
            ),
        ];
        let index = |selection: Selection<'_>, rules: &[IfBlock]| {
            selection
                .iter()
                .filter_map(|rule| {
                    rules
                        .iter()
                        .position(|candidate| std::ptr::eq(candidate, rule))
                })
                .collect::<Vec<_>>()
        };

        let scope = ScopeRules::new(rules.clone(), Some(ExpressionVariable::NameLower));
        assert_eq!(scope.len(), 4);
        assert_eq!(scope.guarded(), 3);
        assert_eq!(index(scope.select("x-mailer"), scope.blocks()), [0, 2]);
        assert_eq!(index(scope.select("to"), scope.blocks()), [1, 2, 3]);
        assert_eq!(index(scope.select("cc"), scope.blocks()), [1, 2]);
        assert_eq!(index(scope.select("received"), scope.blocks()), [2]);
        assert_eq!(index(scope.all(), scope.blocks()), [0, 1, 2, 3]);

        let unguarded = ScopeRules::new(rules, None);
        assert_eq!(unguarded.guarded(), 0);
        assert_eq!(
            index(unguarded.select("x-mailer"), unguarded.blocks()),
            [0, 1, 2, 3]
        );

        let empty = ScopeRules::new(Vec::new(), Some(ExpressionVariable::Location));
        assert!(empty.is_empty());
        assert!(empty.select("from").is_empty());
        assert!(empty.all().is_empty());
    }
}
