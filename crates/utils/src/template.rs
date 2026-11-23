/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use std::{hash::Hash, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Template<T> {
    pub items: Vec<TemplateItem<T>>,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateItem<T> {
    Static(String),
    Variable { name: T, escape: bool },
    If { variable: T, block_end: usize },
    ForEach { variable: T, block_end: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Variable<T: Eq + Hash, V: AsRef<str>> {
    Single(V),
    Block(Vec<AHashMap<T, V>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variables<T: Eq + Hash, V: AsRef<str>> {
    pub items: AHashMap<T, Variable<T, V>>,
}

impl<T: FromStr + Eq + Hash + std::fmt::Debug> Template<T> {
    pub fn parse(mut template: &str) -> Result<Self, String> {
        let mut items = Vec::new();
        let mut block_stack = vec![];
        let mut size = 0;

        loop {
            if let Some((start, end)) = template.split_once("{{") {
                if !start.is_empty() {
                    items.push(TemplateItem::Static(start.to_string()));
                    size += start.len();
                }
                let (var, rest) = end.split_once("}}").ok_or("Unmatched {{")?;
                template = rest;
                let var = var.trim();
                if let Some(var_name) = var.strip_prefix("#").map(|v| v.trim()) {
                    let (is_each, var_name) = if let Some(each) = var_name.strip_prefix("each ") {
                        (true, each)
                    } else if let Some(if_cond) = var_name.strip_prefix("if ") {
                        (false, if_cond)
                    } else {
                        return Err(format!("Invalid block start: {}", var_name));
                    };
                    let var = T::from_str(var_name)
                        .map_err(|_| format!("Invalid variable: {}", var_name))?;

                    block_stack.push((var_name, items.len()));

                    if is_each {
                        items.push(TemplateItem::ForEach {
                            variable: var,
                            block_end: 0,
                        });
                    } else {
                        items.push(TemplateItem::If {
                            variable: var,
                            block_end: 0,
                        });
                    }
                } else if let Some(var_name) = var.strip_prefix("/").map(|v| v.trim()) {
                    let (is_each, var_name) = if let Some(each) = var_name.strip_prefix("each ") {
                        (true, each)
                    } else if let Some(if_cond) = var_name.strip_prefix("if ") {
                        (false, if_cond)
                    } else {
                        return Err(format!("Invalid block end: {}", var_name));
                    };

                    if let Some((expected_name, if_pos)) = block_stack.pop() {
                        if expected_name != var_name {
                            return Err(format!(
                                "Block end does not match start: expected {}, got {}",
                                expected_name, var_name
                            ));
                        }
                        let block_end_idx = items.len();
                        match &mut items[if_pos] {
                            TemplateItem::If { block_end, .. } if !is_each => {
                                *block_end = block_end_idx;
                            }
                            TemplateItem::ForEach { block_end, .. } if is_each => {
                                *block_end = block_end_idx;
                            }
                            _ => {
                                return Err(format!(
                                    "Block end does not match start type for {}",
                                    var_name
                                ));
                            }
                        }
                    }
                } else {
                    let (name, escape) = var.strip_prefix("!").map_or((var, true), |v| (v, false));
                    let name =
                        T::from_str(name).map_err(|_| format!("Invalid variable: {}", name))?;
                    items.push(TemplateItem::Variable { name, escape });
                }
            } else {
                if !template.is_empty() {
                    items.push(TemplateItem::Static(template.to_string()));
                    size += template.len();
                }
                break;
            }
        }

        if block_stack.is_empty() {
            Ok(Template { items, size })
        } else {
            Err(format!("Unmatched {{: {}", block_stack.last().unwrap().0))
        }
    }

    pub fn eval<V>(&self, variables: &Variables<T, V>) -> String
    where
        V: AsRef<str>,
    {
        let mut result = String::with_capacity(self.size);
        let mut items = self.items.iter().enumerate();
        let mut base_offset = 0;

        while let Some((idx, item)) = items.next() {
            let idx = idx + base_offset;
            match item {
                TemplateItem::Static(s) => result.push_str(s),
                TemplateItem::Variable { name, escape } => {
                    if let Some(Variable::Single(variable)) = variables.items.get(name) {
                        if *escape {
                            html_escape(&mut result, variable.as_ref())
                        } else {
                            result.push_str(variable.as_ref());
                        }
                    }
                }
                TemplateItem::If {
                    variable,
                    block_end,
                } => {
                    if !variables.items.contains_key(variable) {
                        items = self.items[*block_end..].iter().enumerate();
                        base_offset = *block_end;
                    }
                }
                TemplateItem::ForEach {
                    variable,
                    block_end,
                } => {
                    if let Some(Variable::Block(entries)) = variables.items.get(variable) {
                        let slice = &self.items[idx + 1..*block_end];
                        for entry in entries {
                            let mut slice = slice.iter();
                            while let Some(sub_item) = slice.next() {
                                match sub_item {
                                    TemplateItem::Static(s) => result.push_str(s),
                                    TemplateItem::Variable { name, escape } => {
                                        if let Some(variable) = entry.get(name) {
                                            if *escape {
                                                html_escape(&mut result, variable.as_ref())
                                            } else {
                                                result.push_str(variable.as_ref());
                                            }
                                        }
                                    }
                                    TemplateItem::If {
                                        variable,
                                        block_end: start_pos,
                                    } if !entry.contains_key(variable) => {
                                        slice = self.items[*start_pos..*block_end].iter();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    items = self.items[*block_end..].iter().enumerate();
                    base_offset = *block_end;
                }
            }
        }

        result
    }
}

fn html_escape(result: &mut String, input: &str) {
    for c in input.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            '\n' => result.push_str("<br>"),
            '\r' => {}
            _ => result.push(c),
        }
    }
}

impl<T: Eq + Hash, V: AsRef<str>> Variables<T, V> {
    pub fn new() -> Self {
        Self {
            items: AHashMap::new(),
        }
    }

    pub fn insert_single(&mut self, key: T, value: V) {
        self.items.insert(key, Variable::Single(value));
    }

    pub fn insert_block<V1, V2>(&mut self, key: T, value: V1)
    where
        V1: IntoIterator<Item = V2>,
        V2: IntoIterator<Item = (T, V)>,
    {
        self.items.insert(
            key,
            Variable::Block(value.into_iter().map(AHashMap::from_iter).collect()),
        );
    }
}

impl<T: Eq + Hash, V: AsRef<str>> Default for Variables<T, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../stalwart-tests/unit/utils/src/template/tests.rs"]
mod tests;
