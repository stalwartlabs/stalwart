/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) mod attr;
pub(crate) mod scan;
pub(crate) mod stream;

use crate::output::Output;

pub(crate) const MAX_TAG_CARRY: usize = 1 << 14;
pub(crate) const MAX_NAME: usize = 64;
const MAX_ENTITY: usize = 32;

pub(crate) struct Tag<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) attrs: Option<&'a [u8]>,
}

impl<'a> Tag<'a> {
    #[inline]
    pub(crate) fn local(&self) -> &'a [u8] {
        local_name(self.name)
    }
}

pub(crate) trait Handler {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>);
    fn end(&mut self, name: &[u8], out: &mut Output<'_>);
    fn text(&mut self, text: &[u8], out: &mut Output<'_>);
    fn entity(&mut self, _name: &[u8], _out: &mut Output<'_>) {}
    fn aborted(&self) -> bool {
        false
    }
}

#[inline]
pub(crate) fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&byte| byte == b':') {
        Some(colon) => name.get(colon + 1..).unwrap_or_default(),
        None => name,
    }
}

pub(crate) struct Skip<E> {
    element: Option<E>,
    depth: u32,
}

impl<E> Default for Skip<E> {
    fn default() -> Self {
        Skip {
            element: None,
            depth: 0,
        }
    }
}

impl<E: Copy + PartialEq> Skip<E> {
    #[inline]
    pub(crate) fn active(&self) -> bool {
        self.depth > 0
    }

    #[inline]
    pub(crate) fn begin(&mut self, element: E) {
        self.element = Some(element);
        self.depth = 1;
    }

    #[inline]
    pub(crate) fn on_start(&mut self, element: Option<E>) -> bool {
        if self.depth == 0 {
            return false;
        }
        if element.is_some() && element == self.element {
            self.depth = self.depth.saturating_add(1);
        }
        true
    }

    #[inline]
    pub(crate) fn on_end(&mut self, element: Option<E>) -> bool {
        if self.depth == 0 {
            return false;
        }
        if element.is_some() && element == self.element {
            self.depth -= 1;
        }
        true
    }

    pub(crate) fn reset(&mut self) {
        self.depth = 0;
    }
}
