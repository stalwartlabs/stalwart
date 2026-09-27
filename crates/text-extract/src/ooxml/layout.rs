/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::text::RunText;
use crate::{
    output::Output,
    xml::{Handler, Tag, Text, local_name},
};

#[derive(Default)]
pub(crate) struct LayoutText {
    text: RunText,
    shapes: u32,
    placeholder: Option<u32>,
    done: bool,
}

fn is_shape(local: &[u8]) -> bool {
    hashify::set!(local, b"sp", b"graphicFrame", b"pic", b"cxnSp")
}

impl Handler for LayoutText {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        let local = tag.local();
        if is_shape(local) {
            self.shapes = self.shapes.saturating_add(1);
        } else if self.placeholder.is_none() && self.shapes > 0 && hashify::set!(local, b"ph") {
            self.placeholder = Some(self.shapes);
        }
        if self.placeholder.is_none() {
            self.text.start(tag, out);
        }
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        if self.placeholder.is_none() {
            self.text.end(name, out);
        }
        let local = local_name(name);
        self.done |= hashify::set!(local, b"cSld");
        if is_shape(local) {
            if self.placeholder == Some(self.shapes) {
                self.placeholder = None;
            }
            self.shapes = self.shapes.saturating_sub(1);
        }
    }

    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        if self.placeholder.is_none() {
            self.text.text(text, out);
        }
    }

    fn aborted(&self) -> bool {
        self.done
    }
}
