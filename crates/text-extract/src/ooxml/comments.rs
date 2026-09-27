/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::text::RunText;
use crate::{
    output::{Mark, Output, Separator},
    xml::{Handler, Tag, Text, local_name},
};

const THREADED_MIRROR: &str = "[Threaded comment]";

#[derive(Default)]
pub(crate) struct CommentsText {
    text: RunText,
    comment: Option<Mark>,
    discarded: String,
}

impl Handler for CommentsText {
    fn start(&mut self, tag: &Tag<'_>, out: &mut Output<'_>) {
        if self.comment.is_none() && tag.local() == b"comment" {
            self.comment = Some(out.mark());
        }
        self.text.start(tag, out);
    }

    fn end(&mut self, name: &[u8], out: &mut Output<'_>) {
        self.text.end(name, out);
        match local_name(name) {
            b"comment" => {
                if let Some(mark) = self.comment.take()
                    && out.since(mark).trim_start().starts_with(THREADED_MIRROR)
                {
                    out.cut(mark, &mut self.discarded, 0);
                }
            }
            b"threadedComment" => out.separator(Separator::Newline),
            _ => {}
        }
    }

    fn text(&mut self, text: Text<'_>, out: &mut Output<'_>) {
        self.text.text(text, out);
    }
}
