/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

use memchr::memchr;

pub(super) const SMIME_FILE_NAME: &str = "SMIME.p7m";
pub(super) const MULTIPART_SIGNED: &str = "multipart/signed";
pub(super) const CONTENT_TYPE: &str = "Content-Type";
pub(super) const SUFFIX_SMIME_SIGNED: &str = ".SMIME.MultipartSigned";
pub(super) const SUFFIX_SMIME: &str = ".SMIME";

pub(super) fn clear_signed_entity(entity: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut content_type = None;
    let mut fields = 0usize;
    let mut field_start = 0usize;
    let mut offset = 0usize;
    loop {
        let rest = entity.get(offset..)?;
        let line_end = memchr(b'\n', rest).map_or(rest.len(), |end| end.saturating_add(1));
        let line = rest.get(..line_end)?;
        let next = offset.saturating_add(line_end);
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            && fields > 0
        {
            offset = next;
            continue;
        }
        if fields > 0 && is_content_type(entity.get(field_start..offset)?) {
            content_type = Some(field_start..offset);
        }
        if matches!(line, b"\r\n" | b"\n") {
            let range = content_type?;
            let body = entity.get(offset..)?;
            return Some(if fields == 1 && range.start == 0 {
                Cow::Borrowed(entity)
            } else {
                let field = entity.get(range)?;
                let mut out = Vec::with_capacity(field.len().saturating_add(body.len()));
                out.extend_from_slice(field);
                out.extend_from_slice(body);
                Cow::Owned(out)
            });
        }
        if line.is_empty() || memchr(b':', line).is_none() {
            return None;
        }
        fields = fields.saturating_add(1);
        field_start = offset;
        offset = next;
    }
}

fn is_content_type(field: &[u8]) -> bool {
    field
        .split(|byte| *byte == b':')
        .next()
        .is_some_and(|name| {
            name.trim_ascii()
                .eq_ignore_ascii_case(CONTENT_TYPE.as_bytes())
        })
}
