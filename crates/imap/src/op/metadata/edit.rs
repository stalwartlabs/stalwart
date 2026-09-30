/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use imap_proto::protocol::metadata::MetadataCode;
use std::borrow::Cow;
use store::write::metadata::MetadataBuf;
use types::metadata::{
    EncodedMetadata, MetadataBuilder, MetadataEdit, MetadataLimits, MetadataScope,
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ContainerUpdate {
    Unchanged,
    Clear,
    Replace(EncodedMetadata, MetadataEdit),
}

struct ContainerEdit<'x> {
    builder: MetadataBuilder<'x>,
    previous_size: usize,
    max_entries: usize,
    largest: usize,
    changed: bool,
}

pub(crate) fn edit_container<'x>(
    previous: Option<&'x MetadataBuf>,
    entries: impl Iterator<Item = (&'x str, Option<&'x [u8]>)> + Clone,
    scope: MetadataScope,
    limits: &MetadataLimits,
) -> Result<ContainerUpdate, MetadataCode> {
    let mut edit = ContainerEdit::new(previous, limits);
    for (name, _) in entries.clone().filter(|(_, value)| value.is_none()) {
        edit.remove(name);
    }
    for (name, value) in entries.filter_map(|(name, value)| value.map(|value| (name, value))) {
        edit.set(name, value, limits)?;
    }
    edit.finish(scope, limits)
}

impl<'x> ContainerEdit<'x> {
    fn new(previous: Option<&'x MetadataBuf>, limits: &MetadataLimits) -> Self {
        let view = previous.map(MetadataBuf::view);
        let previous_entries = view.as_ref().map_or(0, |view| view.len());
        ContainerEdit {
            builder: view
                .as_ref()
                .map_or_else(MetadataBuilder::new, MetadataBuilder::from_view),
            previous_size: view.map_or(0, |view| view.as_bytes().len()),
            max_entries: limits.max_entries.max(previous_entries),
            largest: 0,
            changed: false,
        }
    }

    fn remove(&mut self, name: &str) {
        self.changed |= self.builder.remove_imap(name);
    }

    fn set(
        &mut self,
        name: &'x str,
        value: &'x [u8],
        limits: &MetadataLimits,
    ) -> Result<(), MetadataCode> {
        limits
            .check_entry_size(value.len())
            .map_err(|_| MetadataCode::MaxSize(to_u32(limits.max_entry_size)))?;
        self.largest = self.largest.max(value.len());
        if self.builder.imap(name) != Some(value) {
            self.builder.set_imap(Cow::Borrowed(name), value);
            self.changed = true;
            if self.builder.len() > self.max_entries {
                return Err(MetadataCode::TooMany);
            }
        }
        Ok(())
    }

    fn finish(
        self,
        scope: MetadataScope,
        limits: &MetadataLimits,
    ) -> Result<ContainerUpdate, MetadataCode> {
        if !self.changed {
            return Ok(ContainerUpdate::Unchanged);
        }
        let edit = self.builder.edit();
        let Some(container) = self.builder.encode() else {
            return Ok(ContainerUpdate::Clear);
        };

        let max_size = limits.max_container_size(scope);
        let size = container.len();
        if size > max_size && size > self.previous_size {
            let available = (max_size + self.largest).saturating_sub(size);
            Err(MetadataCode::MaxSize(to_u32(
                available.min(limits.max_entry_size),
            )))
        } else {
            Ok(ContainerUpdate::Replace(container, edit))
        }
    }
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{ContainerUpdate, edit_container};
    use imap_proto::protocol::metadata::MetadataCode;
    use std::borrow::Cow;
    use store::write::metadata::{MetadataBuf, StoredMetadata};
    use types::metadata::{
        MetadataBuilder, MetadataEdit, MetadataKinds, MetadataLimits, MetadataScope,
    };

    fn limits() -> MetadataLimits {
        MetadataLimits {
            max_depth: None,
            max_entry_size: 16,
            max_size: 64,
            max_private_size: 32,
            max_entries: 3,
        }
    }

    fn stored(entries: &[(&str, &str)]) -> MetadataBuf {
        let mut builder = MetadataBuilder::new();
        for (name, value) in entries {
            builder.set_imap(Cow::Borrowed(name), value.as_bytes());
        }
        let container = builder.encode().expect("non-empty container");
        MetadataBuf::read(
            &StoredMetadata::new(container)
                .expect("serializable")
                .into_bytes(),
        )
        .expect("readable")
    }

    fn edit<'x>(
        previous: Option<&'x MetadataBuf>,
        entries: &'x [(&'x str, Option<&'x str>)],
        scope: MetadataScope,
    ) -> Result<ContainerUpdate, MetadataCode> {
        edit_container(
            previous,
            entries
                .iter()
                .map(|(name, value)| (*name, value.map(str::as_bytes))),
            scope,
            &limits(),
        )
    }

    fn entries(update: ContainerUpdate) -> Vec<(String, Vec<u8>)> {
        match update {
            ContainerUpdate::Replace(container, _) => {
                assert_eq!(container.kinds(), MetadataKinds::IMAP);
                container
                    .view()
                    .imap()
                    .map(|(name, value)| (name.to_string(), value.to_vec()))
                    .collect()
            }
            other => panic!("expected a new container, got {other:?}"),
        }
    }

    #[test]
    fn values_are_set_replaced_and_removed() {
        let previous = stored(&[("/a", "1"), ("/b", "2")]);

        assert_eq!(
            entries(
                edit(
                    Some(&previous),
                    &[("/a", None), ("/b", Some("x")), ("/c", Some("a\0b"))],
                    MetadataScope::Shared
                )
                .expect("valid edit")
            ),
            vec![
                ("/b".to_string(), b"x".to_vec()),
                ("/c".to_string(), b"a\0b".to_vec()),
            ]
        );
        assert_eq!(
            edit(None, &[("/a", Some(""))], MetadataScope::Shared).map(entries),
            Ok(vec![("/a".to_string(), Vec::new())])
        );
    }

    #[test]
    fn no_op_edits_leave_the_container_alone() {
        let previous = stored(&[("/a", "1")]);

        assert_eq!(
            edit(
                Some(&previous),
                &[("/a", Some("1")), ("/missing", None)],
                MetadataScope::Shared
            ),
            Ok(ContainerUpdate::Unchanged)
        );
        assert_eq!(
            edit(None, &[("/missing", None)], MetadataScope::Shared),
            Ok(ContainerUpdate::Unchanged)
        );
        assert_eq!(
            edit(Some(&previous), &[("/a", None)], MetadataScope::Shared),
            Ok(ContainerUpdate::Clear)
        );
    }

    #[test]
    fn limits_map_to_metadata_codes() {
        let full = stored(&[("/a", "1"), ("/b", "2"), ("/c", "3")]);

        assert_eq!(
            edit(
                None,
                &[("/a", Some("12345678901234567"))],
                MetadataScope::Shared
            ),
            Err(MetadataCode::MaxSize(16))
        );
        assert_eq!(
            edit(Some(&full), &[("/d", Some("4"))], MetadataScope::Shared),
            Err(MetadataCode::TooMany)
        );
        assert!(matches!(
            edit(
                Some(&full),
                &[("/a", None), ("/d", Some("4"))],
                MetadataScope::Shared
            ),
            Ok(ContainerUpdate::Replace(..))
        ));
        assert!(matches!(
            edit(
                None,
                &[("/a", Some("1234567890123456")), ("/b", Some("1234567890123456"))],
                MetadataScope::Private
            ),
            Err(MetadataCode::MaxSize(size)) if size < 16
        ));
        assert!(matches!(
            edit(
                None,
                &[
                    ("/a", Some("1234567890123456")),
                    ("/b", Some("1234567890123456"))
                ],
                MetadataScope::Shared
            ),
            Ok(ContainerUpdate::Replace(..))
        ));
    }

    #[test]
    fn edits_report_whether_they_only_remove_entries() {
        let previous = stored(&[("/a", "1"), ("/b", "2")]);

        for (entries, expected) in [
            (&[("/a", None)][..], MetadataEdit::RemovalOnly),
            (
                &[("/a", None), ("/b", Some("2"))],
                MetadataEdit::RemovalOnly,
            ),
            (&[("/a", None), ("/c", Some("3"))], MetadataEdit::Write),
            (&[("/b", Some("x"))], MetadataEdit::Write),
        ] {
            assert!(
                matches!(
                    edit(Some(&previous), entries, MetadataScope::Shared),
                    Ok(ContainerUpdate::Replace(_, edit)) if edit == expected
                ),
                "{entries:?}"
            );
        }
    }

    #[test]
    fn containers_above_lowered_limits_can_shrink() {
        let crowded = stored(&[("/a", "1"), ("/b", "2"), ("/c", "3"), ("/d", "4")]);

        assert!(matches!(
            edit(Some(&crowded), &[("/a", None)], MetadataScope::Shared),
            Ok(ContainerUpdate::Replace(_, MetadataEdit::RemovalOnly))
        ));
        assert!(matches!(
            edit(Some(&crowded), &[("/a", Some("9"))], MetadataScope::Shared),
            Ok(ContainerUpdate::Replace(_, MetadataEdit::Write))
        ));
        assert_eq!(
            edit(Some(&crowded), &[("/e", Some("5"))], MetadataScope::Shared),
            Err(MetadataCode::TooMany)
        );
    }
}
