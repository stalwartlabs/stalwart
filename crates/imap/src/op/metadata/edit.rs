/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use common::storage::metadata::ContainerChange;
use imap_proto::protocol::metadata::MetadataCode;
use std::borrow::Cow;
use store::write::metadata::MetadataBuf;
use types::metadata::{EntryBound, LimitViolation, MetadataBuilder, MetadataLimits, MetadataScope};

struct ContainerEdit<'x> {
    builder: MetadataBuilder<'x>,
    previous_len: usize,
    previous_entries: usize,
    entry_bound: EntryBound,
    largest: usize,
    changed: bool,
}

pub(crate) fn edit_container<'x>(
    previous: Option<&'x MetadataBuf>,
    entries: impl Iterator<Item = (&'x str, Option<&'x [u8]>)> + Clone,
    scope: MetadataScope,
    limits: &MetadataLimits,
) -> Result<Option<ContainerChange>, MetadataCode> {
    let mut edit = ContainerEdit::new(previous, limits);
    for (name, _) in entries.clone().filter(|(_, value)| value.is_none()) {
        edit.remove(name);
    }
    for (name, value) in entries.filter_map(|(name, value)| value.map(|value| (name, value))) {
        edit.set(name, value, limits)?;
    }
    edit.finish(previous, scope, limits)
}

impl<'x> ContainerEdit<'x> {
    fn new(previous: Option<&'x MetadataBuf>, limits: &MetadataLimits) -> Self {
        let view = previous.map(MetadataBuf::view);
        let (previous_len, previous_entries) = view
            .as_ref()
            .map_or((0, 0), |view| (view.as_bytes().len(), view.len()));
        ContainerEdit {
            builder: view
                .as_ref()
                .map_or_else(MetadataBuilder::new, MetadataBuilder::from_view),
            previous_len,
            previous_entries,
            entry_bound: limits.entry_bound(previous_entries),
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
            self.entry_bound
                .check(self.builder.len(), 0)
                .map_err(|_| MetadataCode::TooMany)?;
        }
        Ok(())
    }

    fn finish(
        self,
        previous: Option<&MetadataBuf>,
        scope: MetadataScope,
        limits: &MetadataLimits,
    ) -> Result<Option<ContainerChange>, MetadataCode> {
        if !self.changed {
            return Ok(None);
        }
        let edit = self.builder.edit();
        let next = self.builder.encode();
        if let Some(next) = &next {
            match limits.check_edit(scope, self.previous_len, self.previous_entries, next) {
                Ok(()) => {}
                Err(LimitViolation::ContainerSize { size, max }) => {
                    let available = (max + self.largest).saturating_sub(size);
                    return Err(MetadataCode::MaxSize(to_u32(
                        available.min(limits.max_entry_size),
                    )));
                }
                Err(_) => return Err(MetadataCode::TooMany),
            }
        }
        Ok(ContainerChange::new(previous, next, edit))
    }
}

fn to_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::edit_container;
    use common::storage::metadata::ContainerChange;
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
    ) -> Result<Option<ContainerChange>, MetadataCode> {
        edit_container(
            previous,
            entries
                .iter()
                .map(|(name, value)| (*name, value.map(str::as_bytes))),
            scope,
            &limits(),
        )
    }

    fn entries(change: Option<ContainerChange>) -> Vec<(String, Vec<u8>)> {
        let container = change
            .and_then(ContainerChange::into_next)
            .expect("a new container");
        assert_eq!(container.kinds(), MetadataKinds::IMAP);
        container
            .view()
            .imap()
            .map(|(name, value)| (name.to_string(), value.to_vec()))
            .collect()
    }

    fn replaced(result: Result<Option<ContainerChange>, MetadataCode>) -> Option<MetadataEdit> {
        match result {
            Ok(Some(change)) if change.next().is_some() => Some(change.edit()),
            _ => None,
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
            Ok(None)
        );
        assert_eq!(
            edit(None, &[("/missing", None)], MetadataScope::Shared),
            Ok(None)
        );
        let clear = edit(Some(&previous), &[("/a", None)], MetadataScope::Shared)
            .expect("valid edit")
            .expect("changed");
        assert!(clear.next().is_none());
        assert_eq!(
            clear.previous().map(|previous| previous.size),
            Some(previous.stored_len())
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
        assert!(
            replaced(edit(
                Some(&full),
                &[("/a", None), ("/d", Some("4"))],
                MetadataScope::Shared
            ))
            .is_some()
        );
        assert!(matches!(
            edit(
                None,
                &[("/a", Some("1234567890123456")), ("/b", Some("1234567890123456"))],
                MetadataScope::Private
            ),
            Err(MetadataCode::MaxSize(size)) if size < 16
        ));
        assert!(
            replaced(edit(
                None,
                &[
                    ("/a", Some("1234567890123456")),
                    ("/b", Some("1234567890123456"))
                ],
                MetadataScope::Shared
            ))
            .is_some()
        );
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
            assert_eq!(
                replaced(edit(Some(&previous), entries, MetadataScope::Shared)),
                Some(expected),
                "{entries:?}"
            );
        }
    }

    #[test]
    fn containers_above_lowered_limits_can_shrink() {
        let crowded = stored(&[("/a", "1"), ("/b", "2"), ("/c", "3"), ("/d", "4")]);

        assert_eq!(
            replaced(edit(Some(&crowded), &[("/a", None)], MetadataScope::Shared)),
            Some(MetadataEdit::RemovalOnly)
        );
        assert_eq!(
            replaced(edit(
                Some(&crowded),
                &[("/a", Some("9"))],
                MetadataScope::Shared
            )),
            Some(MetadataEdit::Write)
        );
        assert_eq!(
            edit(Some(&crowded), &[("/e", Some("5"))], MetadataScope::Shared),
            Err(MetadataCode::TooMany)
        );
    }
}
