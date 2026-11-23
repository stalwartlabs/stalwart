/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::version::Version;
use super::{
    KEYSPACE_END,
    error::{Error, ErrorCode, Result},
    page::{KeyPage, RangePage},
    read::Snapshot,
};
use crate::{
    client::{Cluster, CursorState, cursor::Scan, expiry::Expiry, transaction::Cancellation},
    codec::kv::KeyValuesBuf,
};
use bytes::Bytes;
use std::{num::NonZeroU32, ops::Bound};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    Forward,
    Reverse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSize {
    rows: Option<NonZeroU32>,
    bytes: NonZeroU32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Readahead {
    #[default]
    Off,
    Next,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RangeOptions {
    pub direction: Direction,
    pub page: PageSize,
    pub readahead: Readahead,
}

pub struct RangeCursor<'k> {
    pub(crate) core: CursorCore<'k>,
}

pub struct KeyCursor<'k> {
    pub(crate) core: CursorCore<'k>,
}

pub(crate) struct CursorCore<'k> {
    pub(crate) begin: Bound<&'k [u8]>,
    pub(crate) end: Bound<&'k [u8]>,
    pub(crate) options: RangeOptions,
    pub(crate) state: CursorState,
}

impl PageSize {
    pub const DEFAULT_BYTES: NonZeroU32 = NonZeroU32::MIN.saturating_add(79_999);
    pub const MAX_BYTES: NonZeroU32 = NonZeroU32::MIN.saturating_add(1_899_999);
    pub const MAX_ROWS: NonZeroU32 = NonZeroU32::MIN.saturating_add(i32::MAX as u32 - 1);

    pub const fn new(rows: Option<NonZeroU32>, bytes: NonZeroU32) -> Self {
        PageSize {
            rows: match rows {
                Some(rows) if rows.get() > Self::MAX_ROWS.get() => Some(Self::MAX_ROWS),
                rows => rows,
            },
            bytes: if bytes.get() > Self::MAX_BYTES.get() {
                Self::MAX_BYTES
            } else {
                bytes
            },
        }
    }

    pub const fn with_bytes(bytes: NonZeroU32) -> Self {
        PageSize::new(None, bytes)
    }

    pub const fn with_rows(rows: NonZeroU32) -> Self {
        PageSize::new(Some(rows), Self::DEFAULT_BYTES)
    }

    pub const fn rows(&self) -> Option<NonZeroU32> {
        self.rows
    }

    pub const fn bytes(&self) -> NonZeroU32 {
        self.bytes
    }
}

impl Default for PageSize {
    fn default() -> Self {
        PageSize::with_bytes(Self::DEFAULT_BYTES)
    }
}

impl<'k> CursorCore<'k> {
    fn new(begin: Bound<&'k [u8]>, end: Bound<&'k [u8]>, options: RangeOptions) -> Result<Self> {
        let (begin_key, end_key) = bound_keys(begin, end);
        if begin_key >= KEYSPACE_END
            || end_key > KEYSPACE_END
            || (end_key == KEYSPACE_END && matches!(end, Bound::Included(_)))
        {
            Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE))
        } else if begin_key > end_key {
            Err(Error::new(ErrorCode::INVERTED_RANGE))
        } else {
            Ok(CursorCore {
                begin,
                end,
                options,
                state: CursorState::new(),
            })
        }
    }

    fn seek(&mut self, position: Bound<Bytes>) -> Result<()> {
        let (begin_key, end_key) = bound_keys(self.begin, self.end);
        if let Bound::Included(key) | Bound::Excluded(key) = &position
            && (key.as_ref() < begin_key || key.as_ref() > end_key)
        {
            return Err(Error::new(ErrorCode::KEY_OUTSIDE_LEGAL_RANGE));
        }
        self.state.seek(
            self.begin,
            self.end,
            position.as_ref().map(Bytes::as_ref),
            self.options.direction,
        );
        Ok(())
    }

    fn is_done(&self) -> bool {
        self.state.is_done(self.begin, self.end)
    }

    pub(crate) fn next_page<'a>(
        &'a mut self,
        cluster: &'a Cluster,
        version: Version,
        cancel: Option<&'a Cancellation>,
        read: impl FnMut(&[u8], &[u8]) + 'a,
    ) -> impl Future<Output = Result<Option<KeyValuesBuf>>> + 'a {
        let CursorCore {
            begin,
            end,
            options,
            state,
        } = self;
        state.next_page(
            cluster,
            Scan {
                begin: *begin,
                end: *end,
                direction: options.direction,
                page: options.page,
                readahead: options.readahead,
                version,
                cancel,
            },
            read,
        )
    }

    fn next_snapshot<'a>(
        &'a mut self,
        snapshot: Snapshot<'a>,
    ) -> Result<Expiry<'a, impl Future<Output = Result<Option<KeyValuesBuf>>> + 'a>> {
        self.state.enter_snapshot()?;
        let cluster = &snapshot.db.cluster;
        Ok(cluster.expiry(
            snapshot.deadline,
            self.next_page(cluster, snapshot.version, None, |_, _| {}),
        ))
    }
}

fn bound_keys<'k>(begin: Bound<&'k [u8]>, end: Bound<&'k [u8]>) -> (&'k [u8], &'k [u8]) {
    let begin_key = match begin {
        Bound::Included(key) | Bound::Excluded(key) => key,
        Bound::Unbounded => b"",
    };
    let end_key = match end {
        Bound::Included(key) | Bound::Excluded(key) => key,
        Bound::Unbounded => KEYSPACE_END,
    };
    (begin_key, end_key)
}

impl<'k> RangeCursor<'k> {
    pub fn new(
        begin: Bound<&'k [u8]>,
        end: Bound<&'k [u8]>,
        options: RangeOptions,
    ) -> Result<Self> {
        CursorCore::new(begin, end, options).map(|core| RangeCursor { core })
    }

    pub fn options(&self) -> &RangeOptions {
        &self.core.options
    }

    pub fn set_page(&mut self, page: PageSize) {
        self.core.options.page = page;
    }

    pub fn is_done(&self) -> bool {
        self.core.is_done()
    }

    pub fn restart(&mut self) {
        self.core.state.restart();
    }

    pub fn seek(&mut self, position: Bound<Bytes>) -> Result<()> {
        self.core.seek(position)
    }

    pub async fn next(&mut self, snapshot: Snapshot<'_>) -> Result<Option<RangePage>> {
        self.core
            .next_snapshot(snapshot)?
            .await
            .map(|rows| rows.map(RangePage::from_rows))
    }
}

impl<'k> KeyCursor<'k> {
    pub fn new(
        begin: Bound<&'k [u8]>,
        end: Bound<&'k [u8]>,
        options: RangeOptions,
    ) -> Result<Self> {
        CursorCore::new(begin, end, options).map(|core| KeyCursor { core })
    }

    pub fn options(&self) -> &RangeOptions {
        &self.core.options
    }

    pub fn set_page(&mut self, page: PageSize) {
        self.core.options.page = page;
    }

    pub fn is_done(&self) -> bool {
        self.core.is_done()
    }

    pub fn restart(&mut self) {
        self.core.state.restart();
    }

    pub fn seek(&mut self, position: Bound<Bytes>) -> Result<()> {
        self.core.seek(position)
    }

    pub async fn next(&mut self, snapshot: Snapshot<'_>) -> Result<Option<KeyPage>> {
        self.core
            .next_snapshot(snapshot)?
            .await
            .map(|rows| rows.map(KeyPage::from_rows))
    }
}
