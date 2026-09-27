/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, Copy)]
struct Searched {
    from: usize,
    found: Option<usize>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Seek {
    last: Option<Searched>,
}

impl Seek {
    pub(crate) fn find(
        &mut self,
        pos: usize,
        search: impl FnOnce(usize) -> Option<usize>,
    ) -> Option<usize> {
        if let Some(Searched { from, found }) = self.last
            && from <= pos
            && found.is_none_or(|found| found >= pos)
        {
            return found;
        }
        let found = search(pos);
        self.last = Some(Searched { from: pos, found });
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn repeated_queries_reuse_the_last_search() {
        let data = b"..x...x";
        let calls = Cell::new(0);
        let mut seek = Seek::default();
        let mut find = |pos: usize| {
            seek.find(pos, |from| {
                calls.set(calls.get() + 1);
                data.get(from..)?
                    .iter()
                    .position(|&byte| byte == b'x')
                    .map(|offset| from + offset)
            })
        };
        assert_eq!(find(0), Some(2));
        assert_eq!(find(1), Some(2));
        assert_eq!(find(2), Some(2));
        assert_eq!(calls.get(), 1);
        assert_eq!(find(3), Some(6));
        assert_eq!(find(7), None);
        assert_eq!(find(9), None);
        assert_eq!(calls.get(), 3);
        assert_eq!(find(4), Some(6));
        assert_eq!(calls.get(), 4);
    }
}
