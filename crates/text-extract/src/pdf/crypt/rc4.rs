/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(crate) struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut state = [0u8; 256];
        for (slot, value) in state.iter_mut().zip(0u8..=255) {
            *slot = value;
        }
        let mut j = 0u8;
        for (i, key_byte) in (0..256usize).zip(key.iter().cycle()) {
            j = j.wrapping_add(state[i]).wrapping_add(*key_byte);
            state.swap(i, usize::from(j));
        }
        Rc4 { state, i: 0, j: 0 }
    }

    fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        let si = self.state[usize::from(self.i)];
        self.j = self.j.wrapping_add(si);
        self.state.swap(usize::from(self.i), usize::from(self.j));
        let sj = self.state[usize::from(self.i)];
        self.state[usize::from(si.wrapping_add(sj))]
    }

    pub(crate) fn apply_in_place(&mut self, data: &mut [u8]) {
        for byte in data {
            *byte ^= self.next_byte();
        }
    }

    pub(crate) fn apply_into(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.reserve(data.len());
        out.extend(data.iter().map(|byte| byte ^ self.next_byte()));
    }
}
