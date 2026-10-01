/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::has_message_id;
use store::U128_LEN;

fn reference(a: &[u128], b: &[u8]) -> bool {
    b.as_chunks::<U128_LEN>()
        .0
        .iter()
        .any(|chunk| a.contains(&u128::from_be_bytes(*chunk)))
}

fn encode(ids: &[u128]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.to_be_bytes()).collect()
}

#[test]
fn has_message_id_matches_a_linear_search() {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        u128::from(state % 64)
    };

    for round in 0..2000 {
        let mut a = (0..round % 7).map(|_| next()).collect::<Vec<_>>();
        let mut b = (0..round % 11).map(|_| next()).collect::<Vec<_>>();
        a.sort_unstable();
        b.sort_unstable();
        let mut encoded = encode(&b);
        if round % 5 == 0 {
            encoded.extend_from_slice(&[0xff; 7]);
        }

        assert_eq!(
            has_message_id(&a, &encoded),
            reference(&a, &encoded),
            "a={a:?} b={b:?}"
        );
    }

    assert!(!has_message_id(&[], &encode(&[1, 2])));
    assert!(!has_message_id(&[1, 2], &[]));
    assert!(has_message_id(&[u128::MAX], &encode(&[0, u128::MAX])));
}
