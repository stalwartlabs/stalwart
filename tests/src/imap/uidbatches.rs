/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{AssertResult, ImapConnection, Type};
use imap_proto::ResponseType;

pub async fn test(imap: &mut ImapConnection, _imap_check: &mut ImapConnection) {
    println!("Running UIDBATCHES tests...");

    // The capability is only advertised once authenticated
    imap.send("CAPABILITY").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("UIDBATCHES");

    imap.send("SELECT INBOX").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;

    // A batch size below the configured minimum is rejected with TOOFEW
    imap.send("UIDBATCHES 10").await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("TOOFEW");

    // Reversed batch ranges are a client bug
    imap.send("UIDBATCHES 500 20:10").await;
    imap.assert_read(Type::Tagged, ResponseType::Bad)
        .await
        .assert_response_code("CLIENTBUG");

    // More batches than the server is willing to return
    imap.send("UIDBATCHES 500 1:100000").await;
    imap.assert_read(Type::Tagged, ResponseType::No)
        .await
        .assert_response_code("TOOMANY");

    // Malformed arguments
    for command in ["UIDBATCHES", "UIDBATCHES abc", "UIDBATCHES 500 10"] {
        imap.send(command).await;
        imap.assert_read(Type::Tagged, ResponseType::Bad).await;
    }

    // INBOX holds fewer messages than one batch, so a single range covering
    // the whole UID space is returned and it always reaches down to UID 1
    imap.send("UIDBATCHES 500").await;
    let response = imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* UIDBATCHES (TAG ")
        .assert_contains(":1");
    let ranges = parse_ranges(&response);
    assert_eq!(ranges.len(), 1, "Expected a single batch, got {ranges:?}");
    assert_eq!(ranges[0].1, 1, "The last batch must reach UID 1");

    // Requesting a batch range beyond what exists returns an empty response
    imap.send("UIDBATCHES 500 50:60").await;
    let response = imap
        .assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("* UIDBATCHES (TAG ");
    assert!(
        parse_ranges(&response).is_empty(),
        "Expected no ranges, got {response:?}"
    );

    // Asking for the first batch explicitly matches the unbounded form
    imap.send("UIDBATCHES 500 1:1").await;
    let response = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    assert_eq!(parse_ranges(&response), ranges);

    // UIDBATCHES must never populate the SEARCHRES $ variable
    imap.send("UID SEARCH RETURN (SAVE) ALL").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UIDBATCHES 500").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    imap.send("UID FETCH $ (UID)").await;
    imap.assert_read(Type::Tagged, ResponseType::Ok)
        .await
        .assert_contains("FETCH");

    // Every batch must tile the UID space with no gaps
    imap.send("UIDBATCHES 500").await;
    let response = imap.assert_read(Type::Tagged, ResponseType::Ok).await;
    let ranges = parse_ranges(&response);
    for window in ranges.windows(2) {
        assert_eq!(
            window[1].0,
            window[0].1 - 1,
            "Batches must be contiguous, got {ranges:?}"
        );
    }
}

fn parse_ranges(response: &[String]) -> Vec<(u32, u32)> {
    let line = response
        .iter()
        .find(|line| line.contains("* UIDBATCHES (TAG "))
        .unwrap_or_else(|| panic!("No UIDBATCHES response in {response:?}"));
    let Some((_, list)) = line.split_once(") ") else {
        return Vec::new();
    };

    list.trim()
        .split(',')
        .filter(|range| !range.is_empty())
        .map(|range| {
            let (high, low) = range
                .split_once(':')
                .unwrap_or_else(|| panic!("Malformed UID range {range:?}"));
            (high.parse().unwrap(), low.parse().unwrap())
        })
        .collect()
}
