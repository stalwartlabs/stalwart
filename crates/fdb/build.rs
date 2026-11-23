/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rustc-check-cfg=cfg(fine_timer)");
    if env::var("CARGO_CFG_TARGET_OS")
        .is_ok_and(|os| hashify::set!(os.as_bytes(), "linux", "freebsd", "macos"))
    {
        println!("cargo::rustc-cfg=fine_timer");
    }
}
