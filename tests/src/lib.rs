/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[cfg(test)]
use ::store::registry::bootstrap::Bootstrap;
#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
use jemallocator::Jemalloc;

#[cfg(not(any(target_env = "msvc", target_os = "freebsd")))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[cfg(test)]
pub mod automation;
#[cfg(test)]
pub mod cluster;
#[cfg(test)]
pub mod directory;
#[cfg(test)]
pub mod imap;
#[cfg(test)]
pub mod jmap;
#[cfg(test)]
pub mod smtp;
#[cfg(test)]
pub mod store;
#[cfg(test)]
pub mod system;
#[cfg(test)]
pub mod telemetry;
#[cfg(test)]
pub mod utils;
#[cfg(test)]
pub mod webdav;

#[cfg(test)]
pub trait AssertConfig {
    fn assert_no_errors(self) -> Self;
    fn assert_no_warnings(self) -> Self;
}

#[cfg(test)]
impl AssertConfig for Bootstrap {
    fn assert_no_errors(self) -> Self {
        if !self.errors.is_empty() {
            panic!("Errors: {:#?}", self.errors);
        }
        self
    }

    fn assert_no_warnings(self) -> Self {
        if !self.warnings.is_empty() {
            panic!("Warnings: {:#?}", self.warnings);
        }
        self
    }
}
