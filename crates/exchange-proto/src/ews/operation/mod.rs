/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod table;

pub use table::Operation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseShape {
    A,
    B,
    C,
    D,
}

macro_rules! operation_table {
    ($($op:ident = $req:literal => $resp:literal, $shape:ident, $msg:expr;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Operation {
            $($op),+
        }

        impl Operation {
            pub fn from_request_root(local: &[u8]) -> Option<Self> {
                hashify::map!(local, Operation, $($req => Operation::$op),+).copied()
            }

            pub const fn name(self) -> &'static str {
                match self {
                    $(Operation::$op => stringify!($op)),+
                }
            }

            pub const fn request_root(self) -> &'static str {
                match self {
                    $(Operation::$op => $req),+
                }
            }

            pub const fn response_root(self) -> &'static str {
                match self {
                    $(Operation::$op => $resp),+
                }
            }

            pub const fn shape(self) -> $crate::ews::operation::ResponseShape {
                match self {
                    $(Operation::$op => $crate::ews::operation::ResponseShape::$shape),+
                }
            }

            pub const fn message_element(self) -> Option<&'static str> {
                match self {
                    $(Operation::$op => $msg),+
                }
            }
        }
    };
}

use operation_table;
