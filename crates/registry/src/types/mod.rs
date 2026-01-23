/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod datetime;
pub mod duration;
pub mod error;
pub mod id;
pub mod ipaddr;
pub mod ipmask;
pub mod socketaddr;

pub trait EnumType: Sized {
    fn parse(s: &str) -> Option<Self>;
    fn as_str(&self) -> &'static str;
    fn from_id(id: u16) -> Option<Self>;
    fn to_id(&self) -> u16;
}
