/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::Uid,
    tls::Plaintext,
    transport::PeerAddress,
    wire::{IpAddress, IpAddressValue, NetworkAddress, NetworkAddressList},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const FLAG_TLS: u16 = 2;
const INDEX_SHIFT: u32 = 32;
const HIGH_MASK: u64 = 0xffff_ffff_0000_0000;

pub(crate) const fn adjusted_token(base: Uid, index: u32) -> Uid {
    Uid::new(
        base.first.wrapping_add((index as u64) << INDEX_SHIFT),
        (base.second & HIGH_MASK) | (base.second as u32).wrapping_add(index) as u64,
    )
}

pub(crate) fn peer_address(
    addresses: &NetworkAddressList,
    tls: bool,
    plaintext: Plaintext,
) -> Option<PeerAddress> {
    let primary = addresses.address;
    let preferred = match addresses.secondary_address {
        Some(secondary) if is_tls(&primary) != tls => secondary,
        _ => primary,
    };
    let address = if is_tls(&preferred) || plaintext == Plaintext::Allowed {
        preferred
    } else {
        [Some(primary), addresses.secondary_address]
            .into_iter()
            .flatten()
            .find(is_tls)?
    };
    Some(PeerAddress::new(socket_addr(&address), is_tls(&address)))
}

pub(crate) fn network_address(addr: SocketAddr, tls: bool) -> NetworkAddress {
    NetworkAddress {
        ip: IpAddress {
            addr: match addr.ip() {
                IpAddr::V4(ip) => IpAddressValue::V4(ip.to_bits()),
                IpAddr::V6(ip) => IpAddressValue::V6(ip.octets()),
            },
        },
        port: addr.port(),
        flags: if tls { FLAG_TLS } else { 0 },
        from_hostname: false,
    }
}

pub(crate) fn socket_addr(address: &NetworkAddress) -> SocketAddr {
    let ip = match address.ip.addr {
        IpAddressValue::V4(ip) => IpAddr::V4(Ipv4Addr::from_bits(ip)),
        IpAddressValue::V6(ip) => IpAddr::V6(Ipv6Addr::from(ip)),
    };
    SocketAddr::new(ip, address.port)
}

const fn is_tls(address: &NetworkAddress) -> bool {
    address.flags & FLAG_TLS != 0
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/endpoint/tests.rs"]
mod tests;
