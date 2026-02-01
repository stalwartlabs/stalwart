/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{
    fmt::{Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::pickle::{Pickle, PickledStream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddrOrMask {
    V4 { addr: Ipv4Addr, mask: u32 },
    V6 { addr: Ipv6Addr, mask: u128 },
}

impl IpAddrOrMask {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(addr) => IpAddrOrMask::V4 {
                addr,
                mask: u32::MAX,
            },
            IpAddr::V6(addr) => IpAddrOrMask::V6 {
                addr,
                mask: u128::MAX,
            },
        }
    }

    pub fn is_valid(&self) -> bool {
        !matches!(
            self,
            IpAddrOrMask::V4 { addr, mask: _ } if addr == &Ipv4Addr::UNSPECIFIED
        )
    }

    pub fn try_to_ip(&self) -> Option<IpAddr> {
        match self {
            IpAddrOrMask::V4 { addr, mask } if *mask == u32::MAX => Some(IpAddr::V4(*addr)),
            IpAddrOrMask::V6 { addr, mask } if *mask == u128::MAX => Some(IpAddr::V6(*addr)),
            _ => None,
        }
    }

    pub fn into_inner(self) -> (IpAddr, u128) {
        match self {
            IpAddrOrMask::V4 { addr, mask } => (IpAddr::V4(addr), mask as u128),
            IpAddrOrMask::V6 { addr, mask } => (IpAddr::V6(addr), mask),
        }
    }

    pub fn matches(&self, remote: &IpAddr) -> bool {
        match self {
            IpAddrOrMask::V4 { addr, mask } => match *mask {
                u32::MAX => match remote {
                    IpAddr::V4(remote) => addr == remote,
                    IpAddr::V6(remote) => {
                        if let Some(remote) = remote.to_ipv4_mapped() {
                            addr == &remote
                        } else {
                            false
                        }
                    }
                },
                0 => {
                    matches!(remote, IpAddr::V4(_))
                }
                _ => {
                    u32::from_be_bytes(match remote {
                        IpAddr::V4(ip) => ip.octets(),
                        IpAddr::V6(ip) => {
                            if let Some(ip) = ip.to_ipv4() {
                                ip.octets()
                            } else {
                                return false;
                            }
                        }
                    }) & mask
                        == u32::from_be_bytes(addr.octets()) & mask
                }
            },
            IpAddrOrMask::V6 { addr, mask } => match *mask {
                u128::MAX => match remote {
                    IpAddr::V6(remote) => remote == addr,
                    IpAddr::V4(remote) => &remote.to_ipv6_mapped() == addr,
                },
                0 => {
                    matches!(remote, IpAddr::V6(_))
                }
                _ => {
                    u128::from_be_bytes(match remote {
                        IpAddr::V6(ip) => ip.octets(),
                        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    }) & mask
                        == u128::from_be_bytes(addr.octets()) & mask
                }
            },
        }
    }
}

impl FromStr for IpAddrOrMask {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Some((addr, mask)) = value.rsplit_once('/') {
            if let (Ok(addr), Ok(mask)) =
                (addr.trim().parse::<IpAddr>(), mask.trim().parse::<u32>())
            {
                match addr {
                    IpAddr::V4(addr) if (8..=32).contains(&mask) => {
                        return Ok(IpAddrOrMask::V4 {
                            addr,
                            mask: u32::MAX << (32 - mask),
                        });
                    }
                    IpAddr::V6(addr) if (8..=128).contains(&mask) => {
                        return Ok(IpAddrOrMask::V6 {
                            addr,
                            mask: u128::MAX << (128 - mask),
                        });
                    }
                    _ => (),
                }
            }
        } else {
            match value.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(addr)) => {
                    return Ok(IpAddrOrMask::V4 {
                        addr,
                        mask: u32::MAX,
                    });
                }
                Ok(IpAddr::V6(addr)) => {
                    return Ok(IpAddrOrMask::V6 {
                        addr,
                        mask: u128::MAX,
                    });
                }
                _ => (),
            }
        }

        Err(format!("Invalid IP address {:?}", value,))
    }
}

impl Display for IpAddrOrMask {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            IpAddrOrMask::V4 { addr, mask } => {
                if (*mask) == u32::MAX {
                    write!(f, "{}", addr)
                } else {
                    let prefix = mask.count_ones();
                    write!(f, "{}/{}", addr, prefix)
                }
            }
            IpAddrOrMask::V6 { addr, mask } => {
                if (*mask) == u128::MAX {
                    write!(f, "{}", addr)
                } else {
                    let prefix = mask.count_ones();
                    write!(f, "{}/{}", addr, prefix)
                }
            }
        }
    }
}

impl serde::Serialize for IpAddrOrMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> serde::Deserialize<'de> for IpAddrOrMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        IpAddrOrMask::from_str(<&str>::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid IpAddrOrMask"))
    }
}

impl Default for IpAddrOrMask {
    fn default() -> Self {
        IpAddrOrMask::V4 {
            addr: Ipv4Addr::UNSPECIFIED,
            mask: u32::MAX,
        }
    }
}

impl Pickle for IpAddrOrMask {
    fn pickle(&self, out: &mut Vec<u8>) {
        match self {
            IpAddrOrMask::V4 { addr, mask } => {
                out.push(4);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&mask.to_le_bytes());
            }
            IpAddrOrMask::V6 { addr, mask } => {
                out.push(6);
                out.extend_from_slice(&addr.octets());
                out.extend_from_slice(&mask.to_le_bytes());
            }
        }
    }

    fn unpickle(data: &mut PickledStream<'_>) -> Option<Self> {
        match data.read()? {
            4 => {
                let mut addr_arr = [0u8; 4];
                addr_arr.copy_from_slice(data.read_bytes(4)?);
                let mut mask_arr = [0u8; 4];
                mask_arr.copy_from_slice(data.read_bytes(4)?);
                Some(IpAddrOrMask::V4 {
                    addr: Ipv4Addr::from(addr_arr),
                    mask: u32::from_le_bytes(mask_arr),
                })
            }
            6 => {
                let mut addr_arr = [0u8; 16];
                addr_arr.copy_from_slice(data.read_bytes(16)?);
                let mut mask_arr = [0u8; 16];
                mask_arr.copy_from_slice(data.read_bytes(16)?);
                Some(IpAddrOrMask::V6 {
                    addr: Ipv6Addr::from(addr_arr),
                    mask: u128::from_le_bytes(mask_arr),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipaddrmask() {
        for (mask, ip) in [
            ("10.0.0.0/8", "10.30.20.11"),
            ("10.0.0.0/8", "10.0.13.73"),
            ("192.168.1.1", "192.168.1.1"),
        ] {
            let mask = IpAddrOrMask::from_str(mask).unwrap();
            let ip = ip.parse::<IpAddr>().unwrap();
            assert!(mask.matches(&ip));
        }

        for (mask, ip) in [
            ("10.0.0.0/8", "11.30.20.11"),
            ("192.168.1.1", "193.168.1.1"),
        ] {
            let mask = IpAddrOrMask::from_str(mask).unwrap();
            let ip = ip.parse::<IpAddr>().unwrap();
            assert!(!mask.matches(&ip));
        }
    }
}
