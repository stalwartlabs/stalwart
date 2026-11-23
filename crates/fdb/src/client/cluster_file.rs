/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::api::{
    config::{ClusterSource, default_config_dir},
    error::OpenError,
};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, fchown};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

const CLUSTER_FILE_NAME: &str = "fdb.cluster";
const MAX_CLUSTER_FILE_BYTES: u64 = 60_000;
const TLS_SUFFIX: &str = ":tls";
const FROM_HOSTNAME_MARKER: &str = "(fromHostname)";
const PERSIST_HEADER: &str =
    "# DO NOT EDIT!\n# This file is auto-generated, it is not to be edited by hand\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Encryption {
    Plain,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CoordinatorAddress {
    pub(crate) addr: SocketAddr,
    pub(crate) encryption: Encryption,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CoordinatorHost {
    pub(crate) host: Box<str>,
    pub(crate) port: u16,
    pub(crate) encryption: Encryption,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionString {
    pub(crate) key: Box<str>,
    pub(crate) addresses: Vec<CoordinatorAddress>,
    pub(crate) hostnames: Vec<CoordinatorHost>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidConnectionString {
    NotAscii,
    MissingAt,
    MissingColon,
    InvalidDescription,
    InvalidId,
    InvalidAddress,
    DuplicateCoordinator,
}

pub(crate) struct ClusterFileRecord {
    pub(crate) path: Option<PathBuf>,
    pub(crate) connection: ConnectionString,
}

impl ClusterFileRecord {
    pub(crate) fn load(source: &ClusterSource) -> Result<Self, OpenError> {
        let path = match source {
            ClusterSource::Coordinators(connection) => {
                return Ok(ClusterFileRecord {
                    path: None,
                    connection: connection.clone(),
                });
            }
            ClusterSource::File(path) if !path.as_os_str().is_empty() => path.clone(),
            _ => default_cluster_file(),
        };
        let contents = read_capped(&path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => OpenError::ClusterFileNotFound,
            kind => OpenError::ClusterFileRead {
                path: path.clone(),
                kind,
            },
        })?;
        match ConnectionString::parse(&contents) {
            Ok(connection) => Ok(ClusterFileRecord {
                path: Some(path),
                connection,
            }),
            Err(reason) => Err(OpenError::ClusterFileInvalid {
                path,
                reason: reason.as_str().into(),
            }),
        }
    }

    pub(crate) fn changed_on_disk(&self) -> Option<ConnectionString> {
        read_capped(self.path.as_deref()?)
            .ok()
            .and_then(|contents| ConnectionString::parse(&contents).ok())
            .filter(|stored| *stored != self.connection)
    }

    pub(crate) fn persist(&self) -> io::Result<()> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let file_name = path
            .file_name()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut temp_name = file_name.to_os_string();
        temp_name.push(format!(
            ".{}.{:016x}.tmp",
            std::process::id(),
            fastrand::u64(..)
        ));
        let temp_path = path.with_file_name(temp_name);
        let write = || -> io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)?;
            match fs::metadata(path) {
                Ok(metadata) => {
                    #[cfg(unix)]
                    fchown(&file, Some(metadata.uid()), Some(metadata.gid()))?;
                    file.set_permissions(metadata.permissions())?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            writeln!(file, "{PERSIST_HEADER}{}", self.connection)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp_path, path)
        };
        write().inspect_err(|_| {
            let _ = fs::remove_file(&temp_path);
        })
    }
}

pub(crate) fn default_cluster_file() -> PathBuf {
    default_config_dir().join(CLUSTER_FILE_NAME)
}

fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let mut contents = Vec::new();
    File::open(path)?
        .take(MAX_CLUSTER_FILE_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_CLUSTER_FILE_BYTES {
        Err(io::Error::from(io::ErrorKind::FileTooLarge))
    } else {
        Ok(contents)
    }
}

impl ConnectionString {
    pub fn from_parts<'a>(
        description: &str,
        id: &str,
        coordinators: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, InvalidConnectionString> {
        Self::from_parts_inner(description, id, &mut coordinators.into_iter())
    }

    fn from_parts_inner(
        description: &str,
        id: &str,
        coordinators: &mut dyn Iterator<Item = &str>,
    ) -> Result<Self, InvalidConnectionString> {
        if !is_plain(description) {
            return Err(InvalidConnectionString::InvalidDescription);
        }
        if !is_plain(id) {
            return Err(InvalidConnectionString::InvalidId);
        }
        let mut text = String::with_capacity(description.len() + id.len() + 64);
        text.push_str(description);
        text.push(':');
        text.push_str(id);
        let mut separator = '@';
        for coordinator in coordinators {
            if !is_plain(coordinator) || coordinator.contains([',', '@']) {
                return Err(InvalidConnectionString::InvalidAddress);
            }
            text.push(separator);
            text.push_str(coordinator);
            separator = ',';
        }
        if separator == '@' {
            return Err(InvalidConnectionString::MissingAt);
        }
        Self::parse(text.as_bytes())
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub(crate) fn uses_tls(&self) -> bool {
        self.addresses
            .iter()
            .map(|address| address.encryption)
            .chain(self.hostnames.iter().map(|host| host.encryption))
            .any(|encryption| encryption == Encryption::Tls)
    }

    pub(crate) fn parse(contents: &[u8]) -> Result<Self, InvalidConnectionString> {
        let trimmed = trim(contents)?;
        let (key, coordinators) = trimmed
            .split_once('@')
            .ok_or(InvalidConnectionString::MissingAt)?;
        parse_key(key)?;

        let mut addresses: Vec<CoordinatorAddress> = Vec::new();
        let mut hostnames: Vec<CoordinatorHost> = Vec::new();
        for entry in coordinators.split(',') {
            if let Some(host) = parse_hostname(entry) {
                if hostnames.contains(&host) {
                    return Err(InvalidConnectionString::DuplicateCoordinator);
                }
                hostnames.push(host);
            } else {
                let address =
                    parse_address(entry).ok_or(InvalidConnectionString::InvalidAddress)?;
                if addresses.contains(&address) {
                    return Err(InvalidConnectionString::DuplicateCoordinator);
                }
                addresses.push(address);
            }
        }

        Ok(ConnectionString {
            key: key.into(),
            addresses,
            hostnames,
        })
    }
}

fn is_plain(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
}

fn trim(contents: &[u8]) -> Result<String, InvalidConnectionString> {
    let mut trimmed = String::with_capacity(contents.len());
    let mut bytes = contents.iter();
    while let Some(&byte) = bytes.next() {
        match byte {
            b'#' => {
                for &skipped in bytes.by_ref() {
                    if matches!(skipped, b'\n' | b'\r') {
                        break;
                    }
                }
            }
            b' ' | b'\n' | b'\r' | b'\t' => {}
            byte if byte.is_ascii() => trimmed.push(char::from(byte)),
            _ => return Err(InvalidConnectionString::NotAscii),
        }
    }
    Ok(trimmed)
}

fn parse_key(key: &str) -> Result<(), InvalidConnectionString> {
    let (description, id) = key
        .split_once(':')
        .ok_or(InvalidConnectionString::MissingColon)?;
    if !description
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        Err(InvalidConnectionString::InvalidDescription)
    } else if !id.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        Err(InvalidConnectionString::InvalidId)
    } else {
        Ok(())
    }
}

fn split_tls(entry: &str) -> (&str, Encryption) {
    match entry.strip_suffix(TLS_SUFFIX) {
        Some(rest) if !rest.is_empty() => (rest, Encryption::Tls),
        _ => (entry, Encryption::Plain),
    }
}

fn parse_port(port: &str) -> Option<u16> {
    if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
        port.parse().ok()
    } else {
        None
    }
}

fn parse_hostname(entry: &str) -> Option<CoordinatorHost> {
    let (rest, encryption) = split_tls(entry);
    let (host, port) = rest.rsplit_once(':')?;
    if is_hostname_shape(host) && !is_ipv4_shape(host) {
        Some(CoordinatorHost {
            host: host.into(),
            port: parse_port(port)?,
            encryption,
        })
    } else {
        None
    }
}

fn is_hostname_shape(host: &str) -> bool {
    host.bytes().next().is_some_and(|first| first != b'.')
        && !host.contains("..")
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn is_ipv4_shape(host: &str) -> bool {
    host.bytes()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
        && !host.contains("..")
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && host.bytes().filter(u8::is_ascii_digit).count() >= 4
}

fn parse_address(entry: &str) -> Option<CoordinatorAddress> {
    let entry = entry
        .split_once(FROM_HOSTNAME_MARKER)
        .map_or(entry, |(address, _)| address);
    let (rest, encryption) = split_tls(entry);
    let addr = if let Some(bracketed) = rest.strip_prefix('[') {
        let (ip, port) = bracketed.split_once(']')?;
        SocketAddr::new(
            ip.parse::<IpAddr>().ok()?,
            parse_port(port.strip_prefix(':')?)?,
        )
    } else {
        let (ip, port) = rest.rsplit_once(':')?;
        SocketAddr::new(IpAddr::V4(parse_ipv4(ip)?), parse_port(port)?)
    };
    Some(CoordinatorAddress { addr, encryption })
}

fn parse_ipv4(ip: &str) -> Option<Ipv4Addr> {
    let mut octets = [0u8; 4];
    let mut parts = ip.split('.');
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *octet = part.parse().ok()?;
    }
    if parts.next().is_some() {
        None
    } else {
        Some(Ipv4Addr::from(octets))
    }
}

impl InvalidConnectionString {
    pub fn as_str(self) -> &'static str {
        match self {
            InvalidConnectionString::NotAscii => "non-ASCII character",
            InvalidConnectionString::MissingAt => "missing '@'",
            InvalidConnectionString::MissingColon => "cluster key without ':'",
            InvalidConnectionString::InvalidDescription => "invalid character in description",
            InvalidConnectionString::InvalidId => "invalid character in cluster id",
            InvalidConnectionString::InvalidAddress => "invalid coordinator address",
            InvalidConnectionString::DuplicateCoordinator => "duplicate coordinator",
        }
    }
}

impl fmt::Display for InvalidConnectionString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for InvalidConnectionString {}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Encryption::Plain => Ok(()),
            Encryption::Tls => f.write_str(TLS_SUFFIX),
        }
    }
}

impl fmt::Display for CoordinatorAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr {
            SocketAddr::V4(addr) => write!(f, "{}:{}{}", addr.ip(), addr.port(), self.encryption),
            SocketAddr::V6(addr) => write!(f, "[{}]:{}{}", addr.ip(), addr.port(), self.encryption),
        }
    }
}

impl fmt::Display for CoordinatorHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}{}", self.host, self.port, self.encryption)
    }
}

impl fmt::Display for ConnectionString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@", self.key)?;
        let mut separator = "";
        for address in &self.addresses {
            write!(f, "{separator}{address}")?;
            separator = ",";
        }
        for host in &self.hostnames {
            write!(f, "{separator}{host}")?;
            separator = ",";
        }
        Ok(())
    }
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/client/cluster_file/tests.rs"]
mod tests;
