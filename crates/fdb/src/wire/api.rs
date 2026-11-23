/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::{
    codec::{Uid, kv::KeyValues},
    wire::List,
};

#[derive(Debug, Clone)]
pub struct OpenDatabaseCoordRequest<'a, Coordinators, Hostnames> {
    pub known_client_info_id: Uid,
    pub cluster_key: &'a [u8],
    pub coordinators: Coordinators,
    pub hostnames: Hostnames,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAddress {
    pub ip: IpAddress,
    pub port: u16,
    pub flags: u16,
    pub from_hostname: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddress {
    pub addr: IpAddressValue,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hostname<'a> {
    pub host: &'a [u8],
    pub service: &'a [u8],
    pub is_tls: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetReadVersionRequest {
    pub transaction_count: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetKeyServerLocationsRequest<'a> {
    pub begin: &'a [u8],
    pub end: Option<&'a [u8]>,
    pub limit: i32,
    pub reverse: bool,
    pub version: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetValueRequest<'a> {
    pub key: &'a [u8],
    pub version: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetKeyRequest<'a> {
    pub sel: KeySelector<'a>,
    pub version: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeySelector<'a> {
    pub key: &'a [u8],
    pub or_equal: bool,
    pub offset: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetKeyValuesRequest<'a> {
    pub begin: KeySelector<'a>,
    pub end: KeySelector<'a>,
    pub version: i64,
    pub limit: i32,
    pub limit_bytes: i32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetKeyValuesStreamRequest<'a> {
    pub begin: KeySelector<'a>,
    pub end: KeySelector<'a>,
    pub version: i64,
    pub limit: i32,
    pub limit_bytes: i32,
}

#[derive(Debug, Clone)]
pub struct CommitTransactionRequest<ReadConflictRanges, WriteConflictRanges, Mutations> {
    pub read_conflict_ranges: ReadConflictRanges,
    pub write_conflict_ranges: WriteConflictRanges,
    pub mutations: Mutations,
    pub read_snapshot: i64,
    pub report_conflicting_keys: bool,
    pub lock_aware: bool,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyRange<'a> {
    pub begin: &'a [u8],
    pub end: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Mutation<'a> {
    pub kind: u8,
    pub param1: &'a [u8],
    pub param2: &'a [u8],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PingRequest {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolInfoRequest {}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AcknowledgementReply {
    pub bytes: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientDBInfo<'a> {
    pub grv_proxies: List<'a, GrvProxyInterface>,
    pub commit_proxies: List<'a, CommitProxyInterface>,
    pub id: Uid,
    pub forward: Option<&'a [u8]>,
}

impl ClientDBInfo<'_> {
    pub const MAX_GRV_PROXIES: usize = 256;
    pub const MAX_COMMIT_PROXIES: usize = 256;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrvProxyInterface {
    pub provisional: bool,
    pub get_consistent_read_version: RequestStream,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestStream {
    pub endpoint: Endpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub addresses: NetworkAddressList,
    pub token: Uid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkAddressList {
    pub address: NetworkAddress,
    pub secondary_address: Option<NetworkAddress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitProxyInterface {
    pub provisional: bool,
    pub commit: RequestStream,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GetReadVersionReply<'a> {
    pub process_busy_time: i32,
    pub version: i64,
    pub locked: bool,
    pub metadata_version: Option<&'a [u8]>,
    pub rk_default_throttled: bool,
    pub rk_batch_throttled: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct GetKeyServerLocationsReply<'a> {
    pub results: List<'a, ShardLocations<'a>>,
}

impl GetKeyServerLocationsReply<'_> {
    pub const MAX_RESULTS: usize = 1000;
}

#[derive(Debug, Clone, Copy)]
pub struct ShardLocations<'a> {
    pub range: KeyRange<'a>,
    pub servers: List<'a, StorageServerInterface<'a>>,
}

impl ShardLocations<'_> {
    pub const MAX_SERVERS: usize = 32;
}

#[derive(Debug, Clone, Copy)]
pub struct StorageServerInterface<'a> {
    pub id: Uid,
    pub locality: Locality<'a>,
    pub get_value: RequestStream,
    pub tss_pair_id: Option<Uid>,
    pub accepting_requests: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Locality<'a> {
    pub entries: List<'a, LocalityEntry<'a>>,
}

impl Locality<'_> {
    pub const MAX_ENTRIES: usize = 64;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocalityEntry<'a> {
    pub key: &'a [u8],
    pub value: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GetValueReply<'a> {
    pub penalty: f64,
    pub error: Option<ReplyError>,
    pub value: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplyError {
    pub code: u16,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GetKeyReply<'a> {
    pub penalty: f64,
    pub error: Option<ReplyError>,
    pub sel: KeySelector<'a>,
}

#[derive(Debug, Clone, Copy)]
pub struct GetKeyValuesReply<'a> {
    pub penalty: f64,
    pub error: Option<ReplyError>,
    pub data: KeyValues<'a>,
    pub more: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct GetKeyValuesStreamReply<'a> {
    pub acknowledge_token: Option<Uid>,
    pub sequence: u16,
    pub data: KeyValues<'a>,
    pub more: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitID<'a> {
    pub version: i64,
    pub conflicting_key_ranges: Option<&'a [[u8; 4]]>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProtocolInfoReply {
    pub version: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Void {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAddressValue {
    V4(u32),
    V6([u8; 16]),
}
