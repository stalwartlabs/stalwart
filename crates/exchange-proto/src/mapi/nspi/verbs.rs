/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    arrays::{AsciiStrings, BinaryArray, MidArray, PropTagList, WideStrings, WideTerminator},
    error::{NspiDecodeError, NspiLimits, NspiStatus},
    minid::MinimalId,
    stat::Stat,
};
use crate::{
    common::{Guid, LeReader, Utf16Le},
    mapi::{
        aux_buffer::AuxIn,
        http::RequestType,
        prop::{
            PropTag, PropValue, TaggedValues,
            codec::{ValueMode, decode_value_in, encode_value_in, wire_type, write_str_utf16},
        },
        restriction::{RestrictionBytes, skip_restriction},
    },
};

pub const BIND_ANONYMOUS: u32 = 0x0000_0020;
pub const SKIP_OBJECTS: u32 = 0x0000_0001;
pub const EPH_ID: u32 = 0x0000_0002;
pub const SPECIAL_ADDRESS_CREATION_TEMPLATES: u32 = 0x0000_0002;
pub const SPECIAL_UNICODE_STRINGS: u32 = 0x0000_0004;
pub const MOD_LINK_DELETE: u32 = 0x0000_0001;
pub const TI_TEMPLATE: u32 = 0x0000_0001;
pub const TI_SCRIPT: u32 = 0x0000_0004;
pub const TI_EMT: u32 = 0x0000_0010;
pub const QUERY_COLUMNS_UNICODE: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bind {
    pub flags: u32,
    pub state: Option<Stat>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareMinIds {
    pub state: Option<Stat>,
    pub mid1: MinimalId,
    pub mid2: MinimalId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnToMinId<'a> {
    pub names: Option<AsciiStrings<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NspiPropertyName {
    pub guid: Guid,
    pub id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetMatches<'a> {
    pub state: Option<Stat>,
    pub mids: Option<MidArray<'a>>,
    pub interface_option_flags: u32,
    pub filter: Option<RestrictionBytes<'a>>,
    pub property_name: Option<NspiPropertyName>,
    pub row_count: u32,
    pub columns: Option<PropTagList<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetPropList {
    pub flags: u32,
    pub mid: MinimalId,
    pub code_page: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetProps<'a> {
    pub flags: u32,
    pub state: Option<Stat>,
    pub tags: Option<PropTagList<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetSpecialTable {
    pub flags: u32,
    pub state: Option<Stat>,
    pub version: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetTemplateInfo<'a> {
    pub flags: u32,
    pub display_type: u32,
    pub template_dn: Option<&'a [u8]>,
    pub code_page: u32,
    pub locale_id: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModLinkAtt<'a> {
    pub flags: u32,
    pub tag: PropTag,
    pub mid: MinimalId,
    pub entry_ids: Option<BinaryArray<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModProps<'a> {
    pub state: Option<Stat>,
    pub tags: Option<PropTagList<'a>>,
    pub values: Option<TaggedValues<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryRows<'a> {
    pub flags: u32,
    pub state: Option<Stat>,
    pub explicit_table: MidArray<'a>,
    pub row_count: u32,
    pub columns: Option<PropTagList<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryColumns {
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveNames<'a> {
    pub state: Option<Stat>,
    pub tags: Option<PropTagList<'a>>,
    pub names: Option<WideStrings<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResortRestriction<'a> {
    pub state: Option<Stat>,
    pub mids: Option<MidArray<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeekEntries<'a> {
    pub state: Option<Stat>,
    pub target: Option<(PropTag, PropValue<'a>)>,
    pub explicit_table: Option<MidArray<'a>>,
    pub columns: Option<PropTagList<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpdateStat {
    pub state: Option<Stat>,
    pub delta_requested: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UrlRequest<'a> {
    pub flags: u32,
    pub dn: Utf16Le<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NspiRequest<'a> {
    Bind(Bind),
    Unbind,
    CompareMinIds(CompareMinIds),
    DnToMinId(DnToMinId<'a>),
    GetMatches(GetMatches<'a>),
    GetPropList(GetPropList),
    GetProps(GetProps<'a>),
    GetSpecialTable(GetSpecialTable),
    GetTemplateInfo(GetTemplateInfo<'a>),
    ModLinkAtt(ModLinkAtt<'a>),
    ModProps(ModProps<'a>),
    QueryRows(QueryRows<'a>),
    QueryColumns(QueryColumns),
    ResolveNames(ResolveNames<'a>),
    ResortRestriction(ResortRestriction<'a>),
    SeekEntries(SeekEntries<'a>),
    UpdateStat(UpdateStat),
    GetMailboxUrl(UrlRequest<'a>),
    GetAddressBookUrl(UrlRequest<'a>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NspiBody<'a> {
    pub request: NspiRequest<'a>,
    pub aux: AuxIn<'a>,
}

struct Body<'a, 'l> {
    r: LeReader<'a>,
    limits: &'l NspiLimits,
    terminator: WideTerminator,
}

impl<'a> Body<'a, '_> {
    fn u32(&mut self) -> Result<u32, NspiDecodeError> {
        Ok(self.r.u32()?)
    }

    fn has(&mut self) -> Result<bool, NspiDecodeError> {
        Ok(self.r.u8()? != 0)
    }

    fn optional<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, NspiDecodeError>,
    ) -> Result<Option<T>, NspiDecodeError> {
        if self.has()? {
            f(self).map(Some)
        } else {
            Ok(None)
        }
    }

    fn state(&mut self) -> Result<Option<Stat>, NspiDecodeError> {
        self.optional(|b| Stat::decode(&mut b.r))
    }

    fn mids(&mut self) -> Result<MidArray<'a>, NspiDecodeError> {
        MidArray::decode(&mut self.r, self.limits.array_max)
    }

    fn tags(&mut self) -> Result<PropTagList<'a>, NspiDecodeError> {
        PropTagList::decode(&mut self.r, self.limits.array_max)
    }

    fn restriction(&mut self) -> Result<RestrictionBytes<'a>, NspiDecodeError> {
        let start = self.r.remaining();
        let before = self.r.offset();
        let limits = self.limits.value_limits();
        skip_restriction(
            &mut self.r,
            ValueMode::AddressBook,
            &limits,
            limits.restriction_depth,
        )?;
        let len = self.r.offset().saturating_sub(before);
        Ok(RestrictionBytes(start.get(..len).unwrap_or_default()))
    }

    fn tagged_value(&mut self) -> Result<(PropTag, PropValue<'a>), NspiDecodeError> {
        let tag = PropTag(self.r.u32()?);
        let limits = self.limits.value_limits();
        let value = decode_value_in(
            &mut self.r,
            wire_type(tag.type_code()),
            ValueMode::AddressBook,
            &limits,
            limits.restriction_depth,
        )?;
        Ok((tag, value))
    }

    fn tagged_values(&mut self) -> Result<TaggedValues<'a>, NspiDecodeError> {
        let offset = self.r.offset();
        let count = self.u32()?;
        if count > self.limits.array_max
            || usize::try_from(count).unwrap_or(usize::MAX) > self.r.remaining().len()
        {
            return Err(NspiDecodeError::TooMany {
                offset: NspiDecodeError::at(offset),
            });
        }
        let limits = self.limits.value_limits();
        Ok(TaggedValues::decode_in(
            &mut self.r,
            count,
            ValueMode::AddressBook,
            &limits,
            limits.restriction_depth,
        )?)
    }

    fn aux(&mut self) -> Result<AuxIn<'a>, NspiDecodeError> {
        let size = self.u32()?;
        if size != 0 && (size < self.limits.aux_min || size > self.limits.aux_max) {
            return Err(NspiDecodeError::BadAux);
        }
        let bytes = self.r.bytes(usize::try_from(size).unwrap_or(usize::MAX))?;
        Ok(AuxIn::new(bytes))
    }

    fn wide(&mut self) -> Result<Utf16Le<'a>, NspiDecodeError> {
        self.terminator.read(&mut self.r)
    }
}

pub fn parse_nspi<'a>(
    request_type: RequestType,
    body: &'a [u8],
    limits: &NspiLimits,
) -> Result<NspiBody<'a>, NspiDecodeError> {
    let strict = parse_terminated(request_type, body, limits, WideTerminator::Single);
    if !matches!(&strict, Ok((_, rest)) if rest.is_empty())
        && matches!(
            request_type,
            RequestType::ResolveNames | RequestType::GetMailboxUrl | RequestType::GetAddressBookUrl
        )
        && let Ok((parsed, [])) =
            parse_terminated(request_type, body, limits, WideTerminator::Double)
    {
        return Ok(parsed);
    }
    strict.map(|(parsed, _)| parsed)
}

fn parse_terminated<'a>(
    request_type: RequestType,
    body: &'a [u8],
    limits: &NspiLimits,
    terminator: WideTerminator,
) -> Result<(NspiBody<'a>, &'a [u8]), NspiDecodeError> {
    let mut b = Body {
        r: LeReader::new(body),
        limits,
        terminator,
    };
    let request = match request_type {
        RequestType::Bind => NspiRequest::Bind(Bind {
            flags: b.u32()?,
            state: b.state()?,
        }),
        RequestType::Unbind => {
            b.u32()?;
            NspiRequest::Unbind
        }
        RequestType::CompareMinIds => {
            b.u32()?;
            NspiRequest::CompareMinIds(CompareMinIds {
                state: b.state()?,
                mid1: MinimalId(b.u32()?),
                mid2: MinimalId(b.u32()?),
            })
        }
        RequestType::DnToMinId => {
            b.u32()?;
            NspiRequest::DnToMinId(DnToMinId {
                names: b.optional(|b| AsciiStrings::decode(&mut b.r, b.limits.array_max))?,
            })
        }
        RequestType::GetMatches => {
            b.u32()?;
            NspiRequest::GetMatches(GetMatches {
                state: b.state()?,
                mids: b.optional(Body::mids)?,
                interface_option_flags: b.u32()?,
                filter: b.optional(Body::restriction)?,
                property_name: b.optional(|b| {
                    Ok(NspiPropertyName {
                        guid: b.r.guid()?,
                        id: b.u32()?,
                    })
                })?,
                row_count: b.u32()?,
                columns: b.optional(Body::tags)?,
            })
        }
        RequestType::GetPropList => NspiRequest::GetPropList(GetPropList {
            flags: b.u32()?,
            mid: MinimalId(b.u32()?),
            code_page: b.u32()?,
        }),
        RequestType::GetProps => NspiRequest::GetProps(GetProps {
            flags: b.u32()?,
            state: b.state()?,
            tags: b.optional(Body::tags)?,
        }),
        RequestType::GetSpecialTable => NspiRequest::GetSpecialTable(GetSpecialTable {
            flags: b.u32()?,
            state: b.state()?,
            version: b.optional(Body::u32)?,
        }),
        RequestType::GetTemplateInfo => NspiRequest::GetTemplateInfo(GetTemplateInfo {
            flags: b.u32()?,
            display_type: b.u32()?,
            template_dn: b.optional(|b| Ok(b.r.ascii_z()?))?,
            code_page: b.u32()?,
            locale_id: b.u32()?,
        }),
        RequestType::ModLinkAtt => NspiRequest::ModLinkAtt(ModLinkAtt {
            flags: b.u32()?,
            tag: PropTag(b.u32()?),
            mid: MinimalId(b.u32()?),
            entry_ids: b.optional(|b| BinaryArray::decode(&mut b.r, b.limits.array_max))?,
        }),
        RequestType::ModProps => {
            b.u32()?;
            NspiRequest::ModProps(ModProps {
                state: b.state()?,
                tags: b.optional(Body::tags)?,
                values: b.optional(Body::tagged_values)?,
            })
        }
        RequestType::QueryRows => NspiRequest::QueryRows(QueryRows {
            flags: b.u32()?,
            state: b.state()?,
            explicit_table: b.mids()?,
            row_count: b.u32()?,
            columns: b.optional(Body::tags)?,
        }),
        RequestType::QueryColumns => {
            b.u32()?;
            NspiRequest::QueryColumns(QueryColumns { flags: b.u32()? })
        }
        RequestType::ResolveNames => {
            b.u32()?;
            NspiRequest::ResolveNames(ResolveNames {
                state: b.state()?,
                tags: b.optional(Body::tags)?,
                names: b.optional(|b| {
                    WideStrings::decode(&mut b.r, b.limits.array_max, b.terminator)
                })?,
            })
        }
        RequestType::ResortRestriction => {
            b.u32()?;
            NspiRequest::ResortRestriction(ResortRestriction {
                state: b.state()?,
                mids: b.optional(Body::mids)?,
            })
        }
        RequestType::SeekEntries => {
            b.u32()?;
            NspiRequest::SeekEntries(SeekEntries {
                state: b.state()?,
                target: b.optional(Body::tagged_value)?,
                explicit_table: b.optional(Body::mids)?,
                columns: b.optional(Body::tags)?,
            })
        }
        RequestType::UpdateStat => {
            b.u32()?;
            NspiRequest::UpdateStat(UpdateStat {
                state: b.state()?,
                delta_requested: b.has()?,
            })
        }
        RequestType::GetMailboxUrl => NspiRequest::GetMailboxUrl(UrlRequest {
            flags: b.u32()?,
            dn: b.wide()?,
        }),
        RequestType::GetAddressBookUrl => NspiRequest::GetAddressBookUrl(UrlRequest {
            flags: b.u32()?,
            dn: b.wide()?,
        }),
        RequestType::Connect
        | RequestType::Execute
        | RequestType::Disconnect
        | RequestType::NotificationWait
        | RequestType::Ping => return Err(NspiDecodeError::NotNspi),
    };
    let aux = b.aux()?;
    Ok((NspiBody { request, aux }, b.r.remaining()))
}

const HAS: u8 = 0xFF;
const HAS_NOT: u8 = 0x00;

pub fn write_nspi_success<F: FnOnce(&mut Vec<u8>)>(
    out: &mut Vec<u8>,
    error: NspiStatus,
    fields: F,
) {
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&error.0.to_le_bytes());
    fields(out);
    out.extend_from_slice(&0u32.to_le_bytes());
}

pub fn write_has(out: &mut Vec<u8>, present: bool) {
    out.push(if present { HAS } else { HAS_NOT });
}

pub fn write_state(out: &mut Vec<u8>, state: Option<&Stat>) {
    write_has(out, state.is_some());
    if let Some(state) = state {
        state.encode(out);
    }
}

pub fn write_u32_opt(out: &mut Vec<u8>, value: Option<u32>) {
    write_has(out, value.is_some());
    if let Some(value) = value {
        out.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn write_i32_opt(out: &mut Vec<u8>, value: Option<i32>) {
    write_u32_opt(out, value.map(|v| u32::from_le_bytes(v.to_le_bytes())));
}

pub fn write_mids(out: &mut Vec<u8>, mids: Option<&[MinimalId]>) {
    write_has(out, mids.is_some());
    if let Some(mids) = mids {
        out.reserve(mids.len().saturating_mul(4).saturating_add(4));
        out.extend_from_slice(&u32::try_from(mids.len()).unwrap_or(u32::MAX).to_le_bytes());
        for mid in mids {
            out.extend_from_slice(&mid.0.to_le_bytes());
        }
    }
}

pub fn write_prop_tags(out: &mut Vec<u8>, tags: Option<&[PropTag]>) {
    write_has(out, tags.is_some());
    if let Some(tags) = tags {
        super::abk::write_tags(out, tags);
    }
}

pub fn write_tagged_value(out: &mut Vec<u8>, tag: PropTag, value: &PropValue<'_>) {
    out.extend_from_slice(&tag.0.to_le_bytes());
    encode_value_in(out, value, ValueMode::AddressBook);
}

pub fn write_url(out: &mut Vec<u8>, url: &str) {
    write_str_utf16(out, url);
}

pub fn write_server_guid(out: &mut Vec<u8>, guid: &Guid) {
    out.extend_from_slice(guid.as_bytes());
}
