/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cell::Cell;

use bytes::Bytes;
use mail_parser::decoders::charsets::Charset;

use super::{
    TnefItem, TnefReader, attr,
    props::{TnefProp, TnefRecipients, TnefValue, trim_nul},
};
use crate::{
    common::{
        guid::Guid,
        time::{FileTime, LocalDateTime},
    },
    convert::{
        BlobLimits, ConvertError,
        address::{Address, RECEIVED_REPRESENTING, SENDER, SENT_REPRESENTING, set_address},
        code_page_charset,
        context::ConvertOptions,
        hex_value,
        model::{AttachData, Attachment, MessageContent, PropBag},
        tags::{self, attach_method, message_flags},
    },
    mapi::prop::{OwnedPropValue, PropId, PropKey, PropKeyRef, PropType},
};

const IID_IMESSAGE: Guid = Guid::from_wire([
    0x07, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
]);
const ATTACH_TAG_OLE: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0A, 0x03, 0x02, 0x01,
];
const ATTACH_ENCODING_MAC_BINARY: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x03, 0x0B, 0x01];
const TRP_ONE_OFF: u16 = 0x0004;
const TRP_HEADER_LEN: usize = 8;
const DTR_LEN: usize = 14;
const REND_DATA_LEN: usize = 14;
const ATTACH_TYPE_OLE: u16 = 2;
const DATA_FLAGS_MAC_BINARY: u32 = 1;
const DEFAULT_CODE_PAGE: u16 = 1252;
const MEETING_RESPONSE_PREFIX: &str = "IPM.Schedule.Meeting.Resp.";
const LEGACY_CLASS_PREFIX: &[u8] = b"Microsoft Mail v3.0 ";

const STATUS_FLAGS: [(u32, i32); 4] = [
    (0x20, message_flags::READ),
    (0x04, message_flags::SUBMIT),
    (0x02, message_flags::UNSENT),
    (0x80, message_flags::HAS_ATTACH),
];
const STATUS_MODIFIED: u32 = 0x01;

#[derive(Default)]
struct PendingAttachment {
    props: PropBag,
    legacy_data: Option<Bytes>,
    object: Option<AttachData>,
}

struct Decoder<'l> {
    limits: &'l BlobLimits,
    charset: Charset,
    depth: u8,
    moves_left: &'l Cell<u32>,
}

pub fn tnef_to_message(
    b: &[u8],
    opts: &ConvertOptions<'_>,
) -> Result<MessageContent, ConvertError> {
    tnef_to_message_at(b, opts, 0)
}

pub(crate) fn tnef_to_message_at(
    b: &[u8],
    opts: &ConvertOptions<'_>,
    depth: u8,
) -> Result<MessageContent, ConvertError> {
    let limits = decode_limits(opts.max_decoded);
    decode(b, &limits, depth, &Cell::new(limits.max_stream_moves))
}

pub(crate) fn tnef_message_props(b: &[u8], max_decoded: u32) -> Result<PropBag, ConvertError> {
    let limits = decode_limits(max_decoded);
    let moves_left = Cell::new(limits.max_stream_moves);
    let mut reader = TnefReader::new(b, &limits)?;
    let decoder = Decoder::new(&reader, &limits, 0, &moves_left);
    let mut content = MessageContent::default();
    while let Some(item) = reader.next()? {
        match item {
            TnefItem::MessageAttr {
                id: attr::RECIP_TABLE | attr::BODY,
                ..
            } => {}
            TnefItem::MessageAttr { id, data } => decoder.message_attr(&mut content, id, data)?,
            TnefItem::Props(mut props) if props.attr() != attr::ATTACHMENT => {
                while let Some(prop) = props.next()? {
                    decoder.set_prop(&mut content.props, prop)?;
                }
            }
            TnefItem::AttachmentStart | TnefItem::AttachAttr { .. } | TnefItem::Props(_) => break,
        }
    }
    Ok(content.props)
}

fn decode_limits(max_decoded: u32) -> BlobLimits {
    BlobLimits {
        max_attr_len: BlobLimits::DEFAULT.max_attr_len.min(max_decoded),
        ..BlobLimits::DEFAULT
    }
}

fn decode(
    b: &[u8],
    limits: &BlobLimits,
    depth: u8,
    moves_left: &Cell<u32>,
) -> Result<MessageContent, ConvertError> {
    let mut reader = TnefReader::new(b, limits)?;
    let decoder = Decoder::new(&reader, limits, depth, moves_left);
    let mut content = MessageContent::default();
    let mut attachment: Option<PendingAttachment> = None;
    while let Some(item) = reader.next()? {
        match item {
            TnefItem::MessageAttr { id, data } => decoder.message_attr(&mut content, id, data)?,
            TnefItem::AttachmentStart => {
                if let Some(done) = attachment.replace(PendingAttachment::default()) {
                    content.attachments.push(done.finish());
                }
            }
            TnefItem::AttachAttr { id, data } => {
                if let Some(pending) = attachment.as_mut() {
                    decoder.attach_attr(pending, id, data);
                }
            }
            TnefItem::Props(mut props) => {
                let in_attachment = props.attr() == attr::ATTACHMENT;
                while let Some(prop) = props.next()? {
                    match attachment.as_mut().filter(|_| in_attachment) {
                        Some(pending) => decoder.attach_prop(pending, prop)?,
                        None => decoder.set_prop(&mut content.props, prop)?,
                    }
                }
            }
        }
    }
    if let Some(done) = attachment {
        content.attachments.push(done.finish());
    }
    Ok(content)
}

impl PendingAttachment {
    fn finish(self) -> Attachment {
        let method = match self
            .props
            .get(PropKeyRef::Tag(tags::ATTACH_METHOD), PropType::I32)
        {
            Some(OwnedPropValue::I32(method)) => *method,
            _ => attach_method::BY_VALUE,
        };
        let data = match (self.object, self.legacy_data) {
            (Some(object), _) => object,
            (None, Some(bytes))
                if method != attach_method::EMBEDDED_MESSAGE && method != attach_method::OLE =>
            {
                AttachData::Bytes(bytes)
            }
            _ => AttachData::None,
        };
        Attachment {
            props: self.props,
            data,
        }
    }
}

impl<'l> Decoder<'l> {
    fn new(
        reader: &TnefReader<'_>,
        limits: &'l BlobLimits,
        depth: u8,
        moves_left: &'l Cell<u32>,
    ) -> Self {
        let code_page = u16::try_from(reader.code_page())
            .ok()
            .filter(|cp| *cp != 0)
            .unwrap_or(DEFAULT_CODE_PAGE);
        Decoder {
            limits,
            charset: code_page_charset(code_page),
            depth,
            moves_left,
        }
    }

    fn ansi(&self, data: &[u8]) -> Box<str> {
        let mut out = String::with_capacity(data.len());
        self.charset.decode_append(trim_nul(data), &mut out);
        out.into_boxed_str()
    }

    fn set_prop(&self, bag: &mut PropBag, prop: TnefProp<'_>) -> Result<(), ConvertError> {
        let TnefValue::Value(value) = prop.value else {
            return Ok(());
        };
        let value = match value {
            OwnedPropValue::Error(_) => return Ok(()),
            OwnedPropValue::String8(bytes) => OwnedPropValue::Unicode(self.ansi(&bytes)),
            OwnedPropValue::MvString8(values) => {
                OwnedPropValue::MvUnicode(values.iter().map(|v| self.ansi(v)).collect())
            }
            value => value,
        };
        let len = bag.len();
        bag.set(prop.key, value);
        if bag.len() > len {
            if bag.len() > usize::from(self.limits.max_bag_props) {
                return Err(ConvertError::TooLarge);
            }
            let left = u32::try_from(bag.len())
                .ok()
                .and_then(|moves| self.moves_left.get().checked_sub(moves))
                .ok_or(ConvertError::TooLarge)?;
            self.moves_left.set(left);
        }
        Ok(())
    }

    fn attach_prop(
        &self,
        pending: &mut PendingAttachment,
        prop: TnefProp<'_>,
    ) -> Result<(), ConvertError> {
        let TnefValue::Object { iid, data } = prop.value else {
            return self.set_prop(&mut pending.props, prop);
        };
        if prop.key.as_ref() != PropKeyRef::Tag(tags::ATTACH_DATA) {
            return Ok(());
        }
        pending.object = Some(if iid == IID_IMESSAGE {
            let depth = self.depth.saturating_add(1);
            if depth > self.limits.max_depth {
                return Err(ConvertError::TooLarge);
            }
            AttachData::Embedded(Box::new(decode(data, self.limits, depth, self.moves_left)?))
        } else {
            AttachData::Bytes(Bytes::copy_from_slice(data))
        });
        Ok(())
    }

    fn message_attr(
        &self,
        content: &mut MessageContent,
        id: u32,
        data: &[u8],
    ) -> Result<(), ConvertError> {
        let bag = &mut content.props;
        match id {
            attr::SUBJECT => set_tag(bag, tags::SUBJECT, OwnedPropValue::Unicode(self.ansi(data))),
            attr::BODY => set_tag(bag, tags::BODY, OwnedPropValue::Unicode(self.ansi(data))),
            attr::MESSAGE_CLASS => set_tag(bag, tags::MESSAGE_CLASS, self.message_class(data)),
            attr::ORIGINAL_MESSAGE_CLASS => {
                set_tag(bag, tags::ORIGINAL_MESSAGE_CLASS, self.message_class(data))
            }
            attr::DATE_SENT => set_time(bag, tags::CLIENT_SUBMIT_TIME, data),
            attr::DATE_RECD => set_time(bag, tags::MESSAGE_DELIVERY_TIME, data),
            attr::DATE_MODIFIED => set_time(bag, tags::LAST_MODIFICATION_TIME, data),
            attr::DATE_START => set_time(bag, tags::START_DATE, data),
            attr::DATE_END => set_time(bag, tags::END_DATE, data),
            attr::PRIORITY => {
                let importance = match data.first_chunk::<2>().map(|b| u16::from_le_bytes(*b)) {
                    Some(1) => 2,
                    Some(3) => 0,
                    _ => 1,
                };
                set_tag(bag, tags::IMPORTANCE, OwnedPropValue::I32(importance));
            }
            attr::MESSAGE_STATUS => {
                let status = match *data {
                    [byte] => u32::from(byte),
                    [a, b, c, d] => u32::from_le_bytes([a, b, c, d]),
                    _ => return Ok(()),
                };
                let mut flags = STATUS_FLAGS
                    .iter()
                    .filter(|(bit, _)| status & bit != 0)
                    .fold(0, |flags, (_, flag)| flags | flag);
                if status & STATUS_MODIFIED == 0 {
                    flags |= message_flags::UNMODIFIED;
                }
                set_tag(bag, tags::MESSAGE_FLAGS, OwnedPropValue::I32(flags));
            }
            attr::MESSAGE_ID => {
                let hex = trim_nul(data);
                let (pairs, odd) = hex.as_chunks::<2>();
                let key: Option<Vec<u8>> = pairs
                    .iter()
                    .map(|[high, low]| Some((hex_value(*high)? << 4) | hex_value(*low)?))
                    .collect();
                if let Some(key) = key.filter(|_| odd.is_empty()) {
                    set_tag(bag, tags::SEARCH_KEY, OwnedPropValue::Binary(key.into()));
                }
            }
            attr::AID_OWNER => {
                if let Some(id) = data.first_chunk::<4>() {
                    set_tag(
                        bag,
                        tags::OWNER_APPOINTMENT_ID,
                        OwnedPropValue::I32(i32::from_le_bytes(*id)),
                    );
                }
            }
            attr::REQUEST_RES => {
                if let Some(value) = data.first() {
                    set_tag(
                        bag,
                        tags::RESPONSE_REQUESTED,
                        OwnedPropValue::Bool(*value != 0),
                    );
                }
            }
            attr::DELEGATE => set_tag(
                bag,
                tags::RECEIVED_REPRESENTING_ENTRY_ID,
                OwnedPropValue::Binary(Bytes::copy_from_slice(data)),
            ),
            attr::FROM => {
                if let Some(address) = self.trp(data) {
                    set_address(bag, &SENDER, address);
                }
            }
            attr::OWNER | attr::SENT_FOR => {
                let received = id == attr::OWNER
                    && matches!(
                        bag.get(PropKeyRef::Tag(tags::MESSAGE_CLASS), PropType::Unicode),
                        Some(OwnedPropValue::Unicode(class)) if class.starts_with(MEETING_RESPONSE_PREFIX)
                    );
                if let Some(address) = self.owner(data) {
                    let target = if received {
                        &RECEIVED_REPRESENTING
                    } else {
                        &SENT_REPRESENTING
                    };
                    set_address(bag, target, address);
                }
            }
            attr::RECIP_TABLE => {
                let mut rows = TnefRecipients::new(data, 0)?;
                while let Some(row) = rows.next()? {
                    let mut recipient = PropBag::new();
                    for prop in row {
                        self.set_prop(&mut recipient, prop)?;
                    }
                    content.recipients.push(recipient);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn attach_attr(&self, pending: &mut PendingAttachment, id: u32, data: &[u8]) {
        let bag = &mut pending.props;
        match id {
            attr::ATTACH_REND_DATA => {
                let Some(rend) = data.first_chunk::<REND_DATA_LEN>() else {
                    return;
                };
                let [t0, t1, p0, p1, p2, p3, _, _, _, _, f0, f1, f2, f3] = *rend;
                set_tag(
                    bag,
                    tags::RENDERING_POSITION,
                    OwnedPropValue::I32(i32::from_le_bytes([p0, p1, p2, p3])),
                );
                if u16::from_le_bytes([t0, t1]) == ATTACH_TYPE_OLE {
                    set_tag(
                        bag,
                        tags::ATTACH_TAG,
                        OwnedPropValue::Binary(Bytes::from_static(ATTACH_TAG_OLE)),
                    );
                }
                if u32::from_le_bytes([f0, f1, f2, f3]) == DATA_FLAGS_MAC_BINARY {
                    set_tag(
                        bag,
                        tags::ATTACH_ENCODING,
                        OwnedPropValue::Binary(Bytes::from_static(ATTACH_ENCODING_MAC_BINARY)),
                    );
                }
            }
            attr::ATTACH_TITLE => set_tag(
                bag,
                tags::ATTACH_FILENAME,
                OwnedPropValue::Unicode(self.ansi(data)),
            ),
            attr::ATTACH_TRANSPORT_FILENAME => set_tag(
                bag,
                tags::ATTACH_TRANSPORT_NAME,
                OwnedPropValue::Unicode(self.ansi(data)),
            ),
            attr::ATTACH_DATA => pending.legacy_data = Some(Bytes::copy_from_slice(data)),
            attr::ATTACH_META_FILE => set_tag(
                bag,
                tags::ATTACH_RENDERING,
                OwnedPropValue::Binary(Bytes::copy_from_slice(data)),
            ),
            attr::ATTACH_CREATE_DATE => set_time(bag, tags::CREATION_TIME, data),
            attr::ATTACH_MODIFY_DATE => set_time(bag, tags::LAST_MODIFICATION_TIME, data),
            _ => {}
        }
    }

    fn message_class(&self, data: &[u8]) -> OwnedPropValue {
        let class = trim_nul(data);
        let class = class.strip_prefix(LEGACY_CLASS_PREFIX).unwrap_or(class);
        let mapped = hashify::map!(class, &'static str,
            "IPM.Microsoft Mail.Note" => "IPM.Note",
            "IPM.Microsoft Mail.Read Receipt" => "Report.IPM.Note.IPNRN",
            "IPM.Microsoft Mail.Non-Delivery" => "Report.IPM.Note.NDR",
            "IPM.Microsoft Schedule.MtgRespP" => "IPM.Schedule.Meeting.Resp.Pos",
            "IPM.Microsoft Schedule.MtgRespN" => "IPM.Schedule.Meeting.Resp.Neg",
            "IPM.Microsoft Schedule.MtgRespA" => "IPM.Schedule.Meeting.Resp.Tent",
            "IPM.Microsoft Schedule.MtgReq" => "IPM.Schedule.Meeting.Request",
            "IPM.Microsoft Schedule.MtgCncl" => "IPM.Schedule.Meeting.Canceled",
        );
        OwnedPropValue::Unicode(match mapped {
            Some(class) => Box::from(*class),
            None => self.ansi(class),
        })
    }

    fn trp(&self, data: &[u8]) -> Option<Address> {
        let (header, rest) = data.split_first_chunk::<TRP_HEADER_LEN>()?;
        let [i0, i1, _, _, n0, n1, e0, e1] = *header;
        if u16::from_le_bytes([i0, i1]) != TRP_ONE_OFF {
            return None;
        }
        let (name, rest) = rest.split_at_checked(usize::from(u16::from_le_bytes([n0, n1])))?;
        let email = rest.get(..usize::from(u16::from_le_bytes([e0, e1])))?;
        self.address(name, email)
    }

    fn owner(&self, data: &[u8]) -> Option<Address> {
        let (len, rest) = data.split_first_chunk::<2>()?;
        let (name, rest) = rest.split_at_checked(usize::from(u16::from_le_bytes(*len)))?;
        let (len, rest) = rest.split_first_chunk::<2>()?;
        let email = rest.get(..usize::from(u16::from_le_bytes(*len)))?;
        self.address(name, email)
    }

    fn address(&self, name: &[u8], email: &[u8]) -> Option<Address> {
        let email = trim_nul(email);
        let colon = memchr::memchr(b':', email)?;
        let (address_type, address) = (email.get(..colon)?, email.get(colon.checked_add(1)?..)?);
        Some(Address {
            name: self.ansi(name),
            address_type: self.ansi(address_type),
            email: self.ansi(address),
        })
    }
}

fn set_tag(bag: &mut PropBag, id: PropId, value: OwnedPropValue) {
    bag.set(PropKey::tag(id), value);
}

fn set_time(bag: &mut PropBag, id: PropId, data: &[u8]) {
    let Some(dtr) = data.first_chunk::<DTR_LEN>() else {
        return;
    };
    let (fields, _) = dtr.as_chunks::<2>();
    let [year, month, day, hour, minute, second, _] = fields else {
        return;
    };
    let field = |f: &[u8; 2]| u8::try_from(u16::from_le_bytes(*f)).ok();
    let local = (|| {
        LocalDateTime::new(
            u16::from_le_bytes(*year),
            field(month)?,
            field(day)?,
            field(hour)?,
            field(minute)?,
            field(second)?,
            0,
        )
    })();
    if let Some(local) = local {
        set_tag(
            bag,
            id,
            OwnedPropValue::Time(FileTime::from_utc(local.to_unix_seconds(), 0)),
        );
    }
}
