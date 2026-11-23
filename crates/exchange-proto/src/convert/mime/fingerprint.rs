use super::{
    export::{attachment_file_name, export_html, has_inline_id, is_inline_part},
    import::sanitized_file_name,
};
use crate::{
    convert::{
        model::{AttachData, Attachment, MessageContent, PropBag},
        tags,
    },
    mapi::prop::{OwnedPropValue, PropId, PropKeyRef, PropType},
};

const FNV_OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;
const BY_VALUE: u8 = 1;
const EMBEDDED: u8 = 5;
const INLINE_RANK: u8 = 0;
const ATTACHED_RANK: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttachmentSlot {
    pub fingerprint: u64,
    pub occurrence: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum AttachmentOrder {
    Export { max_decoded: u32 },
    Stored,
}

struct Ranked {
    fingerprint: u64,
    rank: u8,
    index: usize,
}

impl Ranked {
    fn order(&self) -> (u64, u8, usize) {
        (self.fingerprint, self.rank, self.index)
    }
}

pub fn attachment_slots(content: &MessageContent, order: AttachmentOrder) -> Vec<AttachmentSlot> {
    let attachments = &content.attachments;
    let mut ranked = attachments
        .iter()
        .enumerate()
        .map(|(index, attachment)| Ranked {
            fingerprint: attachment_fingerprint(attachment),
            rank: INLINE_RANK,
            index,
        })
        .collect::<Vec<_>>();
    ranked.sort_unstable_by_key(Ranked::order);
    if let AttachmentOrder::Export { max_decoded } = order {
        rank_inline_parts(content, max_decoded, &mut ranked);
    }
    let mut slots = vec![
        AttachmentSlot {
            fingerprint: 0,
            occurrence: 0,
        };
        attachments.len()
    ];
    for run in ranked.chunk_by(|a, b| a.fingerprint == b.fingerprint) {
        for (occurrence, entry) in run.iter().enumerate() {
            if let Some(slot) = slots.get_mut(entry.index) {
                *slot = AttachmentSlot {
                    fingerprint: entry.fingerprint,
                    occurrence: u16::try_from(occurrence).unwrap_or(u16::MAX),
                };
            }
        }
    }
    slots
}

fn rank_inline_parts(content: &MessageContent, max_decoded: u32, ranked: &mut [Ranked]) {
    let attachment = |entry: &Ranked| content.attachments.get(entry.index);
    let ambiguous =
        |run: &[Ranked]| run.len() > 1 && run.iter().filter_map(attachment).any(has_inline_id);
    if !ranked
        .chunk_by(|a, b| a.fingerprint == b.fingerprint)
        .any(ambiguous)
    {
        return;
    }
    let Ok(Some(html)) = export_html(&content.props, max_decoded) else {
        return;
    };
    for run in ranked.chunk_by_mut(|a, b| a.fingerprint == b.fingerprint) {
        if !ambiguous(run) {
            continue;
        }
        for entry in run.iter_mut() {
            if attachment(entry).is_some_and(|attachment| !is_inline_part(attachment, &html)) {
                entry.rank = ATTACHED_RANK;
            }
        }
        run.sort_unstable_by_key(Ranked::order);
    }
}

struct Fnv(u64);

impl Fnv {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
        }
    }
}

fn attachment_fingerprint(attachment: &Attachment) -> u64 {
    let props = &attachment.props;
    let name = attachment_file_name(props);
    let mut hash = Fnv(FNV_OFFSET);
    let size = match &attachment.data {
        AttachData::Bytes(bytes) => bytes.len(),
        AttachData::None => match props.get(PropKeyRef::Tag(tags::ATTACH_DATA), PropType::Binary) {
            Some(OwnedPropValue::Binary(bytes)) => bytes.len(),
            _ => 0,
        },
        AttachData::Deferred(blob) => usize::try_from(blob.len).unwrap_or(usize::MAX),
        AttachData::Embedded(_) => 0,
    };
    hash.write(&u64::try_from(size).unwrap_or(u64::MAX).to_le_bytes());
    match &attachment.data {
        AttachData::Embedded(embedded) => {
            hash.write(&[EMBEDDED]);
            let name = name.or_else(|| unicode(&embedded.props, tags::SUBJECT));
            hash.write(name.unwrap_or_default().as_bytes());
        }
        AttachData::Bytes(_) | AttachData::None | AttachData::Deferred(_) => {
            hash.write(&[BY_VALUE]);
            let mut utf8 = [0; 4];
            for c in sanitized_file_name(name.unwrap_or_default()) {
                hash.write(c.encode_utf8(&mut utf8).as_bytes());
            }
        }
    }
    hash.0
}

fn unicode(props: &PropBag, id: PropId) -> Option<&str> {
    match props.get(PropKeyRef::Tag(id), PropType::Unicode)? {
        OwnedPropValue::Unicode(value) => Some(value),
        _ => None,
    }
}
