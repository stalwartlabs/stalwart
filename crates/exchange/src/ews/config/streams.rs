/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{BASE64_BLOCK_LEN, ConfigError, STREAM_TAGS};
use crate::{
    mapi::emsmdb::message::object_row::{encode_key, encode_property},
    store::{ArchivedExchangeProperty, ExchangeProperty},
};
use bytes::Bytes;
use exchange_proto::{
    common::base64::Base64Text,
    convert::roaming::{DATATYPE_BINARY, DATATYPE_DICTIONARY, DATATYPE_XML, encode_dictionary},
    ews::types::{config::UserConfiguration, value::XBinary},
    mapi::prop::{OwnedPropValue, PropKeyRef, PropTag, tags},
};

#[derive(Default)]
pub(super) struct Streams {
    pub(super) dictionary: Option<Bytes>,
    pub(super) xml: Option<Bytes>,
    pub(super) binary: Option<Bytes>,
}

impl Streams {
    pub(super) fn from_request(
        configuration: &UserConfiguration<'_>,
        max_size: usize,
    ) -> Result<Self, ConfigError> {
        let dictionary = configuration
            .dictionary
            .as_ref()
            .map(|dictionary| encode_dictionary(dictionary).map_err(|_| ConfigError::InvalidValue))
            .transpose()?;
        if dictionary
            .as_ref()
            .is_some_and(|stream| stream.len() > max_size)
        {
            return Err(ConfigError::TooLarge);
        }
        Ok(Streams {
            dictionary: dictionary.map(Bytes::from),
            xml: decode_stream(configuration.xml_data.as_ref(), max_size)?,
            binary: decode_stream(configuration.binary_data.as_ref(), max_size)?,
        })
    }

    fn slot(&mut self, tag: PropTag) -> &mut Option<Bytes> {
        if tag == tags::ROAMING_DICTIONARY {
            &mut self.dictionary
        } else if tag == tags::ROAMING_XML_STREAM {
            &mut self.xml
        } else {
            &mut self.binary
        }
    }

    pub(super) fn from_stored(properties: &[ArchivedExchangeProperty]) -> Self {
        let keys = StreamKeys::new();
        let mut streams = Streams::default();
        for property in properties {
            if let Some(tag) = keys.tag_of(property.key.as_slice())
                && let Some((OwnedPropValue::Binary(bytes), [])) =
                    OwnedPropValue::read_canonical(property.value.as_slice())
            {
                *streams.slot(tag) = Some(bytes);
            }
        }
        streams
    }

    fn datatypes(&self) -> u32 {
        let mut bits = 0;
        if self.dictionary.is_some() {
            bits |= DATATYPE_DICTIONARY;
        }
        if self.xml.is_some() {
            bits |= DATATYPE_XML;
        }
        if self.binary.is_some() {
            bits |= DATATYPE_BINARY;
        }
        bits
    }

    pub(super) fn into_properties(
        self,
        mut properties: Vec<ExchangeProperty>,
    ) -> Vec<ExchangeProperty> {
        let datatypes = self.datatypes();
        properties.reserve(STREAM_TAGS.len() + 1);
        for (tag, stream) in STREAM_TAGS
            .into_iter()
            .zip([self.dictionary, self.xml, self.binary])
        {
            if let Some(stream) = stream {
                properties.push(encode_property(
                    PropKeyRef::Tag(tag.id()),
                    &OwnedPropValue::Binary(stream),
                ));
            }
        }
        properties.push(encode_property(
            PropKeyRef::Tag(tags::ROAMING_DATATYPES.id()),
            &OwnedPropValue::I32(datatypes as i32),
        ));
        properties.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        properties
    }
}

pub(super) struct StreamKeys {
    datatypes: Vec<u8>,
    streams: [(PropTag, Vec<u8>); 3],
}

impl StreamKeys {
    pub(super) fn new() -> Self {
        StreamKeys {
            datatypes: encode_key(PropKeyRef::Tag(tags::ROAMING_DATATYPES.id())),
            streams: STREAM_TAGS.map(|tag| (tag, encode_key(PropKeyRef::Tag(tag.id())))),
        }
    }

    fn tag_of(&self, key: &[u8]) -> Option<PropTag> {
        self.streams
            .iter()
            .find(|(_, encoded)| encoded.as_slice() == key)
            .map(|(tag, _)| *tag)
    }

    pub(super) fn is_roaming(&self, key: &[u8]) -> bool {
        self.datatypes.as_slice() == key || self.tag_of(key).is_some()
    }
}

fn decode_stream(
    binary: Option<&XBinary<'_>>,
    max_size: usize,
) -> Result<Option<Bytes>, ConfigError> {
    let Some(binary) = binary else {
        return Ok(None);
    };
    let bytes = match binary {
        XBinary::Parsed(text) => Bytes::from(decode_base64(text, max_size)?),
        XBinary::Bytes(bytes) => bytes.clone(),
        XBinary::Borrowed(bytes) => Bytes::copy_from_slice(bytes),
    };
    if bytes.len() > max_size {
        Err(ConfigError::TooLarge)
    } else {
        Ok(Some(bytes))
    }
}

fn decode_base64(text: &Base64Text<'_>, max_size: usize) -> Result<Vec<u8>, ConfigError> {
    let mut raw = Vec::new();
    match text.decode_into(&mut raw, max_size.saturating_add(BASE64_BLOCK_LEN)) {
        Ok(()) => Ok(raw),
        Err(_) if raw.len() > max_size => Err(ConfigError::TooLarge),
        Err(_) => Err(ConfigError::InvalidValue),
    }
}
