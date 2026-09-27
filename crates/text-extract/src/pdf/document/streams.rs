/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::Document;
use crate::pdf::{
    crypt::{Decryptor, Target},
    decode::{Chain, DecodeOutcome},
    object::{ObjRef, Str, Stream},
};
use std::borrow::Cow;

impl<'a> Document<'a> {
    pub(crate) fn decode_stream(&self, stream: Stream<'_>, out: &mut Vec<u8>) -> DecodeOutcome {
        if self.source.budget_exhausted() {
            self.source.mark_truncated();
            return DecodeOutcome::Truncated;
        }
        let chain = Chain::parse(stream.dict, &|object| self.resolve(object));
        let decrypt = self.stream_key(stream, &chain);
        self.source.decode(&chain, stream.data, decrypt, out)
    }

    pub(crate) fn stream_bytes<'s>(
        &self,
        stream: Stream<'s>,
        out: &'s mut Vec<u8>,
    ) -> (&'s [u8], DecodeOutcome) {
        out.clear();
        if self.source.budget_exhausted() {
            self.source.mark_truncated();
            return (out, DecodeOutcome::Truncated);
        }
        let chain = Chain::parse(stream.dict, &|object| self.resolve(object));
        let decrypt = self.stream_key(stream, &chain);
        if chain.is_passthrough() && decrypt.is_none() {
            return self.source.borrow(stream.data);
        }
        let outcome = self.source.decode(&chain, stream.data, decrypt, out);
        (out, outcome)
    }

    fn stream_key(&self, stream: Stream<'_>, chain: &Chain) -> Option<(&Decryptor, ObjRef)> {
        self.crypt
            .get()
            .filter(|_| !stream.dict.is_type(b"XRef"))
            .and_then(|crypt| crypt.stream_key(stream.id, chain.crypt_stage()))
    }

    pub(crate) fn string<'s>(&self, value: Str<'s>) -> Cow<'s, [u8]> {
        let decoded = value.decoded();
        match self
            .crypt
            .get()
            .and_then(|crypt| crypt.string_key(value.owner()))
        {
            Some((decryptor, id)) => {
                let mut out = Vec::with_capacity(decoded.len());
                decryptor.decrypt(Target::String, id.num, id.generation, &decoded, &mut out);
                Cow::Owned(out)
            }
            None => decoded,
        }
    }
}
