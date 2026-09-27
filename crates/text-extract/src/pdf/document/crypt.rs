/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{Document, OpenError, table::Table};
use crate::pdf::{
    crypt::{CryptMethod, Decryptor, EncryptDict, Target},
    object::{Dict, ObjRef, Object},
};
use std::borrow::Cow;

const MODERN_VERSION: i64 = 4;

pub(crate) struct Crypt {
    decryptor: Decryptor,
    encrypt: Option<ObjRef>,
}

impl Crypt {
    pub(super) fn stream_key(
        &self,
        id: ObjRef,
        crypt_stage: Option<bool>,
    ) -> Option<(&Decryptor, ObjRef)> {
        let exempt = crypt_stage == Some(true)
            || Some(id) == self.encrypt
            || self.decryptor.method(Target::Stream) == CryptMethod::Identity;
        (!exempt).then_some((&self.decryptor, id))
    }

    pub(super) fn string_key(&self, owner: Option<ObjRef>) -> Option<(&Decryptor, ObjRef)> {
        let owner = owner.filter(|&owner| Some(owner) != self.encrypt)?;
        (self.decryptor.method(Target::String) != CryptMethod::Identity)
            .then_some((&self.decryptor, owner))
    }
}

impl<'a> Document<'a> {
    pub(super) fn setup_crypt(
        &self,
        table: &Table<'_>,
        trailers: &[Dict<'a>],
    ) -> Result<(), OpenError> {
        let Some((index, encrypt)) = trailers
            .iter()
            .enumerate()
            .find_map(|(index, trailer)| trailer.get(b"Encrypt").map(|value| (index, value)))
        else {
            return Ok(());
        };
        let Object::Dict(dict) = self.resolve_in(table, encrypt) else {
            return match self.resolve_in(table, encrypt) {
                Object::Null => Ok(()),
                _ => Err(OpenError::Encrypted),
            };
        };
        let id0 = trailers
            .get(index)
            .and_then(|trailer| trailer.get(b"ID"))
            .or_else(|| trailers.iter().find_map(|trailer| trailer.get(b"ID")))
            .map(|id| self.resolve_in(table, id))
            .and_then(|id| id.as_array())
            .and_then(|id| id.get(0))
            .map(|first| self.resolve_in(table, first))
            .and_then(|first| first.as_str())
            .map_or(Cow::Borrowed(&[][..]), |first| first.decoded());
        let value = |key: &[u8]| self.resolve_in(table, dict.get(key).unwrap_or_default());
        let bytes = |key: &[u8]| {
            value(key)
                .as_str()
                .map_or(Cow::Borrowed(&[][..]), |value| value.decoded())
        };
        let filter = value(b"Filter")
            .as_name()
            .map_or(Cow::Borrowed(&[][..]), |name| name.decoded());
        let version = value(b"V").as_int().unwrap_or(0);
        let revision = value(b"R").as_int().unwrap_or(match version {
            ..2 => 2,
            2 | 3 => 3,
            4 => 4,
            _ => 6,
        });
        let (o, u, oe, ue) = (bytes(b"O"), bytes(b"U"), bytes(b"OE"), bytes(b"UE"));
        let filters = value(b"CF").as_dict();
        let method = |key: &[u8]| -> Result<Option<CryptMethod>, OpenError> {
            if version < MODERN_VERSION {
                return Ok(None);
            }
            let Some(name) = value(key).as_name() else {
                return Ok(None);
            };
            if name.is(b"Identity") {
                return Ok(Some(CryptMethod::Identity));
            }
            let Some(entry) = filters
                .and_then(|filters| filters.get(name.raw()))
                .map(|entry| self.resolve_in(table, entry))
                .and_then(|entry| entry.as_dict())
            else {
                return Ok(Some(CryptMethod::Identity));
            };
            let cfm = self.resolve_in(table, entry.get(b"CFM").unwrap_or_default());
            match cfm.as_name() {
                None => Ok(Some(CryptMethod::Identity)),
                Some(cfm) if cfm.is(b"None") => Ok(Some(CryptMethod::Identity)),
                Some(cfm) if cfm.is(b"V2") => Ok(Some(CryptMethod::Rc4)),
                Some(cfm) if cfm.is(b"AESV2") => Ok(Some(CryptMethod::AesV2)),
                Some(cfm) if cfm.is(b"AESV3") => Ok(Some(CryptMethod::AesV3)),
                Some(_) => Err(OpenError::Encrypted),
            }
        };
        let crypt_filter_length = value(b"StmF")
            .as_name()
            .and_then(|name| filters?.get(name.raw()))
            .map(|entry| self.resolve_in(table, entry))
            .and_then(|entry| entry.as_dict())
            .and_then(|entry| self.resolve_in(table, entry.get(b"Length")?).as_int());
        let encrypt_dict = EncryptDict {
            filter: &filter,
            v: version,
            r: revision,
            length: value(b"Length").as_int(),
            o: &o,
            u: &u,
            oe: &oe,
            ue: &ue,
            p: value(b"P").as_int().unwrap_or(0),
            encrypt_metadata: value(b"EncryptMetadata").as_bool().unwrap_or(true),
            stream_method: method(b"StmF")?,
            string_method: method(b"StrF")?,
            crypt_filter_length,
            id0: &id0,
        };
        let decryptor = Decryptor::new(&encrypt_dict).map_err(|_| OpenError::Encrypted)?;
        let _ = self.crypt.set(Crypt {
            decryptor,
            encrypt: encrypt.as_ref(),
        });
        Ok(())
    }
}
