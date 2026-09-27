/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod vectors;

use self::vectors::{VECTORS, Vector};
use super::{CryptError, CryptMethod, Decryptor, EncryptDict, Target};

fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).expect("ascii hex");
            u8::from_str_radix(digits, 16).expect("valid hex")
        })
        .collect()
}

struct Owned {
    o: Vec<u8>,
    u: Vec<u8>,
    oe: Vec<u8>,
    ue: Vec<u8>,
    id0: Vec<u8>,
}

impl Owned {
    fn new(vector: &Vector) -> Self {
        Owned {
            o: hex(vector.o),
            u: hex(vector.u),
            oe: hex(vector.oe),
            ue: hex(vector.ue),
            id0: hex(vector.id0),
        }
    }

    fn dict<'a>(&'a self, vector: &'a Vector) -> EncryptDict<'a> {
        EncryptDict {
            filter: vector.filter,
            v: vector.v,
            r: vector.r,
            length: vector.length,
            o: &self.o,
            u: &self.u,
            oe: &self.oe,
            ue: &self.ue,
            p: vector.p,
            encrypt_metadata: vector.encrypt_metadata,
            stream_method: vector.stream_method,
            string_method: vector.string_method,
            crypt_filter_length: vector.crypt_filter_length,
            id0: &self.id0,
        }
    }
}

fn vector(name: &str) -> &'static Vector {
    VECTORS
        .iter()
        .find(|vector| vector.name == name)
        .expect("vector exists")
}

fn decrypted(decryptor: &Decryptor, target: Target, id: (u32, u16), cipher: &str) -> Vec<u8> {
    let mut out = Vec::new();
    decryptor.decrypt(target, id.0, id.1, &hex(cipher), &mut out);
    out
}

fn assert_decrypts(decryptor: &Decryptor, vector: &Vector) {
    assert_eq!(
        decryptor.key.as_slice(),
        hex(vector.file_key),
        "{} file key",
        vector.name
    );
    assert_eq!(
        decrypted(
            decryptor,
            Target::String,
            vector.string_object,
            vector.title_cipher
        ),
        hex(vector.title_plain),
        "{} title",
        vector.name
    );
    assert_eq!(
        decrypted(
            decryptor,
            Target::String,
            vector.string_object,
            vector.subject_cipher
        ),
        hex(vector.subject_plain),
        "{} subject",
        vector.name
    );
    assert_eq!(
        decrypted(
            decryptor,
            Target::Stream,
            vector.stream_object,
            vector.stream_cipher
        ),
        hex(vector.stream_plain),
        "{} stream",
        vector.name
    );
}

#[test]
fn all_revisions_decrypt_real_files() {
    for vector in VECTORS {
        let owned = Owned::new(vector);
        let dict = owned.dict(vector);
        if vector.opens_with_empty {
            let decryptor = Decryptor::new(&dict).expect(vector.name);
            assert_decrypts(&decryptor, vector);
        } else {
            assert_eq!(
                Decryptor::new(&dict).err(),
                Some(CryptError::PasswordRequired),
                "{}",
                vector.name
            );
        }
        let decryptor = Decryptor::with_password(&dict, vector.password).expect(vector.name);
        assert_decrypts(&decryptor, vector);
    }
}

#[test]
fn covers_every_revision() {
    for revision in 2..=6 {
        assert!(
            VECTORS
                .iter()
                .any(|vector| vector.r == revision && vector.opens_with_empty),
            "revision {revision}"
        );
    }
}

#[test]
fn empty_owner_password_opens_file() {
    for name in ["r3_empty_owner", "r4_empty_owner", "r6_empty_owner"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let dict = owned.dict(vector);
        let decryptor = Decryptor::new(&dict).expect(name);
        assert_decrypts(&decryptor, vector);
    }
}

#[test]
fn metadata_flag_is_reported() {
    let vector = vector("r4_aes_128_nometa");
    let owned = Owned::new(vector);
    let decryptor = Decryptor::new(&owned.dict(vector)).expect("opens");
    assert!(!decryptor.encrypts_metadata());
    let vector = self::vector("r2_rc4_40");
    let owned = Owned::new(vector);
    let decryptor = Decryptor::new(&owned.dict(vector)).expect("opens");
    assert!(decryptor.encrypts_metadata());
}

#[test]
fn rejects_other_handlers() {
    let vector = vector("r4_aes_128");
    let owned = Owned::new(vector);
    let dict = EncryptDict {
        filter: b"Adobe.PubSec",
        ..owned.dict(vector)
    };
    assert_eq!(
        Decryptor::new(&dict).err(),
        Some(CryptError::UnsupportedHandler)
    );
}

#[test]
fn rejects_bad_revision_and_version() {
    for name in ["r3_rc4_128", "r6_aes_256"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let base = owned.dict(vector);
        for (v, r) in [
            (vector.v, 7),
            (vector.v, 1),
            (vector.v, -2),
            (0, vector.r),
            (6, vector.r),
            (-1, vector.r),
            (5, 3),
        ] {
            let dict = EncryptDict { v, r, ..base };
            assert_eq!(
                Decryptor::new(&dict).err(),
                Some(CryptError::Malformed),
                "{name} v={v} r={r}"
            );
        }
    }
}

#[test]
fn rejects_unpublished_v3() {
    for name in ["r3_rc4_128", "r6_aes_256"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let dict = EncryptDict {
            v: 3,
            ..owned.dict(vector)
        };
        assert_eq!(
            Decryptor::new(&dict).err(),
            Some(CryptError::UnsupportedHandler),
            "{name}"
        );
    }
}

#[test]
fn tolerates_revision_mismatches() {
    for (name, v, r) in [
        ("r6_aes_256", 4, 6),
        ("r6_aes_256", 5, 5),
        ("r5_aes_256", 5, 6),
        ("r2_rc4_40", 2, 2),
    ] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let dict = EncryptDict {
            v,
            r,
            ..owned.dict(vector)
        };
        let decryptor = Decryptor::new(&dict).expect(name);
        assert_decrypts(&decryptor, vector);
    }
}

#[test]
fn tolerates_flipped_metadata_flag() {
    for (name, encrypt_metadata) in [("r4_aes_128_nometa", true), ("r4_aes_128", false)] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let dict = EncryptDict {
            encrypt_metadata,
            ..owned.dict(vector)
        };
        let decryptor = Decryptor::new(&dict).expect(name);
        assert_decrypts(&decryptor, vector);
    }
}

#[test]
fn rejects_truncated_entries() {
    for name in [
        "r2_rc4_40",
        "r3_rc4_128",
        "r4_aes_128",
        "r5_aes_256",
        "r6_aes_256",
    ] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let base = owned.dict(vector);
        let short_u = EncryptDict {
            u: owned.u.get(..10).expect("u"),
            ..base
        };
        assert_eq!(
            Decryptor::new(&short_u).err(),
            Some(CryptError::Malformed),
            "{name}"
        );
        let short_o = EncryptDict {
            o: owned.o.get(..20).expect("o"),
            ..base
        };
        assert_eq!(
            Decryptor::new(&short_o).err(),
            Some(CryptError::Malformed),
            "{name}"
        );
        let empty = EncryptDict {
            o: &[],
            u: &[],
            oe: &[],
            ue: &[],
            ..base
        };
        assert_eq!(
            Decryptor::new(&empty).err(),
            Some(CryptError::Malformed),
            "{name}"
        );
    }
    let vector = vector("r6_aes_256");
    let owned = Owned::new(vector);
    let dict = EncryptDict {
        ue: owned.ue.get(..31).expect("ue"),
        ..owned.dict(vector)
    };
    assert_eq!(Decryptor::new(&dict).err(), Some(CryptError::Malformed));
}

#[test]
fn garbage_o_fails_password_check() {
    let garbage = [0x5au8; 32];
    for name in ["r2_rc4_40", "r3_rc4_128", "r4_aes_128"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let dict = EncryptDict {
            o: &garbage,
            ..owned.dict(vector)
        };
        assert_eq!(
            Decryptor::new(&dict).err(),
            Some(CryptError::PasswordRequired),
            "{name}"
        );
    }
    let vector = vector("r6_aes_256");
    let owned = Owned::new(vector);
    let garbage = [0x5au8; 48];
    let dict = EncryptDict {
        o: &garbage,
        ..owned.dict(vector)
    };
    let decryptor = Decryptor::new(&dict).expect("user entry alone opens R6");
    assert_decrypts(&decryptor, vector);
}

#[test]
fn tolerates_oversized_entries() {
    for name in ["r3_rc4_128", "r4_aes_128", "r5_aes_256", "r6_aes_256"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let mut o = owned.o.clone();
        let mut u = owned.u.clone();
        o.extend_from_slice(&[0u8; 16]);
        u.extend_from_slice(&[0u8; 16]);
        let dict = EncryptDict {
            o: &o,
            u: &u,
            ..owned.dict(vector)
        };
        let decryptor = Decryptor::new(&dict).expect(name);
        assert_decrypts(&decryptor, vector);
    }
}

#[test]
fn tolerates_key_length_quirks() {
    let vector = vector("r3_rc4_128");
    let owned = Owned::new(vector);
    let base = owned.dict(vector);
    for length in [None, Some(16), Some(128), Some(1000), Some(-1)] {
        let dict = EncryptDict { length, ..base };
        let decryptor = Decryptor::new(&dict).expect("length quirk");
        assert_decrypts(&decryptor, vector);
    }
    let garbage = [0x5au8; 32];
    let dict = EncryptDict {
        length: Some(1000),
        o: &garbage,
        ..base
    };
    assert_eq!(Decryptor::new(&dict).err(), Some(CryptError::Malformed));

    for name in ["r4_aes_128", "r4_rc4_128"] {
        let vector = self::vector(name);
        let owned = Owned::new(vector);
        let base = owned.dict(vector);
        for (length, crypt_filter_length) in [
            (None, None),
            (Some(128), Some(128)),
            (None, Some(16)),
            (Some(40), Some(5)),
            (Some(0), None),
        ] {
            let dict = EncryptDict {
                length,
                crypt_filter_length,
                ..base
            };
            let decryptor = Decryptor::new(&dict).expect(name);
            assert_decrypts(&decryptor, vector);
        }
    }

    let vector = self::vector("r2_rc4_40");
    let owned = Owned::new(vector);
    let dict = EncryptDict {
        length: None,
        ..owned.dict(vector)
    };
    assert_decrypts(&Decryptor::new(&dict).expect("r2"), vector);
}

#[test]
fn tolerates_unsigned_permissions() {
    let vector = vector("r3_rc4_128");
    let owned = Owned::new(vector);
    let dict = EncryptDict {
        p: vector.p + (1i64 << 32),
        ..owned.dict(vector)
    };
    assert_decrypts(&Decryptor::new(&dict).expect("unsigned P"), vector);
}

#[test]
fn v5_forces_aes256_methods() {
    let vector = vector("r6_aes_256");
    let owned = Owned::new(vector);
    let dict = EncryptDict {
        stream_method: Some(CryptMethod::AesV2),
        string_method: Some(CryptMethod::Rc4),
        ..owned.dict(vector)
    };
    assert_decrypts(&Decryptor::new(&dict).expect("v5"), vector);

    let vector = self::vector("r4_aes_128");
    let owned = Owned::new(vector);
    let dict = EncryptDict {
        stream_method: Some(CryptMethod::AesV3),
        ..owned.dict(vector)
    };
    assert_eq!(Decryptor::new(&dict).err(), Some(CryptError::Malformed));
}

#[test]
fn identity_methods_need_no_key() {
    let vector = vector("r4_aes_128");
    let owned = Owned::new(vector);
    let garbage = [0x5au8; 32];
    let dict = EncryptDict {
        o: &garbage,
        stream_method: None,
        string_method: Some(CryptMethod::Identity),
        ..owned.dict(vector)
    };
    let decryptor = Decryptor::new(&dict).expect("identity");
    let mut out = b"prefix".to_vec();
    decryptor.decrypt(Target::Stream, 1, 0, b"plain", &mut out);
    assert_eq!(out, b"prefixplain");
}

#[test]
fn short_and_empty_input() {
    for vector in VECTORS {
        let owned = Owned::new(vector);
        let decryptor =
            Decryptor::with_password(&owned.dict(vector), vector.password).expect(vector.name);
        for target in [Target::String, Target::Stream] {
            let mut out = b"keep".to_vec();
            decryptor.decrypt(target, 1, 0, &[], &mut out);
            assert_eq!(out, b"keep", "{}", vector.name);
        }
        if decryptor.method(Target::Stream) == CryptMethod::Rc4 {
            continue;
        }
        let cipher = hex(vector.stream_cipher);
        for len in [1, 15, 16, 17, 31] {
            let mut out = b"keep".to_vec();
            decryptor.decrypt(
                Target::Stream,
                vector.stream_object.0,
                vector.stream_object.1,
                cipher.get(..len).expect("prefix"),
                &mut out,
            );
            assert_eq!(out, b"keep", "{} len {len}", vector.name);
        }
    }
}

#[test]
fn aes_ignores_trailing_partial_block() {
    for name in ["r4_aes_128", "r5_aes_256", "r6_aes_256"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let decryptor = Decryptor::new(&owned.dict(vector)).expect(name);
        let mut cipher = hex(vector.stream_cipher);
        cipher.extend_from_slice(b"trail");
        let mut out = Vec::new();
        decryptor.decrypt(
            Target::Stream,
            vector.stream_object.0,
            vector.stream_object.1,
            &cipher,
            &mut out,
        );
        assert_eq!(out, hex(vector.stream_plain), "{name}");
    }
}

#[test]
fn aes_keeps_raw_bytes_on_bad_padding() {
    for name in ["r4_aes_128", "r6_aes_256"] {
        let vector = vector(name);
        let owned = Owned::new(vector);
        let decryptor = Decryptor::new(&owned.dict(vector)).expect(name);
        let plain = hex(vector.stream_plain);
        let mut cipher = hex(vector.stream_cipher);
        let flip_at = cipher.len() - 17;
        if let Some(byte) = cipher.get_mut(flip_at) {
            *byte ^= 0x80;
        }
        let mut out = Vec::new();
        decryptor.decrypt(
            Target::Stream,
            vector.stream_object.0,
            vector.stream_object.1,
            &cipher,
            &mut out,
        );
        let whole = cipher.len() - 16;
        let pad = whole - plain.len();
        assert_eq!(out.len(), whole, "{name}");
        assert_eq!(out.get(..whole - 32), plain.get(..whole - 32), "{name}");
        assert_eq!(
            out.get(whole - 16..plain.len()),
            plain.get(whole - 16..),
            "{name}"
        );
        let mut expected_pad = vec![pad as u8; pad];
        if let Some(last) = expected_pad.last_mut() {
            *last ^= 0x80;
        }
        assert_eq!(
            out.get(plain.len()..),
            Some(expected_pad.as_slice()),
            "{name}"
        );
    }
}

#[test]
fn wrong_object_number_changes_output() {
    let vector = vector("r3_rc4_128");
    let owned = Owned::new(vector);
    let decryptor = Decryptor::new(&owned.dict(vector)).expect("r3");
    let (object, generation) = vector.string_object;
    assert_ne!(
        decrypted(
            &decryptor,
            Target::String,
            (object + 1, generation),
            vector.title_cipher
        ),
        hex(vector.title_plain)
    );
}

#[test]
fn decryptor_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Decryptor>();
}

const BUG1782186_O: &str = "0003194bd751c004a5b7177df9716e3e29b9004cabe71da0ae6f0bd2b203fafe";
const BUG1782186_U: &str = "29421ce3fc0039a57eeb573978a7c77700000000000000000000000000000000";
const BUG1782186_ID0: &str = "dd801827e7d886476b1220d8349d6f00";
const BUG1782186_KEY: &str = "45b90efe719b22e11be145ecc5bf4039";
const BUG1782186_STREAM: &str = "00000000000000000000000000000000b37eef688045764e405d20e0bac6720c4ebfabeeafa4a7d3826220e47848cd89011a0b62a7fa5ce240c5bc7d09ef9c5df329a506523d044269d65c80b897ea730654e053d77c79401c37cdc1fae3b09f14da9b57274770fdd1ba8f7c35976d2d3e0d6cf5cd1d63f8cac7034535e6ac853324e563ce4a869f6183845e4eb85c6f1fd5082bb334230faae9b1c3d53c1426f886207473709899df11c020a7b297adc71c90ff6b829d58903e0dbbcef72d76a8d12d46072696f6f4ce7d636dd9888691d60a92a8331a79aff9f2e2705538028fde0b1df3ce0500523f0a5ccb089a5ac88cc755109c495e705ac60c08887aadd2faf5587e8ec9573ac56cdf2890359a95971741eeb6d5b5beca16db64ca1e10037db4b4e4d993508f4460c0aec8a58dfd5afc66f2909e51d8f98f77f2f527b98b566a01b26335f0d2ad176ca100e18bf8a7c45578f0237c35c13e6f84d3d6ca970bc4c6f7d1eb33d97ec1b4a6080845316b87831c62f4236fc16d1bfaa0eef19b8cd13ce563f22726bbcc90b9eec1e7b7b0c91aca8c33fd38a44a00ad4023f8518376378bed9658588bbbe16596633a3028d347d5946ccc0eeec302cf816d7feedfc13d375151c5421df21be12965bc9b939f3cd7be242419b11193a29f57de2da5da789616f67aad48f28d1c3a40309442260daa5db27fbee398d3cfe9af66";
const BUG1782186_PLAIN: &str = "252525252525252525252525252525252525252525252525252525252525252525252525252525250d0a25204c6179657220224c617965723122200d0a2f53414f66662067730d0a2f4f43202f4c6179657230204244430d0a302e37303836363120770d0a30204a0d0a30206a0d0a31302e30303030204d0d0a2f426c61636b2043530d0a312e3030303030302053434e0d0a3338342e34353338363831203431312e30313233303133206d0d0a3435312e39353737393938203431312e30313233303133203530362e36383236313739203337312e36383536313537203530362e36383236313739203332332e3137353532343820630d0a3530362e36383236313739203237342e36363534333338203435312e39353737393938203233352e33333837343832203338342e34353338363831203233352e3333383734383220630d0a3331362e39343939333634203233352e33333837343832203236322e32323531313833203237342e36363534333338203236322e32323531313833203332332e3137353532343820630d0a3236322e32323531313833203337312e36383536313537203331362e39343939333634203431312e30313233303133203338342e34353338363831203431312e3031323330313320630d0a680d0a730d0a454d430d0a";

#[test]
fn pdfjs_bug1782186_needs_its_password() {
    let (o, u, id0) = (hex(BUG1782186_O), hex(BUG1782186_U), hex(BUG1782186_ID0));
    let dict = EncryptDict {
        filter: b"Standard",
        v: 4,
        r: 4,
        length: Some(128),
        o: &o,
        u: &u,
        oe: &[],
        ue: &[],
        p: -1852,
        encrypt_metadata: false,
        stream_method: Some(CryptMethod::AesV2),
        string_method: Some(CryptMethod::Identity),
        crypt_filter_length: Some(16),
        id0: &id0,
    };
    assert_eq!(
        Decryptor::new(&dict).err(),
        Some(CryptError::PasswordRequired)
    );
    let decryptor = Decryptor::with_password(&dict, b"Hello").expect("pdf.js test password");
    assert_eq!(decryptor.key.as_slice(), hex(BUG1782186_KEY));
    assert_eq!(
        decrypted(&decryptor, Target::Stream, (15, 0), BUG1782186_STREAM),
        hex(BUG1782186_PLAIN)
    );
    assert_eq!(
        decrypted(&decryptor, Target::String, (15, 0), "48656c6c6f"),
        b"Hello"
    );
}
