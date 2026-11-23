/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{
    config::PemSource,
    error::{Material, TlsError},
};
use aws_lc_sys::{
    BIO_free, BIO_new_mem_buf, CBB, CBB_cleanup, CBB_finish, CBB_init, ERR_clear_error,
    EVP_PKEY_free, EVP_marshal_private_key, OPENSSL_free, PEM_read_bio_PrivateKey,
};
use memchr::memmem;
use rustls_pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer,
    pem::{self, PemObject},
};
use std::{
    borrow::Cow,
    ffi::{CString, c_void},
    fs,
    mem::MaybeUninit,
    ptr, slice,
};

const MAX_FILE_SIZE: u64 = 5 << 20;
const LEGACY_ENCRYPTED: &[u8] = b"Proc-Type: 4,ENCRYPTED";

pub(crate) fn read(source: &PemSource, material: Material) -> Result<Cow<'_, [u8]>, TlsError> {
    match source {
        PemSource::Pem(pem) => Ok(Cow::Borrowed(pem)),
        PemSource::Path(path) => {
            let read_error = |err: std::io::Error| TlsError::Read {
                material,
                path: path.as_path().into(),
                kind: err.kind(),
            };
            if fs::metadata(path).map_err(read_error)?.len() > MAX_FILE_SIZE {
                return Err(TlsError::TooLarge {
                    material,
                    path: path.as_path().into(),
                });
            }
            fs::read(path).map(Cow::Owned).map_err(read_error)
        }
    }
}

pub(crate) fn certificates(
    pem: &[u8],
    material: Material,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::Pem { material })?;
    if certificates.is_empty() {
        return Err(TlsError::NoCertificate { material });
    }
    Ok(certificates)
}

pub(crate) fn private_key(
    pem: &[u8],
    password: Option<&str>,
) -> Result<PrivateKeyDer<'static>, TlsError> {
    match PrivateKeyDer::from_pem_slice(pem) {
        Ok(key) => Ok(key),
        Err(pem::Error::NoItemsFound) => decrypt_private_key(pem, password),
        Err(_) if memmem::find(pem, LEGACY_ENCRYPTED).is_some() => {
            decrypt_private_key(pem, password)
        }
        Err(_) => Err(TlsError::Pem {
            material: Material::Key,
        }),
    }
}

fn decrypt_private_key(
    pem: &[u8],
    password: Option<&str>,
) -> Result<PrivateKeyDer<'static>, TlsError> {
    let password = CString::new(password.unwrap_or_default()).map_err(|_| TlsError::KeyPassword)?;
    let len = isize::try_from(pem.len()).map_err(|_| TlsError::Key)?;
    let der = unsafe {
        let bio = BIO_new_mem_buf(pem.as_ptr().cast::<c_void>(), len);
        if bio.is_null() {
            return Err(TlsError::Key);
        }
        let key = PEM_read_bio_PrivateKey(
            bio,
            ptr::null_mut(),
            None,
            password.as_ptr().cast_mut().cast::<c_void>(),
        );
        BIO_free(bio);
        if key.is_null() {
            ERR_clear_error();
            return Err(TlsError::Key);
        }
        let mut cbb = MaybeUninit::<CBB>::uninit();
        let mut out = ptr::null_mut::<u8>();
        let mut out_len = 0usize;
        let marshalled = CBB_init(cbb.as_mut_ptr(), 0) == 1 && {
            let ok = EVP_marshal_private_key(cbb.as_mut_ptr(), key) == 1
                && CBB_finish(cbb.as_mut_ptr(), &mut out, &mut out_len) == 1;
            if !ok {
                CBB_cleanup(cbb.as_mut_ptr());
            }
            ok
        };
        EVP_PKEY_free(key);
        if !marshalled || out.is_null() {
            ERR_clear_error();
            return Err(TlsError::Key);
        }
        let der = slice::from_raw_parts(out, out_len).to_vec();
        OPENSSL_free(out.cast::<c_void>());
        der
    };
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}

#[cfg(all(test, stalwart_tests))]
#[rustfmt::skip]
#[path = "../../../../../stalwart-tests/unit/fdb/src/tls/material/tests.rs"]
mod tests;
