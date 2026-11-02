/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use mail_parser::{Message, MessagePart};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedProtocol {
    Pgp,
    Smime,
}

pub(crate) struct DetachedSignature<'x> {
    pub protocol: SignedProtocol,
    pub content: &'x [u8],
    pub signature: MessagePart<'x>,
}

pub(crate) fn detached_signature<'x>(message: &'x Message<'x>) -> Option<DetachedSignature<'x>> {
    let root = message.root_part();
    let ct = root.content_type()?;
    if !ct.ctype().eq_ignore_ascii_case("multipart")
        || !ct.subtype()?.eq_ignore_ascii_case("signed")
    {
        return None;
    }
    let protocol = *hashify::map_ignore_case!(
        ct.attribute("protocol")?.trim().as_bytes(),
        SignedProtocol,
        "application/pgp-signature" => SignedProtocol::Pgp,
        "application/pkcs7-signature" => SignedProtocol::Smime,
        "application/x-pkcs7-signature" => SignedProtocol::Smime,
    )?;
    let mut children = root.children();
    let content = children.next()?.raw();
    let signature = children.next()?;
    Some(DetachedSignature {
        protocol,
        content,
        signature,
    })
}

pub(crate) fn opaque_signed_data<'x>(message: &'x Message<'x>) -> Option<MessagePart<'x>> {
    let root = message.root_part();
    let ct = root.content_type()?;
    let is_pkcs7 = ct.ctype().eq_ignore_ascii_case("application")
        && hashify::set_ignore_case!(ct.subtype()?.as_bytes(), "pkcs7-mime", "x-pkcs7-mime");
    let signed = ct
        .attribute("smime-type")
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("signed-data"));
    (is_pkcs7 && signed).then_some(root)
}
