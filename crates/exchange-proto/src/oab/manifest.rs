/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::{FULL_VERSION, TEMPLATE_VERSION, path::OabFile};
use crate::{
    common::{Braces, Guid, HexCase, guid::push_hex_lower},
    xml::XmlWriter,
};

pub const MANIFEST_DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
pub const TEMPLATE_LANGID: &str = "0409";
pub const TEMPLATE_TYPE: &str = "windows";
pub const SHA1_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestFile {
    pub seq: u32,
    pub size: u32,
    pub uncompressed: u32,
    pub sha1: [u8; SHA1_LEN],
}

#[derive(Debug, Clone, Copy)]
pub struct OabManifest<'x> {
    pub guid: Guid,
    pub name: &'x str,
    pub distinguished_name: &'x str,
    pub full: ManifestFile,
    pub template: ManifestFile,
}

pub fn write_manifest(out: &mut Vec<u8>, manifest: &OabManifest<'_>) {
    let mut guid = Vec::with_capacity(36);
    manifest
        .guid
        .write_text(&mut guid, HexCase::Lower, Braces::None);
    let guid = std::str::from_utf8(&guid).unwrap_or_default();
    out.extend_from_slice(MANIFEST_DECL.as_bytes());
    let mut w = XmlWriter::new(out);
    w.start("", "OAB").close_start();
    w.start("", "OAL")
        .attr("id", guid)
        .attr("dn", manifest.distinguished_name)
        .attr("name", manifest.name)
        .close_start();
    file_element(&mut w, "Full", FULL_VERSION, &manifest.full).close_start();
    write_file_name(
        &mut w,
        manifest.guid,
        OabFile::Full {
            seq: manifest.full.seq,
        },
    );
    w.end("", "Full");
    file_element(&mut w, "Template", TEMPLATE_VERSION, &manifest.template)
        .attr("langid", TEMPLATE_LANGID)
        .attr("type", TEMPLATE_TYPE)
        .close_start();
    write_file_name(
        &mut w,
        manifest.guid,
        OabFile::Template {
            seq: manifest.template.seq,
        },
    );
    w.end("", "Template");
    w.end("", "OAL");
    w.end("", "OAB");
}

fn file_element<'w, 'o>(
    w: &'w mut XmlWriter<'o>,
    name: &str,
    version: u32,
    file: &ManifestFile,
) -> &'w mut XmlWriter<'o> {
    let mut sha = Vec::with_capacity(SHA1_LEN * 2);
    push_hex_lower(&file.sha1, &mut sha);
    w.start("", name)
        .attr_u64("seq", u64::from(file.seq))
        .attr_u64("ver", u64::from(version))
        .attr_u64("size", u64::from(file.size))
        .attr_u64("uncompressedsize", u64::from(file.uncompressed))
        .attr("SHA", std::str::from_utf8(&sha).unwrap_or_default())
}

fn write_file_name(w: &mut XmlWriter<'_>, guid: Guid, file: OabFile) {
    file.write_name(guid, w.buffer());
}
