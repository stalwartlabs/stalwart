/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod epub;
mod html;
mod odf;
mod ooxml;
mod output;
mod package;
mod rtf;
mod xml;
mod zip;

use output::Output;
use package::Package;
use xml::stream::{Budget, Buffers};
use zip::{Archive, Entry, MemberData, ReadRanges};

const MIMETYPE: &[u8] = b"mimetype";
const MAX_MIMETYPE: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    Docx,
    Xlsx,
    Pptx,
    Odt,
    Ods,
    Odp,
    Epub,
    Rtf,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Hints<'a> {
    media_type: Option<(&'a str, &'a str)>,
    file_name: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_entries: usize,
    pub max_parts: usize,
    pub max_part_bytes: u64,
    pub max_total_bytes: u64,
    pub max_rtf_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extraction {
    pub format: Format,
    pub truncated: bool,
    pub bytes_written: usize,
    pub bytes_decompressed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub error: Error,
    pub bytes_decompressed: u64,
}

#[derive(Default)]
pub struct Extractor {
    limits: Limits,
    entries: Vec<Entry>,
    claimed: ReadRanges,
    buffers: Buffers,
    ooxml: ooxml::Scratch,
    epub: epub::Scratch,
    rtf: rtf::Scratch,
}

enum Container {
    Ooxml,
    Odf(Option<Format>),
    Epub,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_input_bytes: 64 << 20,
            max_output_bytes: 4 << 20,
            max_entries: 10_000,
            max_parts: 1_000,
            max_part_bytes: 64 << 20,
            max_total_bytes: 256 << 20,
            max_rtf_depth: 256,
        }
    }
}

impl<'a> Hints<'a> {
    pub fn new() -> Self {
        Hints::default()
    }

    pub fn with_media_type(mut self, media_type: &'a str) -> Self {
        let essence = media_type
            .split_once(';')
            .map_or(media_type, |(essence, _)| essence)
            .trim();
        self.media_type = Some(essence.split_once('/').unwrap_or((essence, "")));
        self
    }

    pub fn with_media_type_parts(mut self, type_: &'a str, subtype: &'a str) -> Self {
        self.media_type = Some((type_, subtype));
        self
    }

    pub fn with_file_name(mut self, file_name: &'a str) -> Self {
        self.file_name = Some(file_name);
        self
    }

    pub fn format(&self) -> Option<Format> {
        self.media_type_format().or_else(|| self.extension_format())
    }

    pub fn may_be_supported(&self) -> bool {
        match self.media_type {
            None => self.file_name.is_none() || self.extension_format().is_some(),
            Some(_) => {
                self.media_type_format().is_some()
                    || self.extension_format().is_some()
                    || (self.is_generic_media_type() && !self.has_extension())
            }
        }
    }

    fn media_type_format(&self) -> Option<Format> {
        let (type_, subtype) = self.media_type?;
        if hashify::tiny_set_ignore_case!(type_.as_bytes(), b"text") {
            return hashify::tiny_map_ignore_case!(subtype.as_bytes(),
                b"rtf" => Format::Rtf,
            );
        }
        if !hashify::tiny_set_ignore_case!(type_.as_bytes(), b"application") {
            return None;
        }
        hashify::tiny_map_ignore_case!(subtype.as_bytes(),
            b"vnd.openxmlformats-officedocument.wordprocessingml.document" => Format::Docx,
            b"vnd.openxmlformats-officedocument.wordprocessingml.template" => Format::Docx,
            b"vnd.ms-word.document.macroenabled.12" => Format::Docx,
            b"vnd.ms-word.template.macroenabled.12" => Format::Docx,
            b"vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Format::Xlsx,
            b"vnd.openxmlformats-officedocument.spreadsheetml.template" => Format::Xlsx,
            b"vnd.ms-excel.sheet.macroenabled.12" => Format::Xlsx,
            b"vnd.ms-excel.template.macroenabled.12" => Format::Xlsx,
            b"vnd.openxmlformats-officedocument.presentationml.presentation" => Format::Pptx,
            b"vnd.openxmlformats-officedocument.presentationml.slideshow" => Format::Pptx,
            b"vnd.openxmlformats-officedocument.presentationml.template" => Format::Pptx,
            b"vnd.ms-powerpoint.presentation.macroenabled.12" => Format::Pptx,
            b"vnd.ms-powerpoint.slideshow.macroenabled.12" => Format::Pptx,
            b"vnd.oasis.opendocument.text" => Format::Odt,
            b"vnd.oasis.opendocument.text-template" => Format::Odt,
            b"vnd.oasis.opendocument.spreadsheet" => Format::Ods,
            b"vnd.oasis.opendocument.spreadsheet-template" => Format::Ods,
            b"vnd.oasis.opendocument.presentation" => Format::Odp,
            b"vnd.oasis.opendocument.presentation-template" => Format::Odp,
            b"epub+zip" => Format::Epub,
            b"rtf" => Format::Rtf,
            b"x-rtf" => Format::Rtf,
        )
    }

    fn is_generic_media_type(&self) -> bool {
        self.media_type.is_some_and(|(type_, subtype)| {
            hashify::tiny_set_ignore_case!(type_.as_bytes(), b"application")
                && hashify::tiny_set_ignore_case!(
                    subtype.as_bytes(),
                    b"octet-stream",
                    b"zip",
                    b"x-zip",
                    b"x-zip-compressed",
                    b"msword",
                    b"vnd.ms-excel",
                    b"vnd.ms-powerpoint",
                    b"vnd.ms-office",
                    b"force-download",
                    b"x-download",
                    b"download",
                    b"binary",
                    b"unknown",
                )
        })
    }

    fn has_extension(&self) -> bool {
        self.file_name.is_some_and(|name| {
            name.rsplit_once('.')
                .is_some_and(|(stem, _)| !stem.is_empty())
        })
    }

    fn extension_format(&self) -> Option<Format> {
        let (_, extension) = self.file_name?.rsplit_once('.')?;
        hashify::tiny_map_ignore_case!(extension.as_bytes().trim_ascii_end(),
            b"docx" => Format::Docx,
            b"docm" => Format::Docx,
            b"dotx" => Format::Docx,
            b"dotm" => Format::Docx,
            b"xlsx" => Format::Xlsx,
            b"xlsm" => Format::Xlsx,
            b"xltx" => Format::Xlsx,
            b"xltm" => Format::Xlsx,
            b"pptx" => Format::Pptx,
            b"pptm" => Format::Pptx,
            b"ppsx" => Format::Pptx,
            b"ppsm" => Format::Pptx,
            b"potx" => Format::Pptx,
            b"potm" => Format::Pptx,
            b"odt" => Format::Odt,
            b"ott" => Format::Odt,
            b"ods" => Format::Ods,
            b"ots" => Format::Ods,
            b"odp" => Format::Odp,
            b"otp" => Format::Odp,
            b"epub" => Format::Epub,
            b"rtf" => Format::Rtf,
        )
    }
}

impl Extractor {
    pub fn new(limits: Limits) -> Self {
        Extractor {
            limits,
            ..Default::default()
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn limits_mut(&mut self) -> &mut Limits {
        &mut self.limits
    }

    pub fn extract(
        &mut self,
        data: &[u8],
        hints: Hints<'_>,
        out: &mut String,
    ) -> Result<Extraction, Failure> {
        if data.len() > self.limits.max_input_bytes {
            return Err(Error::TooLarge.into());
        }
        let original_len = out.len();
        self.extract_into(data, hints, out)
            .inspect_err(|_| out.truncate(original_len))
    }

    fn extract_into(
        &mut self,
        data: &[u8],
        hints: Hints<'_>,
        out: &mut String,
    ) -> Result<Extraction, Failure> {
        let mut output = Output::new(out, self.limits.max_output_bytes);
        if rtf::is_rtf(data) {
            rtf::extract(data, &mut self.rtf, self.limits.max_rtf_depth, &mut output);
            return Ok(Extraction {
                format: Format::Rtf,
                truncated: output.is_full(),
                bytes_written: output.written(),
                bytes_decompressed: 0,
            });
        }

        let Extractor {
            limits,
            entries,
            claimed,
            buffers,
            ooxml,
            epub,
            ..
        } = self;
        let archive = Archive::open(data, entries, limits.max_entries).ok_or(Error::Unsupported)?;
        claimed.clear();
        let mut package = Package {
            archive: &archive,
            buffers,
            claimed,
            budget: Budget {
                part_bytes: limits.max_part_bytes,
                total_bytes: limits.max_total_bytes,
                parts: limits.max_parts,
                used_bytes: 0,
                used_parts: 0,
                truncated: archive.entries_truncated,
            },
        };
        let container = detect(&mut package, hints).ok_or(Error::Unsupported)?;
        let format = match container {
            Container::Ooxml => ooxml::extract(&mut package, ooxml, &mut output),
            Container::Odf(declared) => odf::extract(&mut package, declared, &mut output),
            Container::Epub => {
                epub::extract(&mut package, epub, &mut output);
                Some(Format::Epub)
            }
        }
        .ok_or(Failure {
            error: Error::Unsupported,
            bytes_decompressed: package.budget.used_bytes,
        })?;
        Ok(Extraction {
            format,
            truncated: output.is_full() || package.budget.truncated,
            bytes_written: output.written(),
            bytes_decompressed: package.budget.used_bytes,
        })
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Failure {
            error,
            bytes_decompressed: 0,
        }
    }
}

fn detect(package: &mut Package<'_, '_>, hints: Hints<'_>) -> Option<Container> {
    let archive = package.archive;
    let declared =
        archive
            .find(MIMETYPE)
            .and_then(|member| match archive.read(&member, package.claimed)? {
                MemberData::Stored(value) if value.len() <= MAX_MIMETYPE => Some(value),
                _ => None,
            });
    if let Some(declared) = declared {
        if hashify::tiny_set!(declared.trim_ascii(), b"application/epub+zip") {
            return Some(Container::Epub);
        }
        if let Some(format) = odf::format_from_mimetype(declared) {
            return Some(Container::Odf(Some(format)));
        }
    }
    let has_odf_content = archive.contains(odf::CONTENT);
    let has_epub_container = archive.contains(epub::CONTAINER);
    if ooxml::is_package(package) {
        return Some(Container::Ooxml);
    }
    match (has_odf_content, has_epub_container) {
        (true, true) => Some(match hints.format() {
            Some(Format::Epub) => Container::Epub,
            _ => Container::Odf(None),
        }),
        (true, false) => Some(Container::Odf(None)),
        (false, true) => Some(Container::Epub),
        (false, false) => None,
    }
}

pub fn extract(
    data: &[u8],
    hints: Hints<'_>,
    limits: &Limits,
    out: &mut String,
) -> Result<Extraction, Failure> {
    Extractor::new(limits.clone()).extract(data, hints, out)
}
