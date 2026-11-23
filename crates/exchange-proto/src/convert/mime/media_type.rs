/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub(super) fn from_extension(extension: &str) -> Option<&'static str> {
    let extension = extension.strip_prefix('.').unwrap_or(extension);
    hashify::map_ignore_case!(extension.as_bytes(), &'static str,
        b"png" => "image/png",
        b"jpg" => "image/jpeg",
        b"jpeg" => "image/jpeg",
        b"jpe" => "image/jpeg",
        b"gif" => "image/gif",
        b"bmp" => "image/bmp",
        b"tif" => "image/tiff",
        b"tiff" => "image/tiff",
        b"ico" => "image/x-icon",
        b"svg" => "image/svg+xml",
        b"webp" => "image/webp",
        b"heic" => "image/heic",
        b"txt" => "text/plain",
        b"log" => "text/plain",
        b"csv" => "text/csv",
        b"htm" => "text/html",
        b"html" => "text/html",
        b"css" => "text/css",
        b"xml" => "text/xml",
        b"ics" => "text/calendar",
        b"vcf" => "text/vcard",
        b"rtf" => "application/rtf",
        b"pdf" => "application/pdf",
        b"zip" => "application/zip",
        b"gz" => "application/gzip",
        b"7z" => "application/x-7z-compressed",
        b"json" => "application/json",
        b"js" => "text/javascript",
        b"doc" => "application/msword",
        b"dot" => "application/msword",
        b"xls" => "application/vnd.ms-excel",
        b"ppt" => "application/vnd.ms-powerpoint",
        b"docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        b"xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        b"pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        b"odt" => "application/vnd.oasis.opendocument.text",
        b"ods" => "application/vnd.oasis.opendocument.spreadsheet",
        b"odp" => "application/vnd.oasis.opendocument.presentation",
        b"msg" => "application/vnd.ms-outlook",
        b"mp3" => "audio/mpeg",
        b"wav" => "audio/wav",
        b"mp4" => "video/mp4",
        b"mov" => "video/quicktime",
        b"avi" => "video/x-msvideo",
    )
    .copied()
}
