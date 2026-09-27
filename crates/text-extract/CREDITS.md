# Credits and third-party material

This file records the third-party code, algorithms, data and test files used by the `text-extract` crate, and the license under which each was used. It is meant for maintainers and for license review of the project's AGPL-3.0 and commercial distributions. Anything not listed here was written for this project.

Most of the crate's code was written from scratch. Where another project's code or data was adapted, the source file is named below. Projects under copyleft licenses (MuPDF, poppler) were consulted for ideas only; nothing was copied from them.

## 1. Code and algorithms adapted from other projects

Unless noted otherwise, the material below was adapted (translated to Rust, restructured), not copied verbatim.

### pdf.js (Mozilla Foundation), Apache-2.0

Source: <https://github.com/mozilla/pdf.js>, commit d52fdf411a6e4d338180687456e0df019e28475e. Copyright Mozilla Foundation.

Object layer (`src/pdf/`, lexer, xref, repair):

- `src/core/parser.js` `Lexer.getNumber`: collapsing repeated leading minus signs, skipping line breaks after a sign, reading a lone sign or dot as 0, ignoring a minus sign inside a number.
- `src/core/parser.js` `Lexer.getObj`: a non-printable byte followed by a printable one is a one-byte keyword; a stray `)` is consumed so the lexer always makes progress.
- `src/core/parser.js` `Lexer.getHexString`: invalid hex characters ignored, odd digit count padded with 0.
- `src/core/xref.js` `readXRefTable`: the first-subsection fix (`1 N` whose first entry is free becomes `0 N`).
- `src/core/xref.js` `readXRef`: queue order (table, `/XRefStm`, `/Prev`) with a set of visited offsets; `/Prev N 0 R` accepted as offset N.
- `src/core/xref.js` `fetchCompressed`: looking up an object-stream member by number when the index does not match (bug 1978317).
- `src/core/xref.js` recovery: trailer candidates validated by a `/Root` that reaches a `/Pages` dictionary.
- `src/core/string_utils.js` `PDFStringTranslateTable` and `stringToPDFString`: the PDFDocEncoding table, UTF-16LE BOM support, removal of ESC-delimited language codes.
- `src/core/document.js` `checkHeader`: header search in the first 1024 bytes and header-relative offsets.

Stream filters (`src/pdf/filter/`):

- `src/core/lzw_stream.js` (table walked backwards to emit a code, EarlyChange width rule), `ascii_85_stream.js` (final group padding, `~` as end of data), `ascii_hex_stream.js` (non-hex bytes ignored), `run_length_stream.js`, `predictor_stream.js` (PNG row filters, Paeth tie order, TIFF predictor 2 for 1 to 16 bits per component). Semantics and structure only, no verbatim code.

Decryption (`src/pdf/crypt/`):

- `src/core/crypto.js`: the structure of the key derivation, lenient AES-CBC framing (IV prefix, trailing partial block dropped, PKCS#7 padding stripped only when valid), the Algorithm 2.B round loop and termination rule, the fallback when `/Length` is given in bytes, zero-padding a short version 4 file key to 16 bytes (issue 19484), forcing AES-256 for every crypt filter when V is 5 (bug 2046659).

Text layer (`src/pdf/font/`, `content/`, `layout/`, `forms.rs`):

- `src/core/evaluator.js` (`getTextContent`): a real space glyph only counts when the pen moved (the 0.03 em rule), zero-width glyphs never move the previous ink end, gaps measured from the ink end before character spacing, the per-document cache of form XObjects that drew no text, the ancestor set that stops form cycles, `/Font` in ExtGState dictionaries, keeping the last font when `Tf` names an unknown resource.
- `src/core/evaluator.js` (`_simpleFontToUnicode`, font loading): the list of ten simple-font names written as GBK bytes (SimSun, SimHei, SimKai, SimFang and variants, XiaoBiaoSong), reproduced in `src/pdf/font/simple.rs` (`GBK_FONT_NAMES`); `/ToUnicode /Identity-H` given as a name; empty ToUnicode treated as absent; `.notdef` Differences entries leaving the base encoding in place.
- `src/core/cmap.js` and `evaluator.js` (`readToUnicode`): odd-length and one-byte destination strings left-padded with zero (issue 18099), bfrange array destinations mapped for `min(range, array length)` codes.
- `src/core/parser.js` (`findDefaultInlineStreamEnd`, ASCIIHex and ASCII85 end finders): inline image end detection.
- `src/shared/util.js` (`normalizeUnicode`): NFKC of ligatures and Arabic presentation forms at emission.

Tables and font programs (data copied, see also section 2):

- `src/core/encodings.js`: StandardEncoding, WinAnsiEncoding, MacRomanEncoding, MacExpertEncoding, SymbolSetEncoding, ZapfDingbatsEncoding and ExpertEncoding tables (`src/pdf/tables/encoding_data.rs`). Modified: MacRoman code 0xF0 (`apple`) is left undefined, as in the PDF specification.
- `src/core/glyphlist.js`: 121 glyph names pdf.js adds to the Adobe Glyph List (mostly TeX math extension names). Modified: `intercal` maps to U+22BA instead of U+1D40; underscore ligature names dropped.
- `src/core/standard_fonts.js`: standard-14 font name aliases (`getStdFontMap`) and the font name normalisation rule.
- `src/core/evaluator.js` and `src/core/unicode.js`: numeric glyph name heuristics (`Gxx`, `g00xx`, `Cdd`/`cdd` with hexadecimal fallback).
- `src/core/cff_parser.js` `CFFStandardStrings`, `src/core/charsets.js` `ExpertCharset` and `ExpertSubsetCharset` (stored in `src/pdf/font/program/cff_data.rs`), `src/core/fonts_utils.js` `MacStandardGlyphOrdering` (stored in `src/pdf/font/program/post_data.rs`).
- `src/core/type1_parser.js` (`extractFontHeader`): scanning cleartext tokens for `dup <code> /<name> put` up to `def`. Modified: a later `/Encoding` replaces an earlier one, radix numbers accepted, string tokens skipped whole, scanning stops at `eexec`.

### Apache PDFBox (The Apache Software Foundation), Apache-2.0

Source: <https://github.com/apache/pdfbox>, commit 2245d1c2bb3bbcfe56136a693c395317316ace96.

- `pdfparser/BaseParser.java` and `COSParser.java`: after `stream`, skip spaces then exactly one EOL; `validateStreamLength` (trust `/Length` only when `endstream` follows); a missing `endstream` bounded by `endobj`.
- `pdfparser/BruteForceParser.java`: during repair, an object-stream member replaces an uncompressed definition only when the object stream appears later in the file.
- `pdfparser/PDFXrefStreamParser.java`: `/W` validation and stopping an xref stream section when its data runs out.
- `pdmodel/PDPageTree.java` (PDFBOX-5009, PDFBOX-3953): skipping page-tree nodes already visited.
- `filter/FlateFilterDecoderStream.java`: skipping the two zlib header bytes and inflating raw deflate, so bad Adler-32 checksums and trailing bytes are harmless (idea only).
- `pdmodel/encryption/StandardSecurityHandler.java`: zero-padding a short revision 4 key (PDFBOX-5955), accepting the empty owner password (ideas only).
- `text/PDFTextStripper.java`: duplicate glyph suppression with a tolerance of a third of the glyph width (fake bold, shadows), the space threshold capped at half the font's space width, ActualText honoured on any marked-content tag with duplicate suppression disabled inside it.
- `contentstream/PDFStreamEngine.java` (`showText`): the advance formula, word spacing applied only to single-byte code 32, TJ adjustments.
- `pdmodel/font/PDFont.java` (`getSpaceWidth`): space width from the code that maps to U+0020.
- `pdmodel/font/PDType0Font.java` (`toUnicode`): the CID font Unicode chain.
- `resources/glyphlist/additional.txt`: 7 TeX glyph names not in pdf.js (`bracketleftmath`, `bracketrightmath`, `epsilon1`, `equalmath`, `parenleftmath`, `parenrightmath`, `plusmath`), data copied into `src/pdf/tables/glyph_data.rs`.
- `resources/afm/`: the Adobe Core 14 AFM files, source of the standard-14 widths (see section 2).

### pdfminer.six, MIT

Source: <https://github.com/pdfminer/pdfminer.six>.

- `pdfminer/pdfdocument.py` `_get_objects`: sequential tokenisation of an object stream from `/First` when member offsets are wrong.
- `pdfminer/cmapdb.py` (`CMapParser`): ignoring the count before `begin*` operators and reading until the matching `end*`.
- `pdfminer/layout.py`: a char margin of two glyph widths as the point where a forward jump starts a new line.
- `name2unicode`: accepting lowercase hexadecimal in `uniXXXX` names and rejecting a ligature name with an unknown component (behaviour only).
- User-then-owner password order in decryption (idea only).

### pypdf, BSD-3-Clause

Source: <https://github.com/py-pdf/pypdf>, commit 54d3518.

- `pypdf/_reader.py` `_get_object_from_stream` and `_sanitize_pdf15_xref_stream_index_pairs`: clamping `/N` by `decoded_len / 3` and xref-stream entry counts by the decoded length.
- `pypdf/_font.py`: a cap of 100,000 `/W` entries; `pypdf/_cmap.py`: a cap on one CMap destination string, decoding legacy CJK CMaps with a codec for the whole code.
- `pypdf/_encryption.py`: `/P` as an unsigned 32-bit value, key length from the crypt filter `/Length` in bytes, trying the owner password with the empty string (ideas only).
- Gzip-wrapped and header-less Flate fallbacks (raw deflate at offset 0, then offset 2).

### hayro, MIT or Apache-2.0

Source: <https://github.com/LaurenzV/hayro>.

- `hayro-syntax/src/xref.rs`, `src/data.rs`, `src/object/*`: offsets-only cross-reference storage, lazy borrowed object views, negative caching of object streams that failed to decode, and the list of known gaps (zero-width `/W`, page-tree DAG fan-out, unbounded nesting, per-stream `endstream` rescans) that shaped our defences.
- In-place PNG predictor decoding so `/Columns` never drives an allocation.
- `hayro-cmap`: the `usecmap` depth limit of 16 and accepting `bfchar` entries as CIDs in encoding CMaps.

### lopdf, MIT

- `src/reader.rs`: correcting a `startxref` or `/Prev` pointer that is off by a few bytes by searching a 64-byte window each side for `xref` or an object header.
- Gzip-wrapped and header-less Flate fallbacks (shared with pypdf, above).

### pdf_oxide, MIT or Apache-2.0

- `src/document.rs` and `src/xref.rs`: probing header-relative and absolute offsets when the header is not at byte 0, and searching the whole file backwards for `startxref`.
- Font Unicode chain: ToUnicode entries mapping to U+FFFD, noncharacters or controls treated as misses; Identity fonts invert the embedded TrueType cmap through CIDToGIDMap before the Adobe collection tables.

### Runtime dependencies used by the PDF code

Linked as ordinary Cargo dependencies, listed here for completeness: flate2 (MIT or Apache-2.0) with the zlib-rs backend (Zlib), memchr (Unlicense or MIT), aws-lc-rs (Apache-2.0 or ISC) for AES and SHA-2, and md5 (Apache-2.0 or MIT). RC4 is implemented in the crate.

### Consulted for ideas only (no code or data copied)

- MuPDF (Artifex), AGPL-3.0: repair policy (run once, last occurrence wins, absolute offsets, object number cap of 8,388,607, `startxref 0` treated as missing, zero-width xref-stream field defaults); PNG predictor edge cases; the n-byte versus 16-byte MD5 variant of Algorithm 7 and forcing AESV3 for revisions 5 and 6; text heuristics from `pdf-op-run.c`, `stext-device.c`, `pdf-type3.c` and `pdf-cmap.c` (control-character ToUnicode targets, writing-direction line breaks, no synthetic spaces after CJK, overprint suppression, Type3 ASCII fallback, invalid-code codespace length).
- poppler, GPL-2.0-or-later (some files GPL-3.0): a sorted `endstream` index for recovering wrong `/Length` values; the 1,000,000-member object-stream limit; the frozen 4096-entry LZW table; numeric glyph name detection (`testForNumericNames`) and CIDSystemInfo ordering `UCS`; merging spacing accents into combining marks and estimating a Type3 font's em (`TextOutputDev.cc`).

The 13 spacing-accent to combining-mark pairs in `tables::combining_accent` are Unicode facts (mostly the compatibility decompositions of the spacing accents), checked against poppler and PDFBox behaviour.

### Specifications followed

- ISO 32000-1:2008 and ISO 32000-2:2020 (PDF 1.7 and 2.0): syntax, filters, section 7.6 security handler algorithms, text state and glyph displacement (9.4.4), Type 0 code splitting (9.7.6.2), ToUnicode (9.10.3), marked content and ActualText (14.9.4), forms (12.7), annotations (12.5), text strings (7.9.2.2), Annex D encodings.
- Adobe Supplement to ISO 32000, BaseVersion 1.7, ExtensionLevel 3 (revision 5 encryption).
- Adobe Technical Notes #5014 and #5099 (CMaps), #5176 (CFF), #5040 (PFB), Adobe Type 1 Font Format, PostScript Language Reference 3rd edition (radix numbers).
- OpenType specification 1.9 (`cmap`, `post`, `maxp`, font collections).
- Unicode Standard Annex #9 (simplified per-line bidi reordering).

## 2. Data

All tables in `src/pdf/tables/` were generated from the sources below; the generator is not part of the repository.

### Adobe Glyph List and ITC Zapf Dingbats Glyph List

- Source: <https://github.com/adobe-type-tools/agl-aglfn> (`glyphlist.txt`, Adobe Glyph List 2.0, and `zapfdingbats.txt`, ITC Zapf Dingbats Glyph List 2.0, both dated September 20, 2002).
- Used for: glyph name to Unicode mapping (all 4281 AGL entries and all 201 Zapf Dingbats entries) in `src/pdf/tables/glyph_data.rs`. The name algorithm follows the Adobe Glyph List Specification (<https://github.com/adobe-type-tools/agl-specification>).
- License: BSD-3-Clause:

```
```
Copyright 2002-2019 Adobe (http://www.adobe.com/).

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

Neither the name of Adobe nor the names of its contributors may be
used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
```

### Adobe CMap and CID resources

- Sources: <https://github.com/adobe-type-tools/mapping-resources-pdf> (`pdf2unicode/Adobe-Japan1-UCS2` (Supplement 7), `Adobe-GB1-UCS2`, `Adobe-CNS1-UCS2`, `Adobe-Korea1-UCS2`; commit 2dd5e53fb74a01718b9dfd448a0d1cce6fff2aa5) and <https://github.com/adobe-type-tools/cmap-resources> (the predefined CMaps of ISO 32000 Table 118 plus the UTF-8 and UTF-32 Unicode CMaps; commit f5cf3bca7fdfeaceb77aa82847e974f2306c20b4).
- Used for: `src/pdf/tables/cid_japan1.bin`, `cid_gb1.bin`, `cid_cns1.bin`, `cid_korea1.bin` (CID to Unicode for the four Adobe character collections, loaded by `cid_data.rs`), and the predefined CMap table in `cmap_data.rs`.
- Modifications: CID tables re-encoded (delta-coded values, raw deflate); U+FFFD entries dropped; variation selectors U+FE00 to U+FE0F removed from mapped sequences.
- License: BSD-3-Clause. Both repositories carry the same text; the copyright lines are "Copyright 1990-2023 Adobe. All rights reserved." (cmap-resources) and "Copyright 1990-2019 Adobe. All rights reserved." (mapping-resources-pdf):

```
```
Copyright 1990-2023 Adobe. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

Neither the name of Adobe nor the names of its contributors may be
used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
```

### Adobe Core 14 AFM metrics

- Source: the Adobe Core 14 AFM files as redistributed by Apache PDFBox (`pdfbox/src/main/resources/org/apache/pdfbox/resources/afm/`, commit 2245d1c2bb3bbcfe56136a693c395317316ace96). The same metrics appear in pdf.js `src/core/metrics.js`.
- Used for: the advance widths (`WX`) of the 14 standard fonts in `src/pdf/tables/font_data.rs`. Only the widths are kept; the AFM files are not distributed.
- Modification notice: the widths were extracted from the AFM files and re-encoded as Rust tables (a shared width palette plus per-font indices); Oblique variants share the upright widths, which are identical in the AFM files.
- License notice (from `MustRead.html` accompanying the AFM files, unmodified):

```
```
This file and the 14 PostScript(R) AFM files it accompanies may be used,
copied, and distributed for any purpose and without charge, with or without
modification, provided that all copyright notices are retained; that the AFM
files are not distributed without this file; that all modifications to this
file or any of the AFM files are prominently noted in the modified file(s);
and that this paragraph is not modified. Adobe Systems has no responsibility
or obligation to support the use of the AFM files.
```
```

- Copyright notices of the individual AFM files:
  - Courier, Courier-Oblique: Copyright (c) 1989, 1990, 1991, 1992, 1993, 1997 Adobe Systems Incorporated. All Rights Reserved.
  - Courier-Bold, Courier-BoldOblique: Copyright (c) 1989, 1990, 1991, 1993, 1997 Adobe Systems Incorporated. All Rights Reserved.
  - Helvetica, Helvetica-Bold, Helvetica-Oblique, Helvetica-BoldOblique: Copyright (c) 1985, 1987, 1989, 1990, 1997 Adobe Systems Incorporated. All Rights Reserved. Helvetica is a trademark of Linotype-Hell AG and/or its subsidiaries.
  - Times-Roman, Times-Bold, Times-Italic, Times-BoldItalic: Copyright (c) 1985, 1987, 1989, 1990, 1993, 1997 Adobe Systems Incorporated. All Rights Reserved. Times is a trademark of Linotype-Hell AG and/or its subsidiaries.
  - Symbol: Copyright (c) 1985, 1987, 1989, 1990, 1997 Adobe Systems Incorporated. All rights reserved.
  - ZapfDingbats: Copyright (c) 1985, 1987, 1988, 1989, 1997 Adobe Systems Incorporated. All Rights Reserved. ITC Zapf Dingbats is a registered trademark of International Typeface Corporation.

### Unicode Character Database

- Source: Unicode 18.0.0 `UnicodeData.txt` and `DerivedNormalizationProps.txt` (<https://www.unicode.org/Public/UCD/>).
- Used for: NFKC mappings of the presentation forms U+FB00 to U+FB4F, U+FB50 to U+FDFF and U+FE70 to U+FEFF (`src/pdf/tables/presentation_data.rs`).
- License: Unicode License v3:

```
```
UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE

Copyright © 1991-2026 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY
DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.

Permission is hereby granted, free of charge, to any person obtaining a
copy of data files and any associated documentation (the "Data Files") or
software and any associated documentation (the "Software") to deal in the
Data Files or Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, and/or sell
copies of the Data Files or Software, and to permit persons to whom the
Data Files or Software are furnished to do so, provided that either (a)
this copyright and permission notice appear with all copies of the Data
Files or Software, or (b) this copyright and permission notice appear in
associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
THIRD PARTY RIGHTS.

IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
FILES OR SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall
not be used in advertising or otherwise to promote the sale, use or other
dealings in these Data Files or Software without prior written
authorization of the copyright holder.
```
```

### PDF specification tables

ISO 32000-1:2008 and ISO 32000-2:2020, Annex D (character sets and encodings) and section 9.6.2.2 (standard Type 1 fonts) were used to check the encoding tables and PDFDocEncoding (WinAnsi bullet for unused codes, 0xA0 as space, 0xAD as hyphen, MacRoman 0xDB as `currency`, the extra MacRoman space at 0xCA). The password padding constant in `src/pdf/crypt/` and the CFF standard strings (Appendix A of Technical Note #5176) and the 258 Macintosh glyph names (OpenType `post`) are specification data.

## 3. Test fixtures

Paths are relative to `crates/text-extract/`. Fixtures are used only by tests and are not compiled into the library.

### Generated for this project

These contain no third-party material beyond what the Notes column states and are covered by the project's own license.

| Path | How it was made |
|---|---|
| `tests/fixtures/pdf/crypt/r2_rc4_40.pdf` | Generated by `.ignore/pdf/dev/crypt/vectors/generate.py` with qpdf, pikepdf and pypdf |
| `tests/fixtures/pdf/crypt/r3_empty_owner.pdf` | Same generator (pypdf, empty owner password) |
| `tests/fixtures/pdf/crypt/r3_rc4_128.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r3_user_pw.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r4_aes_128.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r4_aes_128_nometa.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r4_rc4_128.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r5_aes_256.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r6_aes_256.pdf` | Same generator |
| `tests/fixtures/pdf/crypt/r6_empty_owner.pdf` | Same generator (pypdf, empty owner password) |
| `tests/fixtures/pdf/crypt/r6_user_pw.pdf` | Same generator |
| `tests/fixtures/pdf/text/gen/acroform-filled.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/acroform-values-without-appearances.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/actualtext-spans.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/annotations-comments.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/arabic-cairo.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/broken-xref-and-trailer-missing.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/broken-xref-wrong-offsets.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/chromium-skia-two-column.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/cjk-chinese-cairo.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/cjk-cid-predefined-cmap.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/cjk-japanese-weasyprint.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/cjk-korean-cairo.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/cjk-vertical-writing.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/differences-encoding-no-tounicode.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/encrypted-aes-128.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/encrypted-rc4-40.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/filters-lzw-ascii85-hex-rle.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/form-xobject-and-inline-image.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/hebrew-cairo.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/identity-h-cairo-ligatures.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/incremental-update-prev-chain.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/invoice-weasyprint.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/libreoffice-writer-letter.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/linearized.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/rotated-pages.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/scanned-ocr-invisible-text.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/spacing-kerning-geometry.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/truetype-subset-multiscript.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/type1-winansi-std14.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/type3-matplotlib-chart.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/pdf/text/gen/xref-stream-object-streams.pdf` | Generated by `.ignore/pdf/oracle/gen_fixtures.py` |
| `tests/fixtures/real/textutil.docx` | Written by the macOS Cocoa text system (`textutil`), as its metadata shows; local generation, generator command not recorded |
| `tests/fixtures/real/textutil.odt` | Same (metadata generator `CocoaODFWriter/2685.7`) |
| `tests/fixtures/real/textutil.rtf` | Same (`\cocoartf2870` header) |
| `tests/fixtures/hostile/docx_billion_laughs.docx` | Minimal synthetic archive (entity expansion); hand-built for `tests/hostile.rs`, generator not recorded |
| `tests/fixtures/hostile/docx_deep_nesting.docx` | Minimal synthetic archive (deeply nested XML); generator not recorded |
| `tests/fixtures/hostile/docx_lzma_member.docx` | Minimal synthetic archive (LZMA-compressed member); generator not recorded |
| `tests/fixtures/hostile/ods_repeated_rows.ods` | Minimal synthetic archive (huge `number-rows-repeated`); generator not recorded |
| `tests/fixtures/hostile/xlsx_sparse_corners.xlsx` | Minimal synthetic archive (cells at opposite sheet corners); generator not recorded |
| `tests/fixtures/hostile/xlsx_sst_uniquecount.xlsx` | Minimal synthetic archive (inflated shared-string count); generator not recorded |

Font program test data in `src/pdf/font/program/tests/data/`, generated by the font parser's `gen/gen_fixtures.py` (not in the repository) with fontTools (MIT, used only as a tool) from the fonts named below:

| Path | Source font | Font license |
|---|---|---|
| `src/pdf/font/program/tests/data/cmr10-type1.t1` | Cleartext portion (first 2587 bytes plus 32 bytes of the encrypted part) of the CMR10 subset embedded in a TUGboat article PDF; AMS Computer Modern Type 1 fonts, Copyright (c) 1997, 2009 American Mathematical Society | SIL Open Font License 1.1 |
| `src/pdf/font/program/tests/data/cmr10-type1c.cff` | CMR10 Type1C subset embedded in the CTAN `lshort` (English) PDF; same font | SIL Open Font License 1.1 |
| `src/pdf/font/program/tests/data/dejavu-latin.ttf` | Subset of DejaVu Sans 2.37, cmap rebuilt (formats 6, 4, 12) | Bitstream Vera license, DejaVu changes public domain |
| `src/pdf/font/program/tests/data/dejavu-symbol.ttf` | Subset of DejaVu Sans 2.37, cmap rebuilt (format 0, (3,0) format 4, (3,4) format 2) | Same |
| `src/pdf/font/program/tests/data/dejavu-pair.ttc` | Collection of two DejaVu Sans 2.37 subsets | Same |
| `src/pdf/font/program/tests/data/noto-cjk-cid.otf` | Noto Sans CJK JP 2.004 (`NotoSansCJK-Regular.ttc`, font 0), subset to eight characters | SIL Open Font License 1.1 |
| `src/pdf/font/program/tests/data/noto-cjk-cid.cff` | The `CFF ` table of `noto-cjk-cid.otf` | SIL Open Font License 1.1 |
| `src/pdf/font/program/tests/data/cmr10-type1.t1.expect` | fontTools' view of the fixture (from the complete font program), written by `gen/oracle.py` | Project license (generated) |
| `src/pdf/font/program/tests/data/cmr10-type1c.cff.expect` | Expectation written by `gen/oracle.py` | Project license (generated) |
| `src/pdf/font/program/tests/data/dejavu-latin.ttf.expect` | Expectation written by `gen/oracle.py` | Project license (generated) |
| `src/pdf/font/program/tests/data/dejavu-symbol.ttf.expect` | Expectation written by `gen/oracle.py` | Project license (generated) |
| `src/pdf/font/program/tests/data/dejavu-pair.ttc.expect` | Expectation written by `gen/oracle.py` | Project license (generated) |
| `src/pdf/font/program/tests/data/noto-cjk-cid.otf.expect` | Expectation written by `gen/oracle.py` | Project license (generated) |
| `src/pdf/font/program/tests/data/noto-cjk-cid.cff.expect` | Expectation written by `gen/oracle.py` | Project license (generated) |

The filter test vectors in `src/pdf/filter/testdata/` come from the project-owned `scripts/gen_vectors.py` (Python standard library `zlib`, ASCII85 strings from CPython `base64.a85encode`) and were cross-checked with qpdf (through pikepdf) and pypdf. Synthetic PDFs in `tests/common/pdf.rs` are built by the tests at run time.

### Taken from other projects

All files below are unmodified copies. Copyright The Apache Software Foundation; license Apache-2.0 (<https://www.apache.org/licenses/LICENSE-2.0>). The NOTICE text for each project is in section 4.

| Path | Source | License |
|---|---|---|
| `tests/fixtures/pdf/text/tika/testAnnotations.pdf` | Apache Tika, <https://github.com/apache/tika>, `tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/tika-parser-pdf-module/src/test/resources/test-documents/` | Apache-2.0 |
| `tests/fixtures/pdf/text/tika/testExtraSpaces.pdf` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/pdf/text/tika/testOptionalHyphen.pdf` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/pdf/text/tika/testPDF_acroform3.pdf` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/pdf/text/pdfbox/GlyphLayoutBidi.pdf` | Apache PDFBox, <https://github.com/apache/pdfbox/blob/2245d1c2bb3bbcfe56136a693c395317316ace96/pdfbox-layout-awt/src/test/resources/pdf/GlyphLayoutBidi.pdf>; embeds Noto Sans Arabic and DejaVu Sans subsets | Apache-2.0 (embedded fonts: OFL 1.1, Bitstream Vera license) |
| `tests/fixtures/pdf/text/pdfbox/GlyphLayoutLigaturesAndKerning_ActualText.pdf` | Apache PDFBox, same commit, `pdfbox-layout-awt/src/test/resources/pdf/`; embeds Fira Code, DejaVu Sans and Noto subsets | Apache-2.0 (embedded fonts: OFL 1.1, Bitstream Vera license) |
| `tests/fixtures/pdf/text/pdfbox/sampleForSpec.pdf` | Apache PDFBox, same commit, `pdfbox/src/test/resources/input/sampleForSpec.pdf` | Apache-2.0 |
| `tests/fixtures/real/testEXCEL_textbox.xlsx` | Apache Tika, `tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/tika-parser-microsoft-module/src/test/resources/test-documents/` | Apache-2.0 |
| `tests/fixtures/real/testEXCEL_headers_footers.xlsx` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/real/testPPT_charts.pptx` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/real/testPPT_masterText.pptx` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/real/testRTFIgnoredControlWord.rtf` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/real/testRTFTIKA_1713.rtf` | Apache Tika, same directory | Apache-2.0 |
| `tests/fixtures/real/48539.xlsx` | Apache POI, <https://github.com/apache/poi>, `test-data/spreadsheet/` | Apache-2.0 |
| `tests/fixtures/real/testEXCEL.xlsx` | Apache Tika test documents (parser module test resources) | Apache-2.0 |
| `tests/fixtures/real/testPPT.pptx` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testPPT_various.pptx` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testWORD.docx` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testWORD_various.docx` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testODFwithOOo3.odt` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testOpenOffice2.odt` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testRTF.rtf` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testRTFVarious.rtf` | Apache Tika test documents | Apache-2.0 |
| `tests/fixtures/real/testEPUB.epub` | Apache Tika test documents | Apache-2.0 |

## 4. NOTICE

The Apache-2.0 test files listed above are redistributed with the source tree. Section 4(d) of the Apache License requires the NOTICE text of each originating project to accompany them. The texts below were taken from the projects' repositories (`apache/tika` `NOTICE.txt`, `apache/pdfbox` `NOTICE.txt`, `apache/poi` `legal/NOTICE`) on 2026-09-27.

### Apache Tika

```
Apache Tika
Copyright 2007-2026 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (http://www.apache.org/).

Copyright 1993-2010 University Corporation for Atmospheric Research/Unidata
This software contains code derived from UCAR/Unidata's NetCDF library.

Tika-parsers component uses CDDL/LGPL dual-licensed dependency: jhighlight (https://github.com/codelibs/jhighlight)

IPTC Photo Metadata descriptions Copyright 2010 International Press Telecommunications Council.

Tika-mimetypes.xml includes mimetype definitions that were adapted from the PRONOM Technical Registry
by The National Archives (http://www.nationalarchives.gov.uk/PRONOM/Default.aspx). PRONOM is published
under the Open Government License 3.0 (http://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/)
```

### Apache PDFBox

```
Apache PDFBox
Copyright 2014 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (http://www.apache.org/).

Based on source code originally developed in the PDFBox and 
FontBox projects.

Copyright (c) 2002-2007, www.pdfbox.org

Based on source code originally developed in the PaDaF project.
Copyright (c) 2010 Atos Worldline SAS

Includes the Adobe Glyph List
Copyright 1997, 1998, 2002, 2007, 2010 Adobe Systems Incorporated.

Includes the Zapf Dingbats Glyph List
Copyright 2002, 2010 Adobe Systems Incorporated.

Includes OSXAdapter
Copyright (C) 2003-2007 Apple, Inc., All Rights Reserved
```

### Apache POI

```
Apache POI
Copyright 2003-2026 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (https://www.apache.org/).

This product contains parts that were originally based on software from BEA.
Copyright (c) 2000-2003, BEA Systems, <http://www.bea.com/> (dead link),
which was acquired by Oracle Corporation in 2008.
<http://www.oracle.com/us/corporate/Acquisitions/bea/index.html>
<https://en.wikipedia.org/wiki/BEA_Systems>
Note: The ASF Secretary has on hand a Software Grant Agreement (SGA) from
BEA Systems, Inc. dated 9 Sep 2003 for XMLBeans signed by their EVP/CFO.

This product contains W3C XML Schema documents. Copyright 2001-2003 (c)
World Wide Web Consortium (Massachusetts Institute of Technology, European
Research Consortium for Informatics and Mathematics, Keio University)

This product contains the chunks_parse_cmds.tbl file from the vsdump program.
Copyright (C) 2006-2007 Valek Filippov (frob@df.ru)

This product contains parts of the eID Applet project
<http://eid-applet.googlecode.com> and <https://github.com/e-Contract/eid-applet>.
Copyright (c) 2009-2018
FedICT (federal ICT department of Belgium), e-Contract.be BVBA (https://www.e-contract.be),
Bart Hanssens from FedICT

ExceptionUtils is derived from `scala.util.control.NonFatal` in scala-library
which was released under the Apache 2.0 license.

Copyright (c) 2002-2023 EPFL
Copyright (c) 2011-2023 Lightbend, Inc.

Scala includes software developed at
LAMP/EPFL (https://lamp.epfl.ch/) and
Lightbend, Inc. (https://www.lightbend.com/).
```

### pdf.js

pdf.js has no NOTICE file. Its attribution, for the code and data adapted in sections 1 and 2:

```
pdf.js
Copyright Mozilla Foundation
Licensed under the Apache License, Version 2.0
https://github.com/mozilla/pdf.js
```

The full Apache License 2.0 text is at <https://www.apache.org/licenses/LICENSE-2.0>.
