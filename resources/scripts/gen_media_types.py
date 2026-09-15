#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
#
# Regenerates crates/types/src/media_type/catalogue.rs from the IANA media type
# registry plus the mime_guess database. Identifiers are append-only: entries
# already present keep their position, new entries are appended in sorted order.
#
# Usage: gen_media_types.py <iana_csv_dir> <mime_types.rs from mime_guess>

import csv
import glob
import os
import re
import sys

MAX_ENTRIES = 4094
TOP_LEVEL = ["application", "audio", "font", "haptics", "image", "message", "model", "multipart", "text", "video"]
RESTRICTED = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}")
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = os.path.join(ROOT, "crates", "types", "src", "media_type", "catalogue.rs")


def iana_types(directory):
    names = set()
    for top in TOP_LEVEL:
        with open(os.path.join(directory, f"{top}.csv"), newline="") as f:
            for row in csv.DictReader(f):
                template = (row.get("Template") or "").strip().lower()
                if not template:
                    template = f"{top}/{row['Name'].split(' ')[0].strip().lower()}"
                names.add(template)
    return names


def mime_guess_types(path):
    with open(path) as f:
        return {m.lower() for m in re.findall(r'"([a-zA-Z0-9.+-]+/[a-zA-Z0-9.+_-]+)"', f.read())}


def existing_types():
    if not os.path.exists(TARGET):
        return []
    with open(TARGET) as f:
        body = f.read()
    start = body.index("pub(super) static MEDIA_TYPES")
    end = body.index("];", start)
    return re.findall(r'"([^"]+)"', body[start:end])


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: gen_media_types.py <iana_csv_dir> <mime_types.rs>")
    candidates = {n for n in iana_types(sys.argv[1]) | mime_guess_types(sys.argv[2]) if RESTRICTED.fullmatch(n)}
    ordered = existing_types()
    known = set(ordered)
    ordered.extend(sorted(candidates - known))
    if len(ordered) > MAX_ENTRIES:
        sys.exit(f"catalogue has {len(ordered)} entries, limit is {MAX_ENTRIES}")
    by_name = sorted(range(len(ordered)), key=lambda i: ordered[i])

    out = [
        "/*",
        " * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>",
        " *",
        " * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL",
        " */",
        "",
        f"pub(super) static MEDIA_TYPES: [&str; {len(ordered)}] = [",
    ]
    out.extend(f'    "{name}",' for name in ordered)
    out.append("];")
    out.append("")
    out.append("#[rustfmt::skip]")
    out.append(f"pub(super) static BY_NAME: [u16; {len(ordered)}] = [")
    for chunk_start in range(0, len(by_name), 16):
        out.append("    " + " ".join(f"{i}," for i in by_name[chunk_start:chunk_start + 16]))
    out.append("];")
    out.append("")
    os.makedirs(os.path.dirname(TARGET), exist_ok=True)
    with open(TARGET, "w") as f:
        f.write("\n".join(out))
    print(f"wrote {len(ordered)} media types to {TARGET}")


if __name__ == "__main__":
    main()
