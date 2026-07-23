#!/usr/bin/env python3
"""List the S3 object keys of every blob that is still actively linked.

Stalwart reference-counts blobs through link entries kept in the data store
under the SUBSPACE_BLOB_LINK subspace (the PostgreSQL table named "k"). A blob
is garbage-collectable once it has no surviving link; this tool reports the
opposite set: the S3 keys of blobs that are still referenced, so they can be
diffed against the actual contents of an S3 bucket to find orphans.

Key layout in table "k" (the subspace byte is NOT stored, it only selects the
table). All integers are big-endian:

  32 bytes  Commit  : <hash:32>                              (blob exists marker)
  40 bytes  Id link : <hash:32><id:8>
  41 bytes  Doc link: <hash:32><account_id:4><collection:1><document_id:4>
  44 bytes  Tmp link: <hash:32><account_id:4><until:8>        (active iff until > now)

A blob is active when it has at least one Id/Doc link, or a Temporary link whose
"until" (unix seconds) is still in the future. The 32-byte Commit marker alone
does not keep a blob alive.

The S3 object key is the optional configured key prefix (literal string)
followed by the custom-base32 encoding of the 32-byte blob hash, matching
S3Store::build_key in crates/store/src/backend/s3/mod.rs.
"""

import argparse
import os
import sys
import time

BLOB_HASH_LEN = 32
ID_LINK = BLOB_HASH_LEN + 8          # 40
DOC_LINK = BLOB_HASH_LEN + 8 + 1     # 41
TEMP_LINK = BLOB_HASH_LEN + 4 + 8    # 44

BASE32_ALPHABET = b"abcdefghijklmnopqrstuvwxyz792013"


class Base32Writer:
    """Faithful port of utils::codec::base32_custom::Base32Writer."""

    def __init__(self, prefix=""):
        self.last_byte = 0
        self.pos = 0
        self.out = [prefix] if prefix else []

    def _push_byte(self, byte, is_remainder):
        p = self.pos % 5
        if p == 0:
            ch1 = (byte & 0xF8) >> 3
            ch2 = 0xFF
        elif p == 1:
            ch1 = ((self.last_byte & 0x07) << 2) | ((byte & 0xC0) >> 6)
            ch2 = (byte & 0x3E) >> 1
        elif p == 2:
            ch1 = ((self.last_byte & 0x01) << 4) | ((byte & 0xF0) >> 4)
            ch2 = 0xFF
        elif p == 3:
            ch1 = ((self.last_byte & 0x0F) << 1) | (byte >> 7)
            ch2 = (byte & 0x7C) >> 2
        else:
            ch1 = ((self.last_byte & 0x03) << 3) | ((byte & 0xE0) >> 5)
            ch2 = byte & 0x1F

        self.out.append(chr(BASE32_ALPHABET[ch1]))
        if not is_remainder:
            if ch2 != 0xFF:
                self.out.append(chr(BASE32_ALPHABET[ch2]))
            self.last_byte = byte
            self.pos += 1

    def write(self, data):
        for byte in data:
            self._push_byte(byte, False)
        return self

    def finalize(self):
        if self.pos % 5 != 0:
            self._push_byte(0, True)
        return "".join(self.out)


def s3_key(blob_hash, prefix=""):
    return Base32Writer(prefix).write(blob_hash).finalize()


def be_u64(b):
    return int.from_bytes(b, "big")


def collect_active_hashes(rows, now, include_expired_temporary=False):
    active = set()
    unknown = 0
    for (key,) in rows:
        key = bytes(key)
        n = len(key)
        if n == BLOB_HASH_LEN:
            continue
        if n in (ID_LINK, DOC_LINK):
            active.add(key[:BLOB_HASH_LEN])
        elif n == TEMP_LINK:
            until = be_u64(key[BLOB_HASH_LEN + 4:BLOB_HASH_LEN + 12])
            if include_expired_temporary or until > now:
                active.add(key[:BLOB_HASH_LEN])
        else:
            unknown += 1
    if unknown:
        print(f"warning: skipped {unknown} key(s) of unexpected length",
              file=sys.stderr)
    return active


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("PGHOST", "localhost"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PGPORT", "5432")))
    ap.add_argument("--user", default=os.environ.get("PGUSER", "stalwart"))
    ap.add_argument("--password", default=os.environ.get("PGPASSWORD", "stalwart"))
    ap.add_argument("--dbname", default=os.environ.get("PGDATABASE", "stalwart"))
    ap.add_argument("--table", default="k",
                    help="SUBSPACE_BLOB_LINK table name (default: k)")
    ap.add_argument("--prefix", default="",
                    help="S3 key_prefix configured on the blob store (default: none)")
    ap.add_argument("--now", type=int, default=None,
                    help="override unix-seconds used to expire temporary links")
    ap.add_argument("--include-expired-temporary", action="store_true",
                    help="treat expired temporary links as active too")
    args = ap.parse_args()

    try:
        import psycopg2
        conn = psycopg2.connect(host=args.host, port=args.port, user=args.user,
                                password=args.password, dbname=args.dbname)
    except ImportError:
        import psycopg
        conn = psycopg.connect(host=args.host, port=args.port, user=args.user,
                               password=args.password, dbname=args.dbname)

    now = args.now if args.now is not None else int(time.time())

    with conn, conn.cursor() as cur:
        cur.execute(f'SELECT k FROM "{args.table}"')
        rows = cur.fetchall()
    conn.close()

    active = collect_active_hashes(rows, now,
                                   include_expired_temporary=args.include_expired_temporary)

    for h in sorted(active):
        print(s3_key(h, args.prefix))


if __name__ == "__main__":
    main()
