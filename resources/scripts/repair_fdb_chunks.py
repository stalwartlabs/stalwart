#!/usr/bin/env python3
"""
Repair orphaned value chunks in a Stalwart FoundationDB data store.

Values larger than 100000 bytes are split across a base key and one key per
extra chunk, suffixed with a single byte: `key`, `key || 0x00`, `key || 0x01`,
and so on. Releases up to and including v0.16.18 overwrote such a value without
removing the chunk keys the previous, longer value had used. The leftovers are
spliced onto later reads, which surfaces as:

    ERROR Data corruption detected (store.data-corruption)
          details = 'Archive integrity compromised'

This script finds those leftovers and deletes them. It is read-only unless
--commit is given.

Only subspaces whose keys are prefix-free are scanned, so that a key one byte
longer than its predecessor is unambiguously a chunk and never a distinct
record. This is a stricter condition than `is_chunked_subspace` in
crates/store/src/backend/foundationdb/mod.rs, which answers "can chunking
happen here" rather than "are keys here prefix-free". See CHUNKED_SUBSPACES
below for what is excluded and why. Keys are additionally checked against the
shapes a real record can have in their subspace, so a legal record is never
mistaken for a chunk.

Two cases are handled:

  * The base value is under 100000 bytes, so the record is no longer chunked
    and every chunk key that follows it is stale. Unambiguous.

  * The base value is exactly 100000 bytes, so the record is still chunked and
    the live chunk count has to be worked out. Two independent methods must
    agree before anything is deleted: chunk sizes, since every chunk of a live
    value except the last is exactly 100000 bytes, and the trailing xxh3
    checksum that Stalwart archives carry. Records where they disagree, or
    where neither applies, are left untouched and reported.

Each repair re-reads the record and deletes inside a single transaction, so a
record rewritten between the scan and the delete is judged on what is actually
stored rather than on what the scan saw.

Requirements:
    pip install foundationdb xxhash

The `foundationdb` package version must match the cluster's API version.

Usage:
    python repair_fdb_chunks.py --cluster-file /etc/foundationdb/fdb.cluster
    python repair_fdb_chunks.py --cluster-file /etc/foundationdb/fdb.cluster --commit

Stop Stalwart before running with --commit.
"""

# SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
#
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL

import argparse
import sys

try:
    import fdb
except ImportError:
    sys.exit("Missing dependency: pip install foundationdb")

try:
    import xxhash
except ImportError:
    sys.exit("Missing dependency: pip install xxhash")

MAX_VALUE_SIZE = 100000

MAGIC_MARKER = 1 << 7
VERSIONED = 1 << 6
HASHED = 1 << 5

U32_LEN = 4
U64_LEN = 8

CHUNKED_SUBSPACES = {
    b"p": "property",
    b"e": "queue message",
    b"f": "task queue",
    b"d": "directory",
    b"s": "registry",
    b"j": "deleted items",
    b"w": "spam samples",
    b"r": "inbound reports",
    b"h": "outbound reports",
    b"o": "telemetry spans",
}

BASE_KEY_LENGTHS = {
    b"e": {9},
    b"f": {17},
    b"o": {9, 11},
    b"d": {11},
    b"s": {11},
    b"j": {11},
    b"w": {11},
    b"r": {11},
    b"h": {11},
}

# EmailField::Threading, the only property indexed by hash
THREADING_FIELD = 90


def is_record_key(subspace, key):
    lengths = BASE_KEY_LENGTHS.get(subspace)
    if lengths is not None:
        return len(key) in lengths
    if subspace == b"p":
        # Property (11), IndexProperty::Integer (19), the 2-byte schema version written as
        # ValueClass::Any, and IndexProperty::Hash whose CheekyHash is 1 to 16 bytes
        if len(key) in (2, 11, 19):
            return True
        return 12 <= len(key) <= 27 and key[6] == THREADING_FIELD
    return False

READ_BATCH = 32


def is_valid_archive(value):
    """Mirror of validate_marker_and_contents in crates/store/src/write/serialize.rs."""
    if not value:
        return False

    marker = value[-1]
    if marker & MAGIC_MARKER == 0:
        return False

    contents = value[:-1]

    if marker & VERSIONED != 0:
        if len(contents) < U64_LEN + U32_LEN:
            return False
        contents = contents[:-U64_LEN]
    elif marker & HASHED != 0:
        if len(contents) < U32_LEN:
            return False
    else:
        # Unversioned archives carry no checksum, so length cannot be verified
        return False

    contents, archive_hash = contents[:-U32_LEN], contents[-U32_LEN:]
    hash32 = xxhash.xxh3_64_intdigest(contents) & 0xFFFFFFFF
    return hash32.to_bytes(U32_LEN, "big") == archive_hash


def count_by_chunk_size(chunk_values):
    """Live chunk count implied by chunk sizes, or None if it cannot be read off them.

    `chunk_value` splits with value.chunks(MAX_VALUE_SIZE), so every chunk of the live value
    except its last is exactly MAX_VALUE_SIZE bytes. The first short chunk therefore ends the
    live value. This never undercounts: if the live value happens to be an exact multiple of
    MAX_VALUE_SIZE the first short chunk belongs to the stale tail, which yields a count that
    is too high and so only leaves orphans behind. It works for every value format.
    """
    for index, chunk in enumerate(chunk_values):
        if len(chunk) < MAX_VALUE_SIZE:
            return index + 1
    return None


def count_by_archive(base_value, chunk_values):
    """Live chunk count implied by the archive checksum, or None if undecidable.

    Refuses when more than one prefix validates rather than taking the shortest, so a value
    that embeds a complete inner archive cannot cause the live tail to be truncated.
    """
    matches = []
    if is_valid_archive(base_value):
        matches.append(0)

    accumulated = bytearray(base_value)
    for count, chunk in enumerate(chunk_values, start=1):
        accumulated.extend(chunk)
        if is_valid_archive(bytes(accumulated)):
            matches.append(count)

    return matches[0] if len(matches) == 1 else None


def live_chunk_count(base_value, chunk_values):
    """Number of chunk keys that belong to the current value, or None if undecidable.

    Both independent methods must agree. The size rule never undercounts and the checksum
    rule is format specific, so requiring agreement means a disagreement leaves the record
    untouched instead of guessing at an operator's data.
    """
    if len(base_value) < MAX_VALUE_SIZE:
        return 0

    by_size = count_by_chunk_size(chunk_values)
    by_archive = count_by_archive(base_value, chunk_values)

    if by_size is not None and by_archive is not None:
        return by_size if by_size == by_archive else None

    # Non-archive formats (pickled tasks and traces, raw thread indexes, untrusted archives)
    # carry no checksum, so the size rule is the only available signal
    return by_size if by_archive is None else None


TRANSACTION_TOO_OLD = 1007
TRANSACTION_TIMED_OUT = 1031


def read_range(db, begin, end, limit):
    """Read one batch starting at `begin`, returning the rows and the batch size that worked.

    A chunked record holds 100000 bytes per key, so a batch can carry several megabytes and
    outlive FoundationDB's five second transaction window. Every attempt starts a fresh
    transaction from `begin`, so a retry resumes exactly where the failed one started, and the
    batch is halved on each timeout until it fits.
    """
    while True:
        tr = db.create_transaction()
        try:
            rows = list(
                tr.get_range(begin, end, limit=limit, streaming_mode=fdb.StreamingMode.want_all)
            )
            return rows, limit
        except fdb.FDBError as err:
            if err.code in (TRANSACTION_TOO_OLD, TRANSACTION_TIMED_OUT) and limit > 1:
                limit = max(1, limit // 2)
                print(f"  transaction exceeded its time budget, retrying with batch of {limit}")
                continue
            tr.on_error(err).wait()


def repair_record(db, subspace, base_key):
    """Re-read one record and delete its orphans in a single transaction.

    The scan reads the store in many separate transactions, so a record's base value and its
    chunks are not a consistent snapshot. Recomputing inside the transaction that performs
    the delete removes that race: if the record was rewritten in the meantime the deletion is
    based on what is actually there, not on what the scan saw.
    """
    while True:
        tr = db.create_transaction()
        try:
            rows = [
                (bytes(kv.key), bytes(kv.value))
                for kv in tr.get_range(
                    base_key,
                    base_key + bytes([0xFF]),
                    streaming_mode=fdb.StreamingMode.want_all,
                )
            ]
            if not rows or rows[0][0] != base_key:
                return 0

            base_value = rows[0][1]
            chunks = [
                (key, value)
                for key, value in rows[1:]
                if len(key) == len(base_key) + 1
                and key.startswith(base_key)
                and not is_record_key(subspace, key)
            ]

            count = live_chunk_count(base_value, [value for _, value in chunks])
            if count is None:
                return 0

            orphans = [key for key, _ in chunks[count:]]
            for key in orphans:
                tr.clear(key)
            tr.commit().wait()
            return len(orphans)
        except fdb.FDBError as err:
            tr.on_error(err).wait()


class Stats:
    def __init__(self):
        self.records = 0
        self.orphans = 0
        self.deleted = 0
        self.undecidable = 0


def scan_subspace(db, subspace, label, commit, verbose, stats):
    begin = subspace
    end = bytes([subspace[0] + 1])

    base_key = None
    base_value = None
    chunk_keys = []
    chunk_values = []
    cursor = begin

    def flush_record():
        if base_key is None:
            return
        stats.records += 1
        if not chunk_keys:
            return

        count = live_chunk_count(base_value, chunk_values)
        if count is None:
            stats.undecidable += 1
            print(
                f"  ! {label}: cannot determine chunk count for {base_key.hex()} "
                f"({len(chunk_keys)} chunk keys, {len(base_value)} byte base), left untouched"
            )
            return

        orphans = chunk_keys[count:]
        if not orphans:
            return

        stats.orphans += len(orphans)
        if verbose:
            print(
                f"  - {label}: {base_key.hex()} has {len(orphans)} orphaned "
                f"chunk(s), keeping {count}"
            )
        if commit:
            stats.deleted += repair_record(db, subspace, base_key)

    batch = READ_BATCH
    while True:
        rows, batch = read_range(db, cursor, end, batch)
        if not rows:
            break

        for kv in rows:
            key = bytes(kv.key)
            value = bytes(kv.value)

            if (
                base_key is not None
                and len(key) == len(base_key) + 1
                and key.startswith(base_key)
                and not is_record_key(subspace, key)
            ):
                chunk_keys.append(key)
                chunk_values.append(value)
                continue

            flush_record()
            base_key = key
            base_value = value
            chunk_keys = []
            chunk_values = []

        cursor = bytes(rows[-1].key) + b"\x00"

    flush_record()


def main():
    parser = argparse.ArgumentParser(
        description="Repair orphaned value chunks in a Stalwart FoundationDB store"
    )
    parser.add_argument("--cluster-file", help="Path to fdb.cluster")
    parser.add_argument(
        "--api-version", type=int, default=740, help="FoundationDB API version (default: 740)"
    )
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Delete the orphaned chunks. Without this the script only reports.",
    )
    parser.add_argument(
        "--subspace",
        action="append",
        help="Limit the scan to this subspace letter. May be repeated.",
    )
    parser.add_argument("--verbose", action="store_true", help="Print every affected record")
    args = parser.parse_args()

    fdb.api_version(args.api_version)
    db = fdb.open(args.cluster_file)

    selected = CHUNKED_SUBSPACES
    if args.subspace:
        wanted = {s.encode() for s in args.subspace}
        unknown = wanted - set(CHUNKED_SUBSPACES)
        if unknown:
            sys.exit(
                "Not a chunked subspace: "
                + ", ".join(sorted(u.decode() for u in unknown))
                + "\nValid: "
                + ", ".join(sorted(s.decode() for s in CHUNKED_SUBSPACES))
            )
        selected = {s: CHUNKED_SUBSPACES[s] for s in wanted}

    if not args.commit:
        print("DRY RUN. No key will be deleted. Pass --commit to apply the repair.\n")
    else:
        print("COMMIT MODE. Orphaned chunks will be deleted. Stalwart must be stopped.\n")

    stats = Stats()
    for subspace, label in sorted(selected.items()):
        print(f"Scanning subspace {subspace.decode()!r} ({label})...")
        scan_subspace(db, subspace, label, args.commit, args.verbose, stats)

    print(f"\nRecords scanned:   {stats.records}")
    print(f"Orphaned chunks:   {stats.orphans}")
    if stats.undecidable:
        print(f"Undecidable:       {stats.undecidable} (reported above, not modified)")
    if args.commit:
        print(f"Chunks deleted:    {stats.deleted}")
    elif stats.orphans:
        print("\nRe-run with --commit to delete them.")


if __name__ == "__main__":
    main()
