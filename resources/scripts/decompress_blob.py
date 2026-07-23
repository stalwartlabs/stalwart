#!/usr/bin/env python3
"""Decode a raw Stalwart blob object into its original bytes.

Stalwart appends a one-byte compression marker to every blob it writes to the
blob store (see BlobStore::put_blob in crates/store/src/dispatch/blob.rs):

  0x00  (NONE_MARKER)  the preceding bytes are the verbatim payload
  0xa1  (LZ4_MARKER)   the preceding bytes are an lz4_flex block prefixed with a
                       little-endian u32 holding the uncompressed size
  other                a legacy blob stored without a marker; emitted unchanged

This mirrors the read path, which inspects the last byte, strips the marker and,
for LZ4, decompresses the size-prepended block.

Reads the object from a file (or stdin with "-") and writes the decoded payload
to stdout (or to a file with -o).
"""

import argparse
import sys

NONE_MARKER = 0x00
LZ4_MARKER = 0xA1


def decode(data):
    if not data:
        return data
    marker = data[-1]
    if marker == LZ4_MARKER:
        import lz4.block
        return lz4.block.decompress(data[:-1])
    if marker == NONE_MARKER:
        return data[:-1]
    print(f"warning: no known compression marker (last byte 0x{marker:02x}); "
          "emitting bytes unchanged", file=sys.stderr)
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help='raw blob file, or "-" to read from stdin')
    ap.add_argument("-o", "--output",
                    help="write the decoded payload here (default: stdout)")
    args = ap.parse_args()

    if args.input == "-":
        data = sys.stdin.buffer.read()
    else:
        with open(args.input, "rb") as fh:
            data = fh.read()

    out = decode(data)

    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(out)
    else:
        sys.stdout.buffer.write(out)


if __name__ == "__main__":
    main()
