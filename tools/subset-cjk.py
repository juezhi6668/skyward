#!/usr/bin/env python3
"""Cut MiSans VF down to what a recovery's pages can ask for.

The whole file is 19 MiB and 13.7 MiB gzipped, which is more room than a
recovery image's ramdisk has: the boot loader of the older Xiaomi phones
refuses a gzipped ramdisk much past 30 MiB. What it takes is the characters
the pages can draw, and nothing else:

  * every non-ASCII character in the string literals of the crates, which is
    what the pages themselves say, in all three languages;
  * the whole of GB2312, the common set of simplified Chinese, because the
    file manager, the log pages and the terminal show names that come off
    the phone's storage rather than out of this repository, and a subset
    too small for those turns into boxes;
  * the printable ASCII, which the mono face alone does not cover.

The weight axis is kept whole: the pages set titles, captions and values at
ten different coordinates along it, and pinning the axis would flatten them.
"""

import argparse
import glob
import gzip
import io
import os
import re
import sys

from fontTools import subset
from fontTools.ttLib import TTFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STRINGS = re.compile(r'"(?:[^"\\\n]|\\.)*"')


def page_characters():
    """Every non-ASCII character in the string literals of every crate."""
    out = set()
    for path in glob.glob(os.path.join(ROOT, "crates", "*", "src", "**", "*.rs"), recursive=True):
        text = open(path, encoding="utf-8", errors="replace").read()
        for literal in STRINGS.findall(text):
            out.update(ch for ch in literal if ord(ch) > 0x7F)
    return out


def gb2312():
    """The whole of GB2312: its Chinese, and its full-width punctuation."""
    out = set()
    for high in range(0xA1, 0xFF):
        for low in range(0xA1, 0xFF):
            try:
                out.add(bytes((high, low)).decode("gb2312"))
            except UnicodeDecodeError:
                continue
    return out


def wanted():
    chars = page_characters() | gb2312() | {chr(c) for c in range(0x20, 0x7F)}
    return "".join(sorted(chars))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="src", default=os.path.join(ROOT, "resources/fonts/MiSansVF.ttf"))
    ap.add_argument("--out", dest="dst", default="/tmp/MiSansVF-CN.ttf")
    ap.add_argument("--list", help="also write the character list here")
    args = ap.parse_args()

    text = wanted()
    if args.list:
        open(args.list, "w", encoding="utf-8").write(text)
    options = subset.Options()
    options.layout_features = ["kern", "liga", "ccmp", "locl", "mark", "mkmk"]
    options.hinting = False
    options.desubroutinize = True
    options.drop_tables += ["DSIG", "BASE"]
    font = subset.load_font(args.src, options)
    before = TTFont(args.src, lazy=True)["maxp"].numGlyphs
    subsetter = subset.Subsetter(options=options)
    subsetter.populate(text=text)
    subsetter.subset(font)
    font.save(args.dst)
    raw = open(args.dst, "rb").read()
    packed = len(gzip.compress(raw, 9))
    axes = [(a.axisTag, a.minValue, a.maxValue) for a in font["fvar"].axes] if "fvar" in font else []
    print(
        "%d characters, %d of %d glyphs kept, axes %s\n%s: %.2f MiB, %.2f MiB gzipped"
        % (
            len(text),
            font["maxp"].numGlyphs,
            before,
            axes,
            args.dst,
            len(raw) / 2**20,
            packed / 2**20,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
