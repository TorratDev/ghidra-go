#!/bin/sh
# Usage: verify.sh /path/to/decompile
# Replays each recorded input to the real decompile and diffs stdout against the recorded output.
d=$(dirname "$0"); bin=${1:?path to decompile binary}; rc=0
for f in "$d"/*/in.hex; do
	dir=$(dirname "$f")
	xxd -r -p "$f" | "$bin" | xxd -p | diff - "$dir/out.hex" >/dev/null \
		&& echo "OK   $(basename "$dir")" || { echo "FAIL $(basename "$dir")"; rc=1; }
done
exit $rc
