#!/usr/bin/env bash
# Run hashcat in brute-force mode for masks lengths 1..5 against hashes_to_crack.txt
# WARNING: brute-forcing is computationally expensive.
set -euo pipefail
HASH_FILE="hashes_to_crack.txt"
OUT_FILE="cracked_users.txt"
if [ ! -f "$HASH_FILE" ]; then
  echo "$HASH_FILE not found. Run tools/crack_users.py to generate it." >&2
  exit 1
fi
if ! command -v hashcat >/dev/null 2>&1; then
  echo "hashcat not installed or not in PATH" >&2
  exit 2
fi
rm -f "$OUT_FILE"
# Loop masks: 1 to 5 characters using ?a (all chars). You can replace ?a with a tighter mask for speed.
for L in 1 2 3 4 5; do
  MASK=$(printf '?a%.0s' $(seq 1 $L))
  echo "Running hashcat for length=$L mask=$MASK"
  hashcat -m 0 -a 3 "$HASH_FILE" "$MASK" --outfile="$OUT_FILE" --outfile-format=2 --remove --potfile-disable || true
  # Stop early if we cracked all hashes
  if [ -s "$OUT_FILE" ]; then
    # check if all hashes cracked
    total_hashes=$(wc -l < "$HASH_FILE" | tr -d ' ')
    cracked=$(wc -l < "$OUT_FILE" | tr -d ' ')
    echo "Cracked $cracked / $total_hashes so far"
    if [ "$cracked" -ge "$total_hashes" ]; then
      echo "All hashes cracked. Exiting."
      break
    fi
  fi
done

echo "Done. Results (if any) written to $OUT_FILE"