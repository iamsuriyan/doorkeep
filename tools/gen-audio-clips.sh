#!/usr/bin/env sh
# Generates the spoken-character clips for the audio challenge with espeak-ng
# inside a throwaway Alpine container. Output: 8 kHz mono 16-bit WAV, one per
# character per voice, in internal/challenge/visual/clips. espeak-ng is GPL;
# its audio output is not a derivative work and ships under Apache-2.0.
set -eu
OUT="$(cd "$(dirname "$0")/.." && pwd)/internal/challenge/visual/clips"
mkdir -p "$OUT"
ALPHABET="ACDEFHJKLMNPRTUVWXY3479"
docker run --rm -v "$OUT":/out alpine:3.20 sh -c "
  apk add --no-cache espeak-ng ffmpeg >/dev/null
  for v in en-us+m3 en-gb+f3 en-us+m7; do
    tag=\$(echo \$v | tr '+' '_' )
    for c in \$(echo $ALPHABET | sed 's/./& /g'); do
      espeak-ng -v \$v -s 140 -w /tmp/c.wav \"\$c\"
      ffmpeg -loglevel error -y -i /tmp/c.wav -af 'silenceremove=start_periods=1:start_threshold=-45dB,areverse,silenceremove=start_periods=1:start_threshold=-45dB,areverse' -ar 8000 -ac 1 -sample_fmt s16 /out/\${tag}_\$c.wav
    done
  done
  chown -R $(id -u):$(id -g) /out
"
ls "$OUT" | wc -l
