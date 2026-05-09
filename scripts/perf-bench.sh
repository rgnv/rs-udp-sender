#!/usr/bin/env bash
# perf-bench.sh — measure throughput, latency, RSS, IPC for rs-udp-sender vs Go reference.
#
# Requires: hyperfine, /usr/bin/time (-v), perf stat, socat, root or CAP_NET_RAW.
# Methodology:
#   - 10M packets x 1400B payload over UDP4 to loopback (127.0.0.99:5000)
#   - socat black-hole drains receiver to keep send-side honest
#   - taskset pins generator to core 1, sender to core 2 (no SMT siblings)
#   - hyperfine: 3 warmup + 5 measured runs per binary (wall-clock + p50/p99)
#   - /usr/bin/time -v: max RSS in KB
#   - perf stat: instructions, cycles, IPC, context-switches
# Outputs: results/{rust,go}-{packets,trap}.json + results/summary.txt

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/results"
mkdir -p "$RESULTS"

RUST_PG="$ROOT/target/release/rs-udp-packet-generator"
RUST_SENDER="$ROOT/target/release/rs-udp-sender"
GO_PG="${GO_PG:-/tmp/go-packet-generator}"
GO_SENDER="${GO_SENDER:-/tmp/go-udp-sender}"

PKT_COUNT="${PKT_COUNT:-10000000}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-1400}"
DEST_IP="${DEST_IP:-192.0.2.99}"
DEST_PORT="${DEST_PORT:-5000}"
WARMUP="${WARMUP:-3}"
RUNS="${RUNS:-5}"

# 1400 char message gives ~1400-byte UDP payload (msg + counter suffix is fine for size).
MSG="$(printf 'X%.0s' $(seq 1 "$PAYLOAD_BYTES"))"

# Pin to specific cores. Override with TASKSET_GEN/TASKSET_SND.
TASKSET_GEN="${TASKSET_GEN:-taskset -c 1}"
TASKSET_SND="${TASKSET_SND:-taskset -c 2}"

for bin in "$RUST_PG" "$RUST_SENDER" "$GO_PG" "$GO_SENDER"; do
  [[ -x "$bin" ]] || { echo "missing binary: $bin" >&2; exit 1; }
done
command -v hyperfine >/dev/null || { echo "hyperfine required" >&2; exit 1; }
command -v perf >/dev/null      || { echo "perf required" >&2; exit 1; }

# External black-hole listener required on ${DEST_IP}:${DEST_PORT}.
# Recommended setup (run before invoking this script):
#   ip link add bench0 type dummy && ip link set bench0 up
#   ip addr add 192.0.2.1/24 dev bench0 && ip addr add 192.0.2.99/32 dev bench0
#   nohup bash -c 'while true; do nc -u -l -p 5000 -s 192.0.2.99 >/dev/null 2>&1; done' &
if ! ss -ulnp 2>/dev/null | grep -q "${DEST_IP}:${DEST_PORT}"; then
  echo "no UDP listener on ${DEST_IP}:${DEST_PORT} — start blackhole first" >&2
  exit 1
fi

export PKT_COUNT PAYLOAD_BYTES DEST_IP DEST_PORT MSG TASKSET_GEN TASKSET_SND

run_pipeline() {
  local label="$1" pg="$2" snd="$3" style="$4"
  export PG="$pg" SND="$snd"
  # CLI style asymmetry: Rust pkt-gen uses clap GNU double-dash (--count);
  # Go pkt-gen uses Go flag pkg single-dash (-count). Sender flags (-m / --mtu)
  # are accepted by both styles in their respective parsers.
  local pg_args snd_args
  if [[ "$style" == "rust" ]]; then
    pg_args="--count $PKT_COUNT --dest-ip $DEST_IP --dest-port $DEST_PORT --message \"\$MSG\""
    snd_args="--mtu 1500"
  else
    pg_args="-count $PKT_COUNT -dest-ip $DEST_IP -dest-port $DEST_PORT -message \"\$MSG\""
    snd_args="-m 1500"
  fi
  local cmd="$TASKSET_GEN \"\$PG\" $pg_args | $TASKSET_SND \"\$SND\" $snd_args"

  echo "==> [$label] hyperfine wall-clock"
  hyperfine --shell=bash \
    --warmup "$WARMUP" --runs "$RUNS" \
    --export-json "$RESULTS/${label}-hyperfine.json" \
    --command-name "$label" \
    "$cmd"

  echo "==> [$label] /usr/bin/time -v RSS"
  /usr/bin/time -v -o "$RESULTS/${label}-time.txt" bash -c "$cmd" || true

  echo "==> [$label] perf stat IPC"
  perf stat -o "$RESULTS/${label}-perf.txt" \
    -e instructions,cycles,context-switches,cache-misses \
    bash -c "$cmd" || true
}

run_pipeline "rust" "$RUST_PG"  "$RUST_SENDER" "rust"
run_pipeline "go"   "$GO_PG"    "$GO_SENDER"   "go"

echo "==> Summary -> $RESULTS/summary.txt"
{
  echo "rs-udp-sender perf bench"
  echo "PKT_COUNT=$PKT_COUNT PAYLOAD_BYTES=$PAYLOAD_BYTES DEST=${DEST_IP}:${DEST_PORT}"
  echo "WARMUP=$WARMUP RUNS=$RUNS"
  echo
  for label in rust go; do
    echo "=== $label ==="
    if [[ -f "$RESULTS/${label}-hyperfine.json" ]]; then
      jq -r '.results[0] | "wall-mean=\(.mean)s stddev=\(.stddev)s min=\(.min)s max=\(.max)s"' \
         "$RESULTS/${label}-hyperfine.json"
    fi
    grep -E "Maximum resident set size" "$RESULTS/${label}-time.txt" 2>/dev/null || true
    grep -E "instructions|cycles|insn per cycle|context-switches" "$RESULTS/${label}-perf.txt" 2>/dev/null || true
    echo
  done
} | tee "$RESULTS/summary.txt"
