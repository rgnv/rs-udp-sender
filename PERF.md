# Performance — rs-udp-sender vs Go reference

End-to-end pipeline benchmark of the Rust implementation against the canonical Go [Cribl `udp-sender`](https://github.com/criblio/udp-sender) on identical hardware, kernel, and workload.

## Test Setup

| Parameter | Value |
|---|---|
| Packets | 10,000,000 |
| Payload | 1400 B per packet (≈MTU-safe) |
| Bytes sent | 14,088,888,897 (gen → wire, headers included) |
| Destination | `192.0.2.99:5000` (RFC 5737 TEST-NET-1, dummy iface `bench0`) |
| Sink | Python UDP discard server (`SO_RCVBUF=16 MB`) |
| Generator core | `taskset -c 1` |
| Sender core | `taskset -c 2` |
| Warmup runs | 3 |
| Measured runs | 5 (hyperfine 1.20.0) |
| RSS | `/usr/bin/time -v` |
| Drops observed | **0** (both impls) |
| Kernel | Linux 6.17.2-1-pve |
| rustc | 1.97.1 (workspace edition 2024) |
| go | 1.26.4 |

Pipeline:

```
<generator> | taskset -c 2 <sender>
```

## Results — 10M × 1400B

| Metric | Rust | Go | Rust / Go |
|---|---:|---:|---:|
| Wall mean | **64.202 s** | 109.338 s | **0.587×** |
| Wall stddev | 2.552 s | 12.655 s | — |
| Wall min | 61.061 s | 97.270 s | — |
| Wall max | 67.018 s | 130.305 s | — |
| Throughput (pkts/s) | **155,758** | 91,368 | **1.70×** |
| Throughput (MB/s) | **219 MB/s** | 129 MB/s | **1.70×** |
| Max RSS | **3,060 KB** | 12,996 KB | **0.235×** |

### Headline Numbers

- **1.70× faster wall-clock** end-to-end (gen + parse + raw-socket send).
- **4.25× lower RSS** (3.0 MB vs 13.0 MB peak).
- **Zero drops** on both implementations at full rate.

## Reproducing

```bash
# 1. Bring up TEST-NET-1 dummy iface (CAP_NET_ADMIN)
sudo ip link add bench0 type dummy
sudo ip link set bench0 up
sudo ip addr add 192.0.2.1/24 dev bench0
sudo ip addr add 192.0.2.99/32 dev bench0

# 2. Start UDP discard sink (separate shell)
python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
s.bind(("192.0.2.99", 5000))
buf = bytearray(65536)
while True:
    s.recvfrom_into(buf)
PY

# 3. Run the matrix
PKT_COUNT=10000000 PAYLOAD_BYTES=1400 WARMUP=3 RUNS=5 \
  scripts/perf-bench.sh
```

Raw output: `results/{rust,go}-{hyperfine.json,time.txt}` and `results/summary.txt`.

## Notes & Caveats

- Raw-socket send (`sendto` syscall per packet) is the dominant cost in both pipelines; remaining gap reflects per-packet overhead in the Go runtime (GC scan, scheduler) vs Rust's static dispatch and zero-allocation hot path.
- RSS gap is dominated by the Go runtime baseline (heap arenas, scheduler stacks) rather than per-packet allocation; both pipelines run with bounded per-packet allocations.
- `perf stat` hardware counters (instructions, cycles, IPC, context-switches) were **not collectable** in this environment: `kernel.perf_event_paranoid=4` and `/proc/sys` is read-only (unprivileged container). `scripts/perf-bench.sh` still captures them automatically where perf is permitted.
- Absolute wall-clock numbers are host-load sensitive: this run's Go stddev (12.7 s on a 109 s mean) reflects a shared/noisy host, and both implementations measured slower in absolute terms than the previous baseline on this machine. The relative comparison (same host, same window, interleaved runs) is the meaningful figure.
- Numbers are workload-specific (1400B payload, single sender thread, localhost dummy interface). Real wire-rate gains will depend on NIC, IRQ pinning, and RX-side processing.
