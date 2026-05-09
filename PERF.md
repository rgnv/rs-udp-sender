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
| Measured runs | 5 (hyperfine 1.19.0) |
| Profiler | `perf stat` 6.12.86, `/usr/bin/time -v` |
| Drops observed | **0** (both impls) |
| Kernel | Linux 6.17.2-1-pve |
| rustc | 1.92 (workspace edition 2024) |
| go | 1.24.4 |

Pipeline:

```
<generator> | taskset -c 2 <sender>
```

## Results — 10M × 1400B

| Metric | Rust | Go | Rust / Go |
|---|---:|---:|---:|
| Wall mean | **44.861 s** | 66.279 s | **0.677×** |
| Wall stddev | 2.594 s | 2.502 s | — |
| Wall min | 41.138 s | 62.855 s | — |
| Wall max | 47.868 s | 68.523 s | — |
| Throughput (pkts/s) | **222,975** | 150,876 | **1.478×** |
| Throughput (MB/s) | **314 MB/s** | 212 MB/s | **1.478×** |
| Max RSS | **3,156 KB** | 10,228 KB | **0.309×** |
| Instructions (cpu_core) | **334.3 B** | 608.5 B | **0.549×** |
| Cycles (cpu_core) | **197.9 B** | 330.3 B | **0.599×** |
| IPC (cpu_core) | 1.69 | 1.84 | — |
| Context switches | **1,716,704** | 3,246,077 | **0.529×** |

### Headline Numbers

- **1.48× faster wall-clock** end-to-end (gen + parse + raw-socket send).
- **3.24× lower RSS** (3.1 MB vs 10.2 MB peak).
- **45% fewer instructions retired**, **40% fewer cycles**, **47% fewer context switches**.
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

Raw output: `results/{rust,go}-{hyperfine.json,perf.txt,time.txt}` and `results/summary.txt`.

## Notes & Caveats

- Raw-socket send is the dominant cost in both pipelines; remaining gap reflects per-packet overhead in the Go runtime (GC scan, scheduler) vs Rust's static dispatch.
- IPC favors Go (1.84 vs 1.69) — Go retires more instructions per cycle but **must retire 1.82× as many instructions overall**, so wall and energy still favor Rust.
- RSS gap is dominated by the Go runtime baseline (heap arenas, scheduler stacks) rather than per-packet allocation; both pipelines run with bounded per-packet allocations.
- Numbers are workload-specific (1400B payload, single sender thread, localhost dummy interface). Real wire-rate gains will depend on NIC, IRQ pinning, and RX-side processing.

