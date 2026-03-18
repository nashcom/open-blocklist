# perftest — open-blocklist performance test

A standalone Go program that benchmarks all surfaces of open-blocklist:
API insert, API lookup (cold + warm), API auth, CoreDNS RBL (cold + warm),
a custom-port resolver, and the host OS resolver.

## Directory layout

```
perftest/
├── main.go      ← single-file program, no external dependencies
└── go.mod
```

Place this directory next to your main module:

```
open-blocklist/
├── ...           ← main service
└── perftest/     ← this directory
```

## Quick start

```bash
# 1. start the open-blocklist stack first (API + CoreDNS)

# 2. run with defaults (100 000 entries, 50 workers)
cd perftest
go run .

# 3. shorter smoke-test
go run . -entries 1000 -concurrency 10
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-admin` | `http://localhost:8090` | Admin API base (PUT/DELETE /block) |
| `-lookup` | `http://localhost:8080` | Lookup API base (/lookup, /auth) |
| `-coredns` | `127.0.0.1:55` | CoreDNS address (host:port) |
| `-customdns` | `127.0.0.1:5353` | Custom resolver address |
| `-zone` | `open-blocklist.internal` | RBL DNS zone suffix |
| `-entries` | `100000` | IPs to insert and query |
| `-concurrency` | `50` | Parallel workers |
| `-seed` | `42` | RNG seed for reproducible IP sets |
| `-insert` | `true` | Run insertion phase |
| `-api-lookup` | `true` | Run /lookup benchmark (cold + warm) |
| `-api-auth` | `true` | Run /auth benchmark |
| `-coredns-dns` | `true` | Run CoreDNS RBL benchmark |
| `-custom-dns` | `true` | Run custom resolver benchmark |
| `-host-dns` | `true` | Run host resolver benchmark |
| `-delete` | `false` | Delete all entries at the end |

## Phases

| Phase | Name(s) in output | What it measures |
|-------|-------------------|-----------------|
| 1 | `api_block_insert` | Bulk write throughput |
| 2 | `api_lookup_cold` / `api_lookup_warm` | Read throughput + in-process cache effect |
| 3 | `api_auth` | Auth (HEAD) throughput |
| 4 | `coredns_cold` / `coredns_warm` | CoreDNS RBL; warm pass shows cache hit-rate benefit |
| 5 | `custom_dns_cold` / `custom_dns_warm` | Same via custom-port resolver |
| 6 | `host_dns_cold` | OS resolver (needs /etc/resolv.conf to forward the zone) |
| 7 | `api_block_delete` | Bulk delete throughput (opt-in with `-delete`) |

> DNS phases use a 10 000 IP sample by default (DNS is RTT-bound; 10 k gives
> stable percentiles without long runtimes).

## Example output

```
Benchmark             Total    Errors  Duration    RPS     P50      P95      P99
---------             -----    ------  --------    ---     ---      ---      ---
api_block_insert      100000   0       4.321s      23142   1.8ms    4.2ms    8.1ms
api_lookup_cold       100000   0       3.987s      25082   1.6ms    3.9ms    7.4ms
api_lookup_warm       100000   0       2.103s      47550   800µs    2.1ms    4.0ms
api_auth              100000   0       3.210s      31152   1.3ms    3.1ms    5.9ms
coredns_cold          10000    0       8.442s      1185    38ms     72ms     95ms
coredns_warm          10000    0       1.023s      9775    4.2ms    9.1ms    14ms
custom_dns_cold       10000    0       9.101s      1099    41ms     79ms     102ms
custom_dns_warm       10000    0       1.211s      8257    5.1ms    10ms     16ms
host_dns_cold         10000    0       10.201s     980     45ms     88ms     115ms
```

The `warm` vs `cold` gap on CoreDNS rows directly shows the caching benefit.

## What to look for

- **`api_lookup_warm` vs `api_lookup_cold`**: in-process / HTTP-layer caching.
- **`coredns_warm` vs `coredns_cold`**: CoreDNS cache plugin effectiveness.
- **`coredns_*` vs `custom_dns_*`**: cost of the extra hop through a forwarding resolver.
- **`host_dns_*`**: baseline for applications that just use the OS resolver — depends heavily on `/etc/resolv.conf` forwarding setup.
- **Error column**: any non-zero value needs investigation before reading RPS numbers.

## Notes

- All IPs are generated in `10.0.0.0/8` to avoid touching real addresses.
- The same seed always produces the same IP set, making runs reproducible.
- The program has **no external dependencies** — only the Go standard library.
- Adjust `-concurrency` to match your server's CPU count for fairness.
