# testing — open-blocklist test suite

Two standalone Go programs for testing open-blocklist:

| Directory | Purpose |
|-----------|---------|
| `perftest/` | Performance benchmarks — throughput, latency, RPS |
| `functest/` | Functional correctness — block, lookup, auth, delete |

Both require a running open-blocklist stack (API + DNS).

---

## perftest

Benchmarks all surfaces: API insert, API lookup (cold + warm), API auth,
CoreDNS RBL (cold + warm), custom-port resolver, and host OS resolver.

### Quick start

```bash
cd testing/perftest

# defaults: 100 000 entries, 50 workers
go run .

# shorter smoke-test
go run . -entries 1000 -concurrency 10
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-admin` | `http://localhost:8091` | Admin API base (PUT/DELETE /block) |
| `-lookup` | `http://localhost:8090` | Lookup API base (/lookup, /auth) |
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
| `-host-dns` | `false` | Run host resolver benchmark |
| `-delete` | `false` | Delete all entries at the end |

### Phases

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

### Example output

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
```

---

## functest

Verifies API correctness: block → lookup → HEAD → auth → delete → verify clean.
Exits 0 if all pass, 1 if any fail. Suitable for CI smoke-tests.

### Quick start

```bash
cd testing/functest

go run .

# against a non-default stack
go run . -admin http://myhost:8091 -lookup http://myhost:8090
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-admin` | `http://localhost:8091` | Admin API base (PUT/DELETE /block) |
| `-lookup` | `http://localhost:8090` | Lookup API base (/lookup, /auth) |

### What it tests

- Block an IP → expect 2xx
- GET /lookup → expect 200 + `blocked: true`
- HEAD /lookup → expect `X-Blocklist-Status: blocked`
- HEAD /auth → expect 403 for blocked IP, 200 for clean IP
- GET /lookup on a clean IP → expect 204
- HEAD /lookup on a clean IP → expect `X-Blocklist-Status: clean`
- DELETE /block → expect 2xx
- GET /lookup after delete → expect 204
- Edge case: invalid IP → expect 400/404

---

## Notes

- All test IPs are in `10.0.0.0/8` to avoid touching real addresses.
- Neither tool has external dependencies — only the Go standard library.
