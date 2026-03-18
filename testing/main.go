// perftest - Performance test suite for open-blocklist
// Tests API operations and DNS resolution (host resolver, custom port, CoreDNS)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

// ---- Config ---------------------------------------------------------------

type Config struct {
	AdminBase   string // e.g. http://localhost:8090
	LookupBase  string // e.g. http://localhost:8080
	DNSAddr     string // CoreDNS addr, e.g. 127.0.0.1:55
	CustomDNS   string // custom resolver addr, e.g. 127.0.0.1:5353
	Zone        string // RBL zone suffix
	Entries     int    // number of IPs to insert
	Concurrency int    // parallel workers
	Seed        int64  // random seed for IP generation
}

func defaultConfig() Config {
	return Config{
		AdminBase:   "http://localhost:8090",
		LookupBase:  "http://localhost:8080",
		DNSAddr:     "127.0.0.1:55",
		CustomDNS:   "127.0.0.1:5353",
		Zone:        "open-blocklist.internal",
		Entries:     100_000,
		Concurrency: 50,
		Seed:        42,
	}
}

// ---- Result ---------------------------------------------------------------

type Result struct {
	Name     string
	Total    int
	Errors   int
	Duration time.Duration
	// latency buckets (µs)
	P50, P95, P99 time.Duration
	Latencies     []time.Duration
}

func (r *Result) RPS() float64 {
	if r.Duration == 0 {
		return 0
	}
	return float64(r.Total) / r.Duration.Seconds()
}

func (r *Result) ComputePercentiles() {
	if len(r.Latencies) == 0 {
		return
	}
	// simple insertion-sort-free percentile via copying & sorting
	lats := make([]time.Duration, len(r.Latencies))
	copy(lats, r.Latencies)
	sortDurations(lats)
	r.P50 = lats[len(lats)*50/100]
	r.P95 = lats[len(lats)*95/100]
	r.P99 = lats[len(lats)*99/100]
}

func sortDurations(d []time.Duration) {
	// shell sort – avoids importing sort for simple slice
	n := len(d)
	gap := n / 2
	for gap > 0 {
		for i := gap; i < n; i++ {
			temp := d[i]
			j := i
			for j >= gap && d[j-gap] > temp {
				d[j] = d[j-gap]
				j -= gap
			}
			d[j] = temp
		}
		gap /= 2
	}
}

// ---- IP generation --------------------------------------------------------

// generateIPs returns `n` deterministic pseudo-random IPs in the
// 10.0.0.0/8 range, avoiding .0 and .255 last octets.
func generateIPs(n int, seed int64) []string {
	rng := rand.New(rand.NewSource(seed))
	ips := make([]string, 0, n)
	seen := make(map[uint32]bool, n)
	for len(ips) < n {
		a := uint8(10)
		b := uint8(rng.Intn(256))
		c := uint8(rng.Intn(256))
		d := uint8(1 + rng.Intn(254))
		key := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
		if seen[key] {
			continue
		}
		seen[key] = true
		ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", a, b, c, d))
	}
	return ips
}

// reverseIP turns "1.2.3.4" → "4.3.2.1"
func reverseIP(ip string) string {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return ip
	}
	return fmt.Sprintf("%d.%d.%d.%d", parsed[3], parsed[2], parsed[1], parsed[0])
}

// ---- HTTP helpers ---------------------------------------------------------

var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     90 * time.Second,
	},
}

func blockIP(adminBase, ip string) error {
	req, err := http.NewRequest(http.MethodPut, adminBase+"/block/"+ip, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("block %s: HTTP %d", ip, resp.StatusCode)
	}
	return nil
}

func deleteIP(adminBase, ip string) error {
	req, err := http.NewRequest(http.MethodDelete, adminBase+"/block/"+ip, nil)
	if err != nil {
		return err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete %s: HTTP %d", ip, resp.StatusCode)
	}
	return nil
}

type LookupResponse struct {
	Blocked bool   `json:"blocked"`
	IP      string `json:"ip"`
	Source  string `json:"source"`
}

func lookupIP(lookupBase, ip string) (LookupResponse, error) {
	resp, err := httpClient.Get(lookupBase + "/lookup/" + ip)
	if err != nil {
		return LookupResponse{}, err
	}
	defer resp.Body.Close()
	var lr LookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return LookupResponse{}, err
	}
	return lr, nil
}

func authIP(lookupBase, ip string) (int, error) {
	resp, err := httpClient.Head(lookupBase + "/auth/" + ip)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ---- DNS helpers ----------------------------------------------------------

func newDNSResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// queryRBL queries addr for <reversed-ip>.<zone> A record.
func queryRBL(resolver *net.Resolver, ip, zone string) (bool, error) {
	fqdn := reverseIP(ip) + "." + zone
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, fqdn)
	if err != nil {
		// NXDOMAIN = not blocked
		return false, nil
	}
	return len(addrs) > 0, nil
}

// ---- Benchmark runner -----------------------------------------------------

type benchFunc func(ip string) error

func runBench(name string, ips []string, concurrency int, fn benchFunc) Result {
	result := Result{
		Name:      name,
		Total:     len(ips),
		Latencies: make([]time.Duration, 0, len(ips)),
	}

	work := make(chan string, len(ips))
	for _, ip := range ips {
		work <- ip
	}
	close(work)

	var (
		mu      sync.Mutex
		errCnt  int64
		wg      sync.WaitGroup
		latBuf  = make([][]time.Duration, concurrency)
	)

	start := time.Now()
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var lats []time.Duration
			for ip := range work {
				t0 := time.Now()
				if err := fn(ip); err != nil {
					atomic.AddInt64(&errCnt, 1)
				}
				lats = append(lats, time.Since(t0))
			}
			latBuf[idx] = lats
		}(i)
	}
	wg.Wait()
	result.Duration = time.Since(start)
	result.Errors = int(errCnt)

	for _, lats := range latBuf {
		mu.Lock()
		result.Latencies = append(result.Latencies, lats...)
		mu.Unlock()
	}
	result.ComputePercentiles()
	return result
}

// ---- Reporting ------------------------------------------------------------

func printResults(results []Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "\nBenchmark\tTotal\tErrors\tDuration\tRPS\tP50\tP95\tP99")
	fmt.Fprintln(w, "---------\t-----\t------\t--------\t---\t---\t---\t---")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%.0f\t%s\t%s\t%s\n",
			r.Name,
			r.Total,
			r.Errors,
			r.Duration.Round(time.Millisecond),
			r.RPS(),
			r.P50.Round(time.Microsecond),
			r.P95.Round(time.Microsecond),
			r.P99.Round(time.Microsecond),
		)
	}
	w.Flush()
}

// ---- Main -----------------------------------------------------------------

func main() {
	cfg := defaultConfig()

	flag.StringVar(&cfg.AdminBase, "admin", cfg.AdminBase, "Admin API base URL (block/delete)")
	flag.StringVar(&cfg.LookupBase, "lookup", cfg.LookupBase, "Lookup API base URL")
	flag.StringVar(&cfg.DNSAddr, "coredns", cfg.DNSAddr, "CoreDNS address (host:port)")
	flag.StringVar(&cfg.CustomDNS, "customdns", cfg.CustomDNS, "Custom resolver address (host:port)")
	flag.StringVar(&cfg.Zone, "zone", cfg.Zone, "RBL DNS zone")
	flag.IntVar(&cfg.Entries, "entries", cfg.Entries, "Number of IPs to insert")
	flag.IntVar(&cfg.Concurrency, "concurrency", cfg.Concurrency, "Parallel workers")
	flag.Int64Var(&cfg.Seed, "seed", cfg.Seed, "Random seed for IP generation")

	// Flags to selectively run phases
	doInsert := flag.Bool("insert", true, "Run insertion phase")
	doAPILookup := flag.Bool("api-lookup", true, "Run API lookup benchmark")
	doAPIAuth := flag.Bool("api-auth", true, "Run API auth benchmark")
	doCoreDNS := flag.Bool("coredns-dns", true, "Run CoreDNS benchmark")
	doCustomDNS := flag.Bool("custom-dns", true, "Run custom resolver benchmark")
	doHostDNS := flag.Bool("host-dns", false, "Run host resolver benchmark")
	doDelete := flag.Bool("delete", false, "Run deletion phase at the end")

	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)

	fmt.Println("=== open-blocklist performance test ===")
	fmt.Printf("Entries:     %d\n", cfg.Entries)
	fmt.Printf("Concurrency: %d\n", cfg.Concurrency)
	fmt.Printf("Admin:       %s\n", cfg.AdminBase)
	fmt.Printf("Lookup:      %s\n", cfg.LookupBase)
	fmt.Printf("CoreDNS:     %s\n", cfg.DNSAddr)
	fmt.Printf("CustomDNS:   %s\n", cfg.CustomDNS)
	fmt.Printf("Zone:        %s\n\n", cfg.Zone)

	ips := generateIPs(cfg.Entries, cfg.Seed)
	log.Printf("Generated %d unique IPs", len(ips))

	var results []Result

	// -- Phase 1: Insert ----------------------------------------------------
	if *doInsert {
		log.Printf("Phase 1: Inserting %d entries ...", cfg.Entries)
		r := runBench("api_block_insert", ips, cfg.Concurrency, func(ip string) error {
			return blockIP(cfg.AdminBase, ip)
		})
		log.Printf("  done: %.0f RPS, %d errors", r.RPS(), r.Errors)
		results = append(results, r)
	}

	// -- Phase 2: API Lookup ------------------------------------------------
	if *doAPILookup {
		log.Printf("Phase 2: API /lookup for %d entries ...", cfg.Entries)
		// first pass: no cache warm-up (cold)
		r := runBench("api_lookup_cold", ips, cfg.Concurrency, func(ip string) error {
			lr, err := lookupIP(cfg.LookupBase, ip)
			if err != nil {
				return err
			}
			if !lr.Blocked {
				return fmt.Errorf("expected %s to be blocked", ip)
			}
			return nil
		})
		log.Printf("  cold done: %.0f RPS, %d errors", r.RPS(), r.Errors)
		results = append(results, r)

		// second pass: warm (any in-process caching should kick in)
		r2 := runBench("api_lookup_warm", ips, cfg.Concurrency, func(ip string) error {
			lr, err := lookupIP(cfg.LookupBase, ip)
			if err != nil {
				return err
			}
			if !lr.Blocked {
				return fmt.Errorf("expected %s to be blocked", ip)
			}
			return nil
		})
		log.Printf("  warm done: %.0f RPS, %d errors", r2.RPS(), r2.Errors)
		results = append(results, r2)
	}

	// -- Phase 3: API Auth --------------------------------------------------
	if *doAPIAuth {
		log.Printf("Phase 3: API /auth for %d entries ...", cfg.Entries)
		r := runBench("api_auth", ips, cfg.Concurrency, func(ip string) error {
			code, err := authIP(cfg.LookupBase, ip)
			if err != nil {
				return err
			}
			if code != http.StatusForbidden {
				return fmt.Errorf("expected 403 for %s, got %d", ip, code)
			}
			return nil
		})
		log.Printf("  done: %.0f RPS, %d errors", r.RPS(), r.Errors)
		results = append(results, r)
	}

	// -- Phase 4: CoreDNS ---------------------------------------------------
	// We use a subset for DNS (DNS is slower; 10k is usually sufficient for perf data)
	dnsSample := ips
	if len(dnsSample) > 10_000 {
		dnsSample = ips[:10_000]
	}

	if *doCoreDNS {
		coreDNSResolver := newDNSResolver(cfg.DNSAddr)
		log.Printf("Phase 4: CoreDNS RBL queries (%d entries, addr=%s) ...", len(dnsSample), cfg.DNSAddr)

		// cold
		r := runBench("coredns_cold", dnsSample, cfg.Concurrency, func(ip string) error {
			found, err := queryRBL(coreDNSResolver, ip, cfg.Zone)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("expected %s in RBL", ip)
			}
			return nil
		})
		log.Printf("  cold done: %.0f RPS, %d errors", r.RPS(), r.Errors)
		results = append(results, r)

		// warm (CoreDNS cache should serve many hits)
		r2 := runBench("coredns_warm", dnsSample, cfg.Concurrency, func(ip string) error {
			found, err := queryRBL(coreDNSResolver, ip, cfg.Zone)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("expected %s in RBL", ip)
			}
			return nil
		})
		log.Printf("  warm done: %.0f RPS, %d errors", r2.RPS(), r2.Errors)
		results = append(results, r2)
	}

	// -- Phase 5: Custom DNS resolver (e.g. 5353) ---------------------------
	if *doCustomDNS {
		customResolver := newDNSResolver(cfg.CustomDNS)
		log.Printf("Phase 5: Custom resolver RBL queries (%d entries, addr=%s) ...", len(dnsSample), cfg.CustomDNS)

		r := runBench("custom_dns_cold", dnsSample, cfg.Concurrency, func(ip string) error {
			found, err := queryRBL(customResolver, ip, cfg.Zone)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("expected %s in RBL", ip)
			}
			return nil
		})
		log.Printf("  cold done: %.0f RPS, %d errors", r.RPS(), r.Errors)
		results = append(results, r)

		r2 := runBench("custom_dns_warm", dnsSample, cfg.Concurrency, func(ip string) error {
			found, err := queryRBL(customResolver, ip, cfg.Zone)
			if err != nil {
				return err
			}
			if !found {
				return fmt.Errorf("expected %s in RBL", ip)
			}
			return nil
		})
		log.Printf("  warm done: %.0f RPS, %d errors", r2.RPS(), r2.Errors)
		results = append(results, r2)
	}

	// -- Phase 6: Host DNS resolver -----------------------------------------
	if *doHostDNS {
		hostResolver := &net.Resolver{PreferGo: true} // uses /etc/resolv.conf
		log.Printf("Phase 6: Host resolver RBL queries (%d entries) ...", len(dnsSample))

		r := runBench("host_dns_cold", dnsSample, cfg.Concurrency, func(ip string) error {
			_, err := queryRBL(hostResolver, ip, cfg.Zone)
			// host resolver may NXDOMAIN if not configured to forward to CoreDNS;
			// we record results but don't treat them as hard errors here.
			_ = err
			return nil
		})
		log.Printf("  done: %.0f RPS", r.RPS())
		results = append(results, r)
	}

	// -- Phase 7 (optional): Delete all -------------------------------------
	if *doDelete {
		log.Printf("Phase 7: Deleting %d entries ...", cfg.Entries)
		r := runBench("api_block_delete", ips, cfg.Concurrency, func(ip string) error {
			return deleteIP(cfg.AdminBase, ip)
		})
		log.Printf("  done: %.0f RPS, %d errors", r.RPS(), r.Errors)
		results = append(results, r)
	}

	// -- Summary ------------------------------------------------------------
	printResults(results)
}
