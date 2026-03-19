// functest - Functional test suite for open-blocklist
// Tests API correctness: block, lookup, auth, HEAD, delete
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "net/http"
    "os"
    "time"
)

// ---- Config ---------------------------------------------------------------

type Config struct {
    AdminBase  string // e.g. http://localhost:8090
    LookupBase string // e.g. http://localhost:8080
}

// ---- State ----------------------------------------------------------------

var (
    passed int
    failed int
    client = &http.Client{Timeout: 5 * time.Second}
)

// ---- Assertions -----------------------------------------------------------

func pass(name string) {
    fmt.Printf("  PASS  %s\n", name)
    passed++
}

func fail(name, reason string) {
    fmt.Printf("  FAIL  %s — %s\n", name, reason)
    failed++
}

func expect(name string, ok bool, reason string) {
    if ok {
        pass(name)
    } else {
        fail(name, reason)
    }
}

// ---- HTTP helpers ---------------------------------------------------------

func doRequest(method, url string) (*http.Response, error) {
    req, err := http.NewRequest(method, url, nil)
    if err != nil {
        return nil, err
    }
    return client.Do(req)
}

func blockIP(adminBase, ip string) (int, error) {
    resp, err := doRequest(http.MethodPut, adminBase+"/block/"+ip)
    if err != nil {
        return 0, err
    }
    resp.Body.Close()
    return resp.StatusCode, nil
}

func deleteIP(adminBase, ip string) (int, error) {
    resp, err := doRequest(http.MethodDelete, adminBase+"/block/"+ip)
    if err != nil {
        return 0, err
    }
    resp.Body.Close()
    return resp.StatusCode, nil
}

type LookupResponse struct {
    Blocked bool   `json:"blocked"`
    IP      string `json:"ip"`
}

func lookupIP(lookupBase, ip string) (LookupResponse, int, error) {
    resp, err := doRequest(http.MethodGet, lookupBase+"/lookup/"+ip)
    if err != nil {
        return LookupResponse{}, 0, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return LookupResponse{Blocked: false}, resp.StatusCode, nil
    }

    var lr LookupResponse
    if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
        return LookupResponse{}, resp.StatusCode, err
    }
    return lr, resp.StatusCode, nil
}

func headLookup(lookupBase, ip string) (int, string, error) {
    resp, err := doRequest(http.MethodHead, lookupBase+"/lookup/"+ip)
    if err != nil {
        return 0, "", err
    }
    resp.Body.Close()
    return resp.StatusCode, resp.Header.Get("X-Blocklist-Status"), nil
}

func authIP(lookupBase, ip string) (int, error) {
    resp, err := doRequest(http.MethodHead, lookupBase+"/auth/"+ip)
    if err != nil {
        return 0, err
    }
    resp.Body.Close()
    return resp.StatusCode, nil
}

// ---- Test sections --------------------------------------------------------

func section(name string) {
    fmt.Printf("\n[%s]\n", name)
}

func runTests(cfg Config) {
    testIP := "10.99.1.1"
    cleanIP := "10.99.2.2"

    // -----------------------------------------------------------------------
    section("Block IP")

    code, err := blockIP(cfg.AdminBase, testIP)
    expect("PUT /block/"+testIP+" returns 2xx",
        err == nil && code >= 200 && code < 300,
        fmt.Sprintf("err=%v code=%d", err, code))

    // -----------------------------------------------------------------------
    section("Lookup blocked IP")

    lr, code, err := lookupIP(cfg.LookupBase, testIP)
    expect("GET /lookup/"+testIP+" returns 200",
        err == nil && code == http.StatusOK,
        fmt.Sprintf("err=%v code=%d", err, code))
    expect("GET /lookup/"+testIP+" blocked=true",
        err == nil && lr.Blocked,
        fmt.Sprintf("blocked=%v", lr.Blocked))

    // -----------------------------------------------------------------------
    section("HEAD lookup blocked IP")

    code, status, err := headLookup(cfg.LookupBase, testIP)
    expect("HEAD /lookup/"+testIP+" returns 200",
        err == nil && code == http.StatusOK,
        fmt.Sprintf("err=%v code=%d", err, code))
    expect("HEAD /lookup/"+testIP+" X-Blocklist-Status: blocked",
        err == nil && status == "blocked",
        fmt.Sprintf("status=%q", status))

    // -----------------------------------------------------------------------
    section("Auth check blocked IP")

    code, err = authIP(cfg.LookupBase, testIP)
    expect("HEAD /auth/"+testIP+" returns 403",
        err == nil && code == http.StatusForbidden,
        fmt.Sprintf("err=%v code=%d", err, code))

    // -----------------------------------------------------------------------
    section("Lookup clean IP (never blocked)")

    lr, code, err = lookupIP(cfg.LookupBase, cleanIP)
    expect("GET /lookup/"+cleanIP+" returns 204",
        err == nil && code == http.StatusNoContent,
        fmt.Sprintf("err=%v code=%d", err, code))
    expect("GET /lookup/"+cleanIP+" blocked=false",
        err == nil && !lr.Blocked,
        fmt.Sprintf("blocked=%v", lr.Blocked))

    // -----------------------------------------------------------------------
    section("HEAD lookup clean IP")

    code, status, err = headLookup(cfg.LookupBase, cleanIP)
    expect("HEAD /lookup/"+cleanIP+" returns 204",
        err == nil && code == http.StatusNoContent,
        fmt.Sprintf("err=%v code=%d", err, code))
    expect("HEAD /lookup/"+cleanIP+" X-Blocklist-Status: clean",
        err == nil && status == "clean",
        fmt.Sprintf("status=%q", status))

    // -----------------------------------------------------------------------
    section("Auth check clean IP")

    code, err = authIP(cfg.LookupBase, cleanIP)
    expect("HEAD /auth/"+cleanIP+" returns 200",
        err == nil && code == http.StatusOK,
        fmt.Sprintf("err=%v code=%d", err, code))

    // -----------------------------------------------------------------------
    section("Delete blocked IP")

    code, err = deleteIP(cfg.AdminBase, testIP)
    expect("DELETE /block/"+testIP+" returns 2xx",
        err == nil && code >= 200 && code < 300,
        fmt.Sprintf("err=%v code=%d", err, code))

    // -----------------------------------------------------------------------
    section("Lookup after delete")

    lr, code, err = lookupIP(cfg.LookupBase, testIP)
    expect("GET /lookup/"+testIP+" returns 204 after delete",
        err == nil && code == http.StatusNoContent,
        fmt.Sprintf("err=%v code=%d", err, code))
    expect("GET /lookup/"+testIP+" blocked=false after delete",
        err == nil && !lr.Blocked,
        fmt.Sprintf("blocked=%v", lr.Blocked))

    // -----------------------------------------------------------------------
    section("Edge cases")

    // Invalid IP path — lookup server should return 400
    _, code, err = lookupIP(cfg.LookupBase, "not-an-ip")
    expect("GET /lookup/not-an-ip returns 400 or 404",
        err == nil && (code == http.StatusBadRequest || code == http.StatusNotFound),
        fmt.Sprintf("err=%v code=%d", err, code))
}

// ---- Main -----------------------------------------------------------------

func main() {
    cfg := Config{
        AdminBase:  "http://localhost:8090",
        LookupBase: "http://localhost:8080",
    }

    flag.StringVar(&cfg.AdminBase, "admin", cfg.AdminBase, "Admin API base URL")
    flag.StringVar(&cfg.LookupBase, "lookup", cfg.LookupBase, "Lookup API base URL")
    flag.Parse()

    fmt.Println("=== open-blocklist functional tests ===")
    fmt.Printf("Admin:  %s\n", cfg.AdminBase)
    fmt.Printf("Lookup: %s\n", cfg.LookupBase)

    runTests(cfg)

    fmt.Printf("\n--- Results: %d passed, %d failed ---\n", passed, failed)

    if failed > 0 {
        os.Exit(1)
    }
}
