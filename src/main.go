// open-blocklist - An open blocklist tool
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type LogLevel int

const (
    LOG_NONE LogLevel = iota
    LOG_ERROR
    LOG_INFO
    LOG_VERBOSE
    LOG_DEBUG
)

func (l LogLevel) String() string {

    switch l {

    case LOG_NONE:
        return "NONE"

    case LOG_ERROR:
        return "ERROR"

    case LOG_INFO:
        return "INFO"

    case LOG_VERBOSE:
        return "VERBOSE"

    case LOG_DEBUG:
        return "DEBUG"

    default:
        return "UNKNOWN"
    }
}

func ParseLogLevel(s string) (LogLevel, error) {

    switch strings.ToLower(strings.TrimSpace(s)) {

    case "none":
        return LOG_NONE, nil

    case "error":
        return LOG_ERROR, nil

    case "info":
        return LOG_INFO, nil

    case "verbose":
        return LOG_VERBOSE, nil

    case "debug":
        return LOG_DEBUG, nil
    }

    return LOG_NONE, fmt.Errorf("Invalid log level: %s", s)
}

const (
    VersionMajor = 0
    VersionMinor = 8
    VersionPatch = 0

    VersionBuild int64 = VersionMajor*10000 + VersionMinor*100 + VersionPatch

    COPYRIGHT = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."

    SKY_DNS_PREFIX  = "/skydns"
    OPEN_BLOCK_LIST = "open-blocklist"
    RBL_ZONE        = "open-blocklist"

    HTTP_HEADER_X_SERVICE    = "X-Service"
    HTTP_HEADER_CONTENT_TYPE = "Content-Type"
    HTTP_METHOD_HEAD         = "HEAD"

    HTTP_CONTENT_TYPE_TEXT_PLAIN = "text/plain"
    HTTP_CONTENT_TYPE_APPL_JSON  = "application/json"

    env_openbl_LookupListenAddr  = "OPENBL_LOOKUP_LISTEN_ADDR"
    env_openbl_ApiListenAddr     = "OPENBL_API_LISTEN_ADDR"
    env_openbl_DNSListenAddr     = "OPENBL_DNS_LISTEN_ADDR"
    env_openbl_MetricsListenAddr = "OPENBL_METRICS_LISTEN_ADDR"
    env_openbl_EtcEndpoint       = "OPENBL_ETCD_ENDPOINT"
    env_openbl_LogLevel          = "OPENBL_LOGLEVEL"
    env_openbl_LogFileName       = "OPENBL_LOG_FILENAME"
    env_openbl_LogJSON           = "OPENBL_LOGJSON"
    env_openbl_MultiInstanceMode = "OPENBL_MULTI_INSTANCE_MODE"

    defaultSource            = "openbl"
    defaultReturn            = "127.0.0.2"
    defaultLogJSON           = false
    defaultMultiInstance     = true
    defaultLookupListenAddr  = ":8090"
    defaultApiListenAddr     = ":8091"
    defaultMetricsListenAddr = ":9100"
    defaultDNSListenAddr     = ":5353"
    defaultLogLevel          = LOG_INFO
    defaultEtcEndpoint       = "http://etcd:2379"
)

// Declared to overwrite by build
var gBuildPlatform = "unknown"

var allowedPutParams = map[string]bool{
    "duration":    true,
    "expiration":  true,
    "source":      true,
    "return_code": true,
    "scenario":    true,
    "action":      true,
    "last_seen":   true,
}

var (
    logWriter = os.Stdout // default

    gVersionStr     = fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)
    gGoVersion      = runtime.Version()
    gGoVersionBuild = parseGoVersionBuild(gGoVersion)

    gMultiInstanceMode = true

    rblPrefix         = fmt.Sprintf("%s/internal/%s", SKY_DNS_PREFIX, RBL_ZONE)
    rblPrefixScan     = rblPrefix + "/"
    gExpCheckInterval = 1 * time.Minute

    gLogJSON           bool
    gShutdownRequested bool
    gLogLevel          LogLevel
    gEtcdRevision      atomic.Int64

    gLogFilePath      string
    gLookupListenAddr string
    gApiListenAddr    string
    gDNSListenAddr    string
    gMetricListnAddr  string

    gProfileListener = ":6060"
    gReverseHost     = "blocked.internal"
    gPtrTTL          = 120
    gRecordTTL       = 120
    gRBLZone         = "open-blocklist.internal."

    gEndpointMetrics = "/metrics"
    gEndpointHealth  = "/healthz"
    gEndpointLive    = "/livez"
    gEndpointReady   = "/readyz"

    gEtcdEndpoint = defaultEtcEndpoint
)

type EtcdKV struct {
    Key            string `json:"key"`
    Value          string `json:"value"`
    CreateRevision string `json:"create_revision"`
    ModRevision    string `json:"mod_revision"`
    Version        string `json:"version"`
}

// BlockRecord is the etcd persistence format for a blocked IP.
// CreateRevision and ModRevision are managed by etcd — they are
// populated from the KV envelope on read and never written to JSON.
type BlockRecord struct {
    Version    int    `json:"v"`
    TTL        int    `json:"ttl,omitempty"`
    Host       string `json:"host,omitempty"`
    Source     string `json:"source,omitempty"`
    Scenario   string `json:"scenario,omitempty"`
    Action     string `json:"action,omitempty"`
    FirstSeen  int64  `json:"first_seen,omitempty"`
    LastSeen   int64  `json:"last_seen,omitempty"`
    Expiration int64  `json:"expiration,omitempty"`
    CreateRevision int64 `json:"-"`
    ModRevision    int64 `json:"-"`
}

type PTRRecord struct {
    Host string `json:"host"`
    TTL  int    `json:"ttl"`
}

type BlockEntry struct {
    IP             string // LATER: have IPv4 and IPv6 table. have the IPv4 table use a uint32 and the IPv6 table a type with two uint64
    Source         string
    Scenario       string
    Action         string
    CreateRevision int64
    ModRevision    int64
    FirstSeen      int64
    LastSeen       int64
    Expiration     int64
    ReturnCode     uint32
}

type ipTableStore struct {
    sync.RWMutex
    entries map[string]*BlockEntry
}

type Stats struct {

    RequestsLookup          atomic.Int64
    RequestsAuth            atomic.Int64
    RequestsPut             atomic.Int64
    RequestsDelete          atomic.Int64
    RequestsList            atomic.Int64
    RequestsHealth          atomic.Int64
    MetricsRequests         atomic.Int64
    RequestsWriteActive     atomic.Int64

    InvalidEndpointRequests atomic.Int64
    ConfigErrors            atomic.Int64

    HealthSuccess           atomic.Int64
    HealthFailure           atomic.Int64
    LivenessSuccess         atomic.Int64
    LivenessFailure         atomic.Int64
    ReadinessFailure        atomic.Int64
    ReadinessSuccess        atomic.Int64

    ReqDnsInvalidQuery      atomic.Int64
    ReqDnsWrongZone         atomic.Int64
    ReqDnsBlocked           atomic.Int64
    ReqDnsNotListed         atomic.Int64
    ReqDnsOtherQueryType    atomic.Int64
    LogDropped              atomic.Int64
}

var stats Stats

var ipTable = ipTableStore{
    entries: make(map[string]*BlockEntry),
}

func ipTableLookup(ip string) (*BlockEntry, bool) {

    ipTable.RLock()
    entry, ok := ipTable.entries[ip]
    ipTable.RUnlock()

    if !ok || entry == nil {
        return nil, false
    }

    if entry.Expiration > 0 && entry.Expiration <= time.Now().Unix() {
        go deleteExpiredIP(ip)
        return nil, false
    }

    return entry, true
}

func deleteExpiredIP(ipstr string) {

    parsed := net.ParseIP(ipstr)
    if parsed == nil {
        return
    }

    etcdDelete(rblKey(parsed))
    etcdDelete(reverseKey(parsed))

    if !gMultiInstanceMode {
        ipTable.Lock()
        delete(ipTable.entries, ipstr)
        ipTable.Unlock()
    }

    logMsg(LOG_INFO, "Lazy expiry: IP %s", ipstr)
}

func ipTableLen() int64 {

    ipTable.RLock()
    entryCount := len(ipTable.entries)
    ipTable.RUnlock()

    return int64(entryCount)
}

func entryToMap(entry *BlockEntry) map[string]interface{} {

    return map[string]interface{}{
        "ip":              entry.IP,
        "source":          entry.Source,
        "scenario":        entry.Scenario,
        "action":          entry.Action,
        "create_revision": entry.CreateRevision,
        "mod_revision":    entry.ModRevision,

        "first_seen":     entry.FirstSeen,
        "first_seen_iso": epochToISO(entry.FirstSeen),

        "last_seen":     entry.LastSeen,
        "last_seen_iso": epochToISO(entry.LastSeen),

        "expiration":     entry.Expiration,
        "expiration_iso": epochToISO(entry.Expiration),

        "remaining_seconds":  remainingSeconds(entry.Expiration),
        "remaining_duration": remainingDuration(entry.Expiration),

        "return_code": Uint32ToIPv4Str(entry.ReturnCode),
    }
}

func handleLookup(w http.ResponseWriter, r *http.Request) {

    const ReqType = "Lookup"
    start := time.Now()

    stats.RequestsLookup.Add(1)

    ip := r.PathValue("ip")

    if ip == "" || !IsValidIP(ip) {
        w.Header().Set("X-Blocklist-Status", "error")
        w.WriteHeader(http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }

    entry, blocked := ipTableLookup(ip)

    var matchedCIDR string
    if !blocked {
        if parsed := net.ParseIP(ip); parsed != nil {
            if cidrEntry := cidrTable.lookup(parsed); cidrEntry != nil {
                entry = cidrEntryToBlockEntry(cidrEntry)
                entry.IP = ip
                matchedCIDR = cidrEntry.CIDR
                blocked = true
            }
        }
    }

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)

    if r.Method == HTTP_METHOD_HEAD {

        if blocked && entry == nil {
            w.WriteHeader(http.StatusInternalServerError)
            logHttpReq(r, start, ReqType, "Error")
            return
        }

        if blocked {

            w.Header().Set("X-Blocklist-IP",                 entry.IP)
            w.Header().Set("X-Blocklist-CreateRevision",     fmt.Sprintf("%d", entry.CreateRevision))
            w.Header().Set("X-Blocklist-ModRevision",        fmt.Sprintf("%d", entry.ModRevision))
            w.Header().Set("X-Blocklist-Source",             entry.Source)
            w.Header().Set("X-Blocklist-Return",             Uint32ToIPv4Str(entry.ReturnCode))
            w.Header().Set("X-Blocklist-First-Seen",         fmt.Sprintf("%d", entry.FirstSeen))
            w.Header().Set("X-Blocklist-First-Seen-ISO",     epochToISO(entry.FirstSeen))
            w.Header().Set("X-Blocklist-Expiration",         fmt.Sprintf("%d", entry.Expiration))
            w.Header().Set("X-Blocklist-Expiration-ISO",     epochToISO(entry.Expiration))
            w.Header().Set("X-Blocklist-Remaining-Seconds",  fmt.Sprintf("%d", remainingSeconds(entry.Expiration)))
            w.Header().Set("X-Blocklist-Remaining-Duration", remainingDuration(entry.Expiration))

            if matchedCIDR != "" {
                w.Header().Set("X-Blocklist-Matched-CIDR", matchedCIDR)
            }

            w.Header().Set("X-Blocklist-Status", "blocked")

        } else {
            w.Header().Set("X-Blocklist-Status", "clean")
        }
    }

    if !blocked {
        w.WriteHeader(http.StatusNoContent)
        logHttpReq(r, start, ReqType, "NotBlocked")
        return
    }

    format := r.URL.Query().Get("format")

    if format == "text" {

        w.Header().Set(HTTP_HEADER_CONTENT_TYPE, HTTP_CONTENT_TYPE_TEXT_PLAIN)

        fmt.Fprintf(w,
            "blocked=true\nip=%s\ncreate_revision=%d\nmod_revision=%d\nsource=%s\nfirst_seen=%d\nfirst_seen_iso=%s\nexpiration=%d\nexpiration_iso=%s\nremaining_seconds=%d\nremaining_duration=%s\n",
            entry.IP,
            entry.CreateRevision,
            entry.ModRevision,
            entry.Source,
            entry.FirstSeen,
            epochToISO(entry.FirstSeen),
            entry.Expiration,
            epochToISO(entry.Expiration),
            remainingSeconds(entry.Expiration),
            remainingDuration(entry.Expiration))

        logHttpReq(r, start, ReqType, "Blocked")
        return
    }

    w.Header().Set(HTTP_HEADER_CONTENT_TYPE, HTTP_CONTENT_TYPE_APPL_JSON)

    resp := entryToMap(entry)
    resp["blocked"] = true
    if matchedCIDR != "" {
        resp["matched_cidr"] = matchedCIDR
    }

    json.NewEncoder(w).Encode(resp)

    logHttpReq(r, start, ReqType, "Blocked")
}

func handleAuth(w http.ResponseWriter, r *http.Request) {

    const ReqType = "Auth"

    start := time.Now()
    stats.RequestsAuth.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)

    ip := r.PathValue("ip")

    if ip == "" || !IsValidIP(ip) {
        w.WriteHeader(http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }

    _, blocked := ipTableLookup(ip)

    if !blocked {
        if parsed := net.ParseIP(ip); parsed != nil {
            blocked = cidrTable.lookup(parsed) != nil
        }
    }

    if blocked {
        w.WriteHeader(http.StatusForbidden)
        logHttpReq(r, start, ReqType, "Blocked")
        return
    }

    logHttpReq(r, start, ReqType, "NotBlocked")
    w.WriteHeader(http.StatusOK)
}

func handlePut(w http.ResponseWriter, r *http.Request) {

    const ReqType = "Put"

    start := time.Now()
    stats.RequestsPut.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)
    w.Header().Set(HTTP_HEADER_CONTENT_TYPE, HTTP_CONTENT_TYPE_APPL_JSON)

    ipstr := r.PathValue("ip")

    ip := net.ParseIP(ipstr)
    if ip == nil {
        http.Error(w, "Invalid ip", http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }

    now := time.Now().Unix()

    entry := BlockEntry{
        IP:         ipstr,
        Source:     defaultSource,
        Action:     "ban",
        ReturnCode: IPv4StrToUint32(defaultReturn),
        FirstSeen:  now,
        LastSeen:   now,
    }

    // Preserve first_seen if the IP is already blocked
    if existing, blocked := ipTableLookup(ipstr); blocked && existing != nil {
        entry.FirstSeen = existing.FirstSeen
    }

    q := r.URL.Query()

    for k := range q {
        if !allowedPutParams[k] {
            http.Error(w, "Invalid parameter: "+k, http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }
    }

    if q.Get("duration") != "" && q.Get("expiration") != "" {
        http.Error(w, "Duration and expiration cannot be used together", http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }

    if v := q.Get("source"); v != "" {
        entry.Source = v
    }

    if v := q.Get("scenario"); v != "" {
        entry.Scenario = v
    }

    if v := q.Get("action"); v != "" {
        entry.Action = v
    }

    if v := q.Get("return_code"); v != "" {
        entry.ReturnCode = IPv4StrToUint32(v)
    }

    if v := q.Get("last_seen"); v != "" {
        t, err := time.Parse(time.RFC3339, v)
        if err != nil {
            http.Error(w, "Invalid last_seen timestamp", http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }
        entry.LastSeen = t.Unix()
    }

    if v := q.Get("duration"); v != "" {
        d, err := time.ParseDuration(v)
        if err != nil {
            http.Error(w, "Invalid duration", http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }

        entry.Expiration = now + int64(d/time.Second)
    }

    if v := q.Get("expiration"); v != "" {
        t, err := time.Parse(time.RFC3339, v)
        if err != nil {
            http.Error(w, "Invalid expiration timestamp", http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }

        entry.Expiration = t.Unix()
    }

    rbl := rblKey(ip)
    ptr := reverseKey(ip)

    rblRecord := BlockRecord{
        Version:    1,
        Host:       Uint32ToIPv4Str(entry.ReturnCode),
        TTL:        gRecordTTL,
        Source:     entry.Source,
        Scenario:   entry.Scenario,
        Action:     entry.Action,
        FirstSeen:  entry.FirstSeen,
        LastSeen:   entry.LastSeen,
        Expiration: entry.Expiration,
    }

    ptrRecord := PTRRecord{
        Host: gReverseHost,
        TTL:  gPtrTTL,
    }

    etcdPut(rbl, rblRecord)
    etcdPut(ptr, ptrRecord)

    if gMultiInstanceMode == false {
        ipTable.Lock()
        ipTable.entries[ipstr] = &entry
        ipTable.Unlock()
    }

    json.NewEncoder(w).Encode(entry)
    logHttpReq(r, start, ReqType, "OK")
}

func handleDelete(w http.ResponseWriter, r *http.Request) {

    const ReqType = "Delete"

    start := time.Now()
    stats.RequestsDelete.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    ipstr := r.PathValue("ip")

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)

    ip := net.ParseIP(ipstr)

    if ip == nil {
        http.Error(w, "Invalid ip", 400)
        logHttpReq(r, start, ReqType, "Error")
        return
    }

    rbl := rblKey(ip)
    ptr := reverseKey(ip)

    etcdDelete(rbl)
    etcdDelete(ptr)

    if gMultiInstanceMode == false {
        ipTable.Lock()
        delete(ipTable.entries, ipstr)
        ipTable.Unlock()
    }

    w.WriteHeader(http.StatusNoContent)

    logHttpReq(r, start, ReqType, "OK")
}

func handlePutNetwork(w http.ResponseWriter, r *http.Request) {

    const ReqType = "PutNetwork"

    start := time.Now()
    stats.RequestsPut.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)
    w.Header().Set(HTTP_HEADER_CONTENT_TYPE, HTTP_CONTENT_TYPE_APPL_JSON)

    // Reconstruct CIDR from the two path segments: {net}/{prefix}
    cidrStr := r.PathValue("net") + "/" + r.PathValue("prefix")

    _, network, err := net.ParseCIDR(cidrStr)
    if err != nil {
        http.Error(w, "Invalid network: "+cidrStr, http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }
    cidr := network.String() // canonical form, e.g. "1.2.3.0/24"

    now := time.Now().Unix()

    entry := CIDREntry{
        CIDR:       cidr,
        Net:        network,
        Source:     defaultSource,
        Action:     "ban",
        ReturnCode: IPv4StrToUint32(defaultReturn),
        FirstSeen:  now,
        LastSeen:   now,
    }

    // Preserve first_seen if the network is already blocked.
    if existing := cidrTable.findByCIDR(cidr); existing != nil {
        entry.FirstSeen = existing.FirstSeen
    }

    q := r.URL.Query()

    for k := range q {
        if !allowedPutParams[k] {
            http.Error(w, "Invalid parameter: "+k, http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }
    }

    if q.Get("duration") != "" && q.Get("expiration") != "" {
        http.Error(w, "Duration and expiration cannot be used together", http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }

    if v := q.Get("source"); v != "" {
        entry.Source = v
    }
    if v := q.Get("scenario"); v != "" {
        entry.Scenario = v
    }
    if v := q.Get("action"); v != "" {
        entry.Action = v
    }
    if v := q.Get("return_code"); v != "" {
        entry.ReturnCode = IPv4StrToUint32(v)
    }
    if v := q.Get("last_seen"); v != "" {
        t, err := time.Parse(time.RFC3339, v)
        if err != nil {
            http.Error(w, "Invalid last_seen timestamp", http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }
        entry.LastSeen = t.Unix()
    }
    if v := q.Get("duration"); v != "" {
        d, err := time.ParseDuration(v)
        if err != nil {
            http.Error(w, "Invalid duration", http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }
        entry.Expiration = now + int64(d/time.Second)
    }
    if v := q.Get("expiration"); v != "" {
        t, err := time.Parse(time.RFC3339, v)
        if err != nil {
            http.Error(w, "Invalid expiration timestamp", http.StatusBadRequest)
            logHttpReq(r, start, ReqType, "Error")
            return
        }
        entry.Expiration = t.Unix()
    }

    rec := BlockRecord{
        Version:    1,
        Host:       Uint32ToIPv4Str(entry.ReturnCode),
        TTL:        gRecordTTL,
        Source:     entry.Source,
        Scenario:   entry.Scenario,
        Action:     entry.Action,
        FirstSeen:  entry.FirstSeen,
        LastSeen:   entry.LastSeen,
        Expiration: entry.Expiration,
    }

    etcdPutCIDR(cidr, rec)

    if !gMultiInstanceMode {
        cidrTable.upsert(&entry)
    }

    json.NewEncoder(w).Encode(cidrEntryToMap(&entry))
    logHttpReq(r, start, ReqType, "OK")
}

func handleDeleteNetwork(w http.ResponseWriter, r *http.Request) {

    const ReqType = "DeleteNetwork"

    start := time.Now()
    stats.RequestsDelete.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)

    cidrStr := r.PathValue("net") + "/" + r.PathValue("prefix")

    _, network, err := net.ParseCIDR(cidrStr)
    if err != nil {
        http.Error(w, "Invalid network: "+cidrStr, http.StatusBadRequest)
        logHttpReq(r, start, ReqType, "Error")
        return
    }
    cidr := network.String()

    etcdDeleteCIDR(cidr)

    if !gMultiInstanceMode {
        cidrTable.remove(cidr)
    }

    w.WriteHeader(http.StatusNoContent)
    logHttpReq(r, start, ReqType, "OK")
}

func handleList(w http.ResponseWriter, r *http.Request) {

    const ReqType = "List"

    start := time.Now()
    stats.RequestsList.Add(1)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)
    w.Header().Set(HTTP_HEADER_CONTENT_TYPE, HTTP_CONTENT_TYPE_APPL_JSON)

    ipTable.RLock()
    defer ipTable.RUnlock()

    if len(ipTable.entries) == 0 {
        w.Write([]byte("[]"))
        logHttpReq(r, start, ReqType, "OK")
        return
    }

    result := make([]map[string]interface{}, 0, len(ipTable.entries))

    for _, entry := range ipTable.entries {
        result = append(result, entryToMap(entry))
    }

    json.NewEncoder(w).Encode(result)

    logMsg(LOG_DEBUG, "[List-Req] %s %s %dms", r.Method, r.RequestURI, time.Since(start).Milliseconds())
}

func handleHealth(w http.ResponseWriter, r *http.Request) {

    stats.RequestsHealth.Add(1)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}

func expirationWorker() {

    ticker := time.NewTicker(gExpCheckInterval)

    for {

        <-ticker.C

        now := time.Now().Unix()

        var expired []string

        ipTable.RLock()

        for ip, entry := range ipTable.entries {

            if entry.Expiration > 0 && entry.Expiration <= now {
                expired = append(expired, ip)
            }
        }

        ipTable.RUnlock()

        for _, ipstr := range expired {

            ip := net.ParseIP(ipstr)
            if ip == nil {
                continue
            }

            rbl := rblKey(ip)
            ptr := reverseKey(ip)

            etcdDelete(rbl)
            etcdDelete(ptr)

            ipTable.Lock()
            delete(ipTable.entries, ipstr)
            ipTable.Unlock()

            logMsg(LOG_INFO, "Expired block removed: %s", ipstr)
        }

        var expiredCIDRs []string

        cidrTable.RLock()
        for _, e := range cidrTable.entries {
            if e.Expiration > 0 && e.Expiration <= now {
                expiredCIDRs = append(expiredCIDRs, e.CIDR)
            }
        }
        cidrTable.RUnlock()

        for _, cidr := range expiredCIDRs {
            etcdDeleteCIDR(cidr)
            cidrTable.remove(cidr)
            logMsg(LOG_INFO, "Expired CIDR block removed: %s", cidr)
        }
    }
}

func RegisterReadHandler(mux *http.ServeMux) {

    mux.HandleFunc("GET /lookup",       handleList)
    mux.HandleFunc("GET /lookup/{ip}",  handleLookup)
    mux.HandleFunc("HEAD /lookup/{ip}", handleLookup)
    mux.HandleFunc("GET /auth/{ip}",    handleAuth)
    mux.HandleFunc("HEAD /auth/{ip}",   handleAuth)
    mux.HandleFunc("GET /health",       handleHealth)

}

func RegisterWriteHandler(mux *http.ServeMux) {

    mux.HandleFunc("PUT /block/{ip}",                      handlePut)
    mux.HandleFunc("DELETE /block/{ip}",                   handleDelete)
    mux.HandleFunc("PUT /block-network/{net}/{prefix}",    handlePutNetwork)
    mux.HandleFunc("DELETE /block-network/{net}/{prefix}", handleDeleteNetwork)

}

func RegisterCatchAll(mux *http.ServeMux) {
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

        start := time.Now()

        logHttpReq(r, start, "Invalid", "NotFound")
        http.Error(w, "not found", http.StatusNotFound)
    })
}

func startLookupListener(addr string) {

    mux := http.NewServeMux()

    RegisterReadHandler(mux)
    RegisterCatchAll(mux)

    logListerner("Lookup", addr)

    if addr == "" {
        return
    }

    go func() {
        err := http.ListenAndServe(addr, mux)
        if err != nil {
            logMsg(LOG_INFO, "Lookup listener stopped: %v", err)
        }
    }()
}

func startApiListener(addr string) {

    logListerner("API", addr)

    if addr == "" {
        return
    }

    mux := http.NewServeMux()

    RegisterReadHandler(mux)
    RegisterWriteHandler(mux)
    RegisterCatchAll(mux)

    go func() {
        err := http.ListenAndServe(addr, mux)
        if err != nil {
            logMsg(LOG_INFO, "API Listener stopped: %v", err)
        }
    }()
}

func handleSignals() {

    sigChan := make(chan os.Signal, 1)

    signal.Notify(sigChan,
        syscall.SIGINT,
        syscall.SIGTERM,
        syscall.SIGHUP,
    )

    for {
        sig := <-sigChan

        switch sig {

        case syscall.SIGHUP:
            logMsg(LOG_INFO, "SIGHUP received - Reloading configuration")
            /* LATER ... */

        case syscall.SIGINT, syscall.SIGTERM:
            logMsg(LOG_INFO, "Shutdown signal received: %v", sig)
            shutdown()
            os.Exit(0)
        }
    }
}

func shutdown() {

    logMsg(LOG_INFO, "Shutting down ...")
    gShutdownRequested = true

    time.Sleep(time.Second)

    logMsg(LOG_INFO, "Shutdown completed")
}

func main() {

    // Have full control over logging
    log.SetFlags(0)

    // Always read this first
    gLogLevel           = getEnvLogLevel(env_openbl_LogLevel, defaultLogLevel)
    gMultiInstanceMode  = getEnvBool(env_openbl_MultiInstanceMode, defaultMultiInstance)
    gLogJSON            = getEnvBool(env_openbl_LogJSON, defaultLogJSON)
    initCrowdSec()
    gLogFilePath        = getEnv(env_openbl_LogFileName, "")
    gLookupListenAddr   = getEnv(env_openbl_LookupListenAddr, defaultLookupListenAddr)
    gApiListenAddr      = getEnv(env_openbl_ApiListenAddr, defaultApiListenAddr)
    gDNSListenAddr      = getEnv(env_openbl_DNSListenAddr, defaultDNSListenAddr)
    gMetricListnAddr    = getEnv(env_openbl_MetricsListenAddr, defaultMetricsListenAddr)
    gEtcdEndpoint       = getEnv(env_openbl_EtcEndpoint, defaultEtcEndpoint)

    var printVersion = flag.Bool("version", false, "print version")
    var showGoVersion = flag.Bool("goversion", false, "show the go runtime version")

    flag.Parse()

    if *printVersion {
        logMsg(LOG_INFO, "%s", gVersionStr)
        return
    }

    if gLogFilePath != "" {
        if err := LogSetFile(gLogFilePath); err != nil {
            logFatal("Cannot open log file: %v", err)
        }
    }

    initPprof()

    if !runUnitTests() {
        os.Exit(1)
    }

    logSpace()

    if *showGoVersion {
        showRuntimeInfo()
        return
    }

    logSpace()
    logMsg(LOG_INFO, "Open-Blocklist V%s", gVersionStr)
    logMsg(LOG_INFO, "%s", dashLine(25))
    logSpace()

    logMsg(LOG_INFO, "%s", COPYRIGHT)
    logSpace()
    logSpace()

    showCfg("Description", "Variable", "Default", "Current")
    logMsg(LOG_INFO, "%s", dashLine(160))

    logLevelValues := fmt.Sprintf("%s|%s|%s|%s|%s", LOG_NONE, LOG_ERROR, LOG_INFO, LOG_VERBOSE, LOG_DEBUG)

    showCfg("Lookup listen address", env_openbl_LookupListenAddr, formatStr(defaultLookupListenAddr), gLookupListenAddr)
    showCfg("API    listen address", env_openbl_ApiListenAddr, formatStr(defaultApiListenAddr), gApiListenAddr)
    showCfg("DNS    listen address", env_openbl_DNSListenAddr, formatStr(defaultDNSListenAddr), gDNSListenAddr)
    showCfg("Metricslisten address", env_openbl_MetricsListenAddr, formatStr(defaultMetricsListenAddr), gMetricListnAddr)
    showCfg("etcd endpoint URL",     env_openbl_EtcEndpoint, formatStr(defaultEtcEndpoint), gEtcdEndpoint)
    showCfg("Multi instance mode",   env_openbl_MultiInstanceMode, defaultMultiInstance, gMultiInstanceMode)
    showCfg(logLevelValues,          env_openbl_LogLevel, defaultLogLevel, gLogLevel)
    showCfg("Log File name",         env_openbl_LogFileName, "<STDOUT>", gLogFilePath)
    showCfg("Log output in JSON",    env_openbl_LogJSON, defaultLogJSON, gLogJSON)
    showCfg("CrowdSec enabled",      env_openbl_CrowdSecEnabled, false, gCrowdSecEnabled)
    showCfg("CrowdSec LAPI URL",     env_openbl_CrowdSecLAPIURL, defaultCrowdSecLAPIURL, gCrowdSecLAPIURL)
    showCfg("CrowdSec poll interval",env_openbl_CrowdSecPollInterval, "30s", gCrowdSecPollInterval)

    showRuntimeInfo()
    logSpace()

    go handleSignals()

    waitForEtcd(gEtcdEndpoint, 2*time.Minute)

    // Load existing data
    loadFromEtcd()
    loadCIDRFromEtcd()

    logSpace()

    startLookupListener(gLookupListenAddr)
    startApiListener(gApiListenAddr)
    startDNSListener(gDNSListenAddr)

    if gMetricListnAddr != "" {
        startMetricsListener(gMetricListnAddr)
    }

    time.Sleep(2 * time.Second)

    go expirationWorker()

    if gMultiInstanceMode {
        logMsg(LOG_INFO, "Running in multi-instance mode (watch enabled)")
        startEtcWatcher()
        startCIDRWatcher()
    } else {
        logMsg(LOG_INFO, "Running in single-instance mode")
    }

    startCrowdSecBouncer()

    select {}
}
