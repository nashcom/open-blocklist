// open-blocklist - An open blocklist tool
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "encoding/json"
    "fmt"
    "flag"
    "os"
    "log"
    "net"
    "os/signal"
    "net/http"
    "runtime"
    "strings"
    "syscall"
    "sync"
    "sync/atomic"
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

    COPYRIGHT                      = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."

    SKY_DNS_PREFIX                 = "/skydns"
    OPEN_BLOCK_LIST                = "open-blocklist"
    RBL_ZONE                       = "open-blocklist"

    HTTP_HEADER_X_SERVICE          = "X-Service"
    HTTP_HEADER_CONTENT_TYPE       = "Content-Type"
    HTTP_METHOD_HEAD               = "HEAD"

    HTTP_CONTENT_TYPE_TEXT_PLAIN   = "text/plain"
    HTTP_CONTENT_TYPE_APPL_JSON    = "application/json"

    env_openbl_LookupListenAddr    = "OPENBL_LOOKUP_LISTEN_ADDR"
    env_openbl_ApiListenAddr       = "OPENBL_API_LISTEN_ADDR"
    env_openbl_DNSListenAddr       = "OPENBL_DNS_LISTEN_ADDR"
    env_openbl_MetricsListenAddr   = "OPENBL_METRICS_LISTEN_ADDR"
    env_openbl_EtcEndpoint         = "OPENBL_ETCD_ENDPOINT"
    env_openbl_LogLevel            = "OPENBL_LOGLEVEL"
    env_openbl_LogJSON             = "OPENBL_LOGJSON"
    env_openbl_MultiInstanceMode   = "OPENBL_MULTI_INSTANCE_MODE"

    defaultSource                  = "openbl"
    defaultReturn                  = "127.0.0.2"
    defaultLogJSON                 = false
    defaultMultiInstance           = true
    defaultLookupListenAddr        = ":8080"
    defaultApiListenAddr           = ":8090"
    defaultMetricsListenAddr       = ":9100"
    defaultDNSListenAddr           = ":5353"
    defaultLogLevel                = LOG_INFO
    defaultEtcEndpoint             = "http://etcd:2379"
)

// Declared to overwrite by build
var gBuildPlatform = "unknown"

var allowedPutParams = map[string]bool{
    "duration":    true,
    "expiration":  true,
    "source":      true,
    "return_code": true,
}

var (

    gVersionStr        = fmt.Sprintf("%d.%d.%d", VersionMajor, VersionMinor, VersionPatch)
    gGoVersion         = runtime.Version()
    gGoVersionBuild    = parseGoVersionBuild(gGoVersion)

    gMultiInstanceMode = true

    rblPrefix          = fmt.Sprintf("%s/internal/%s", SKY_DNS_PREFIX, RBL_ZONE)
    rblPrefixScan      = rblPrefix + "/"
    gExpCheckInterval  = 1 * time.Minute

    gLogJSON            bool
    gShutdownRequested  bool
    gLogLevel           LogLevel
    gEtcdRevision       atomic.Int64

    gLookupListenAddr   string
    gApiListenAddr      string
    gDNSListenAddr      string
    gMetricListnAddr    string

    gReverseHost       = "blocked.internal"
    gPtrTTL            = 120
    gRecordTTL         = 120
    gRBLZone           = "open-blocklist.internal."

    gEndpointMetrics   = "/metrics"
    gEndpointHealth    = "/healthz"
    gEndpointLive      = "/livez"
    gEndpointReady     = "/readyz"

    gEtcdEndpoint      = defaultEtcEndpoint

)

type EtcdKV struct {
    Key            string `json:"key"`
    Value          string `json:"value"`
    CreateRevision string `json:"create_revision"`
    ModRevision    string `json:"mod_revision"`
    Version        string `json:"version"`
}

type DNSRecord struct {
    Version        int    `json:"v"`
    TTL            int    `json:"ttl"`
    FirstSeen      int64  `json:"first_seen"`
    Expiration     int64  `json:"expiration"`
    CreateRevision int64  `json:"create_revision"`
    ModRevision    int64  `json:"mod_revision"`
    Host           string `json:"host"`
    Source         string `json:"source"`
}

type DNSRecordPut struct {
    Version        int    `json:"v"`
    TTL            int    `json:"ttl"`
    FirstSeen      int64  `json:"first_seen"`
    Expiration     int64  `json:"expiration"`
    Host           string `json:"host"`
    Source         string `json:"source"`
}

type PTRRecord struct {
    Host string `json:"host"`
    TTL  int    `json:"ttl"`
}

type BlockEntry struct {
    IP             string // LATER: have IPv4 and IPv6 table. have the IPv4 table use a uint32 and the IPv6 table a type with two uint64
    Source         string // Should be short in which case string does not take a few bytes
    CreateRevision int64
    ModRevision    int64
    FirstSeen      int64
    Expiration     int64
    ReturnCode     uint32
}

type ipTableStore struct {
    sync.RWMutex
    entries map[string]*BlockEntry
}

type Stats struct
{
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
}

var stats Stats

var ipTable = ipTableStore{
    entries: make(map[string]*BlockEntry),
}

func ipTableLookup(ip string) (*BlockEntry, bool) {

    ipTable.RLock()
    entry, ok := ipTable.entries[ip]
    ipTable.RUnlock()

    return entry, ok
}

func ipTableLen() int64 {

    ipTable.RLock()
    entryCount := len(ipTable.entries)
    ipTable.RUnlock()

    return int64(entryCount)
}

func entryToMap(entry *BlockEntry) map[string]interface{} {

    return map[string]interface{}{
        "ip"                : entry.IP,
        "source"            : entry.Source,
        "create_revision"   : entry.CreateRevision,
        "mod_revision"      : entry.ModRevision,

        "first_seen"        : entry.FirstSeen,
        "first_seen_iso"    : epochToISO(entry.FirstSeen),

        "expiration"        : entry.Expiration,
        "expiration_iso"    : epochToISO(entry.Expiration),

        "remaining_seconds" : remainingSeconds(entry.Expiration),
        "remaining_duration": remainingDuration(entry.Expiration),

        "return_code"       : Uint32ToIPv4Str(entry.ReturnCode),
    }
}

func handleLookup(w http.ResponseWriter, r *http.Request) {

    const ReqType = "Lookup"
    start := time.Now()

    stats.RequestsLookup.Add(1)

    ip := r.PathValue("ip")
    entry, blocked := ipTableLookup(ip)

    w.Header().Set(HTTP_HEADER_X_SERVICE, OPEN_BLOCK_LIST)

    if r.Method == HTTP_METHOD_HEAD {

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

        if blocked {
            w.Header().Set("X-Blocklist-Status", "clean")
        } else {
            w.Header().Set("X-Blocklist-Status", "blocked")
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

    _, blocked := ipTableLookup(ip)

    if blocked {
        w.WriteHeader(http.StatusForbidden)
        logHttpReq(r, start, ReqType, "Blocked")
        return
    }

    logHttpReq(r, start, ReqType, "NotBlocked")
    w.WriteHeader(http.StatusNoContent)
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
        ReturnCode: FastIPv4StrToUint32(defaultReturn),
        FirstSeen:  now,
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

    if v := q.Get("return_code"); v != "" {
        entry.ReturnCode = FastIPv4StrToUint32(v)
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

    rblRecord := DNSRecordPut{
        Version:    1,
        Host:       Uint32ToIPv4Str(entry.ReturnCode),
        TTL:        gRecordTTL,
        Source:     entry.Source,
        FirstSeen:  entry.FirstSeen,
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

    logHttpReq(r, start, ReqType, "NotFound")
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
        w.Write([]byte("{}"))
        logHttpReq(r, start, ReqType, "Error")
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

        if len(expired) == 0 {
            continue
        }

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
    }
}

func RegisterReadHandler(mux *http.ServeMux) {

    mux.HandleFunc("GET /lookup",        handleList)
    mux.HandleFunc("GET /lookup/{ip}",   handleLookup)
    mux.HandleFunc("HEAD /lookup/{ip}",  handleLookup)
    mux.HandleFunc("GET /auth/{ip}",     handleAuth)
    mux.HandleFunc("HEAD /auth/{ip}",    handleAuth)
    mux.HandleFunc("GET /health",        handleHealth)

}

func RegisterWriteHandler(mux *http.ServeMux) {

    mux.HandleFunc("PUT /block/{ip}",    handlePut)
    mux.HandleFunc("DELETE /block/{ip}", handleDelete)

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

    RegisterReadHandler (mux)
    RegisterCatchAll    (mux)

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

    RegisterReadHandler  (mux)
    RegisterWriteHandler (mux)
    RegisterCatchAll     (mux)

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
    gLogLevel          = getEnvLogLevel (env_openbl_LogLevel,          defaultLogLevel)
    gMultiInstanceMode = getEnvBool     (env_openbl_MultiInstanceMode, defaultMultiInstance)
    gLogJSON           = getEnvBool     (env_openbl_LogJSON,           defaultLogJSON)
    gLookupListenAddr  = getEnv         (env_openbl_LogJSON,           defaultLookupListenAddr)
    gApiListenAddr     = getEnv         (env_openbl_ApiListenAddr,     defaultApiListenAddr)
    gDNSListenAddr     = getEnv         (env_openbl_DNSListenAddr,     defaultDNSListenAddr)
    gMetricListnAddr   = getEnv         (env_openbl_MetricsListenAddr, defaultMetricsListenAddr)
    gEtcdEndpoint      = getEnv         (env_openbl_EtcEndpoint,       defaultEtcEndpoint)

    var printVersion  = flag.Bool("version",   false, "print version")
    var showGoVersion = flag.Bool("goversion", false, "show the go runtime version")

    flag.Parse()

    if *printVersion {
        logMsg(LOG_INFO, "%s", gVersionStr)
        return
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

    showCfg("Lookup listen address",        env_openbl_LookupListenAddr,  formatStr(defaultLookupListenAddr),  gLookupListenAddr)
    showCfg("API    listen address",        env_openbl_ApiListenAddr,     formatStr(defaultApiListenAddr),     gApiListenAddr)
    showCfg("DNS    listen address",        env_openbl_DNSListenAddr,     formatStr(defaultDNSListenAddr),     gDNSListenAddr)
    showCfg("Metricslisten address",        env_openbl_MetricsListenAddr, formatStr(defaultMetricsListenAddr), gMetricListnAddr)
    showCfg("etcd endpoint URL",            env_openbl_EtcEndpoint,       formatStr(defaultEtcEndpoint),       gEtcdEndpoint)
    showCfg("Multi instance mode",          env_openbl_MultiInstanceMode, defaultMultiInstance,                gMultiInstanceMode)
    showCfg(logLevelValues,                 env_openbl_LogLevel,          defaultLogLevel,                     gLogLevel)
    showCfg("Log output is in JSON format", env_openbl_LogJSON,           defaultLogJSON,                      gLogJSON)

    showRuntimeInfo()
    logSpace()

    go handleSignals()

    waitForEtcd (gEtcdEndpoint, 2 * time.Minute)

     // Load existing data
    loadFromEtcd()

    logSpace()

    startLookupListener (gLookupListenAddr)
    startApiListener    (gApiListenAddr)
    startDNSListener    (gDNSListenAddr)

    if gMetricListnAddr != "" {
        startMetricsListener(gMetricListnAddr)
    }

    time.Sleep(2 * time.Second)

    go expirationWorker()

    if gMultiInstanceMode {
        logMsg(LOG_INFO, "Running in multi-instance mode (watch enabled)")
        startEtcWatcher()

    } else {
        logMsg(LOG_INFO, "Running in single-instance mode")
    }

    select {}
}
