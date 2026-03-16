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

type LogLevel    int

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
    VersionMinor = 0
    VersionPatch = 9

    VersionBuild int64 = VersionMajor*10000 + VersionMinor*100 + VersionPatch

    copyright = "Copyright 2026 Nash!Com/Daniel Nashed. All rights reserved."

    skyPrefix       = "/skydns"
    rblZone         = "open-blocklist"
    defaultSource   = "open-blocklist"
    defaultReturn   = "127.0.0.2"
    reverseHost     = "blocked.internal"

    env_openbl_LookupListenAddr    = "OPENBL_LOOKUP_LISTEN_ADDR"
    env_openbl_ApiListenAddr       = "OPENBL_API_LISTEN_ADDR"
    env_openbl_MetricsListenAddr   = "OPENBL_METRICS_LISTEN_ADDR"
    env_openbl_EtcEndpoint         = "OPENBL_ETCD_ENDPOINT"
    env_openbl_LogLevel            = "OPENBL_LOGLEVEL"
    env_openbl_LogJSON             = "OPENBL_LOGJSON"
    env_openbl_MultiInstanceMode   = "OPENBL_MULTI_INSTANCE_MODE"

    defaultLogJSON                 = false
    defaultMultiInstance           = true
    defaultLookupListenAddr        = ":8080"
    defaultApiListenAddr           = ":8090"
    defaultMetricsAddr             = ":9100"
    defaultLogLevel                = LOG_ERROR
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

    rblPrefix          = fmt.Sprintf("%s/internal/%s", skyPrefix, rblZone)
    rblPrefixScan      = rblPrefix + "/"
    gExpCheckInterval  = 1 * time.Minute

    gLogJSON            bool
    gShutdownRequested  bool
    gMetricListnerAddr  string
    gLogLevel           LogLevel
    gEtcdRevision       atomic.Int64

    gEndpointMetrics   = "/metrics"
    gEndpointHealth    = "/healthz"
    gEndpointLive      = "/livez"
    gEndpointReady     = "/readyz"

    gLookupListenAddr  = ":8080"
    gApiListenAddr     = ":8090"
    gEtcdEndpoint      = defaultEtcEndpoint

)

type EtcdKV struct {
    Key   string `json:"key"`
    Value string `json:"value"`
}

type DNSRecord struct {
    Version    int    `json:"v"`
    Host       string `json:"host"`
    TTL        int    `json:"ttl"`
    Source     string `json:"source"`
    FirstSeen  int64  `json:"first_seen"`
    Expiration int64  `json:"expiration"`
}

type PTRRecord struct {
    Host string `json:"host"`
    TTL  int    `json:"ttl"`
}

type BlockEntry struct {
    IP         string
    Source     string
    ReturnCode string
    FirstSeen  int64
    Expiration int64
}

type Store struct {
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
}

var stats Stats

var store = Store{
    entries: make(map[string]*BlockEntry),
}

func entryToMap(entry *BlockEntry) map[string]interface{} {

    return map[string]interface{}{
        "ip": entry.IP,
        "source": entry.Source,

        "first_seen"        : entry.FirstSeen,
        "first_seen_iso"    : epochToISO(entry.FirstSeen),

        "expiration"        : entry.Expiration,
        "expiration_iso"    : epochToISO(entry.Expiration),

        "remaining_seconds" : remainingSeconds(entry.Expiration),
        "remaining_duration": remainingDuration(entry.Expiration),

        "return_code": entry.ReturnCode,
    }
}

func handleLookup(w http.ResponseWriter, r *http.Request) {

    stats.RequestsLookup.Add(1)

    ip := r.PathValue("ip")

    entry, blocked := lookup(ip)

    if !blocked {

        w.Header().Set("X-Blocklist-Status", "clean")
        w.WriteHeader(http.StatusNoContent)
        return
    }

    if r.Method == "HEAD" {

        w.Header().Set("X-Service",                      "open-blocklist")
        w.Header().Set("X-Blocklist-IP",                 entry.IP)
        w.Header().Set("X-Blocklist-Source",             entry.Source)
        w.Header().Set("X-Blocklist-Return",             entry.ReturnCode)

        w.Header().Set("X-Blocklist-First-Seen",         fmt.Sprintf("%d", entry.FirstSeen))
        w.Header().Set("X-Blocklist-First-Seen-ISO",     epochToISO(entry.FirstSeen))

        w.Header().Set("X-Blocklist-Expiration",         fmt.Sprintf("%d", entry.Expiration))
        w.Header().Set("X-Blocklist-Expiration-ISO",     epochToISO(entry.Expiration))

        w.Header().Set("X-Blocklist-Remaining-Seconds",  fmt.Sprintf("%d", remainingSeconds(entry.Expiration)))
        w.Header().Set("X-Blocklist-Remaining-Duration", remainingDuration(entry.Expiration))

        w.Header().Set("X-Blocklist-Status", "blocked")

        return
    }

    format := r.URL.Query().Get("format")

    if format == "text" {

        w.Header().Set("Content-Type", "text/plain")

        fmt.Fprintf(w,
            "blocked=true\nip=%s\nsource=%s\nfirst_seen=%d\nfirst_seen_iso=%s\nexpiration=%d\nexpiration_iso=%s\nremaining_seconds=%d\nremaining_duration=%s\n",
            entry.IP,
            entry.Source,
            entry.FirstSeen,
            epochToISO(entry.FirstSeen),
            entry.Expiration,
            epochToISO(entry.Expiration),
            remainingSeconds(entry.Expiration),
            remainingDuration(entry.Expiration))

        return
    }

    w.Header().Set("Content-Type", "application/json")

    resp := entryToMap(entry)
    resp["blocked"] = true

    json.NewEncoder(w).Encode(resp)
}

func handleAuth(w http.ResponseWriter, r *http.Request) {

    stats.RequestsAuth.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    ip := r.PathValue("ip")

    _, blocked := lookup(ip)

    if blocked {
        w.WriteHeader(http.StatusForbidden)
        return
    }

    w.WriteHeader(http.StatusNoContent)
}

func handlePut(w http.ResponseWriter, r *http.Request) {

    stats.RequestsPut.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    w.Header().Set("Content-Type", "application/json")

    ipstr := r.PathValue("ip")

    ip := net.ParseIP(ipstr)
    if ip == nil {
        http.Error(w, "Invalid ip", http.StatusBadRequest)
        return
    }

    now := time.Now().Unix()

    entry := BlockEntry{
        IP:         ipstr,
        Source:     defaultSource,
        ReturnCode: defaultReturn,
        FirstSeen:  now,
    }

    q := r.URL.Query()

    for k := range q {
        if !allowedPutParams[k] {
            http.Error(w, "Invalid parameter: "+k, http.StatusBadRequest)
            return
        }
    }

    if q.Get("duration") != "" && q.Get("expiration") != "" {
        http.Error(w, "Duration and expiration cannot be used together", http.StatusBadRequest)
        return
    }

    if v := q.Get("source"); v != "" {
        entry.Source = v
    }

    if v := q.Get("return_code"); v != "" {
        entry.ReturnCode = v
    }

    if v := q.Get("duration"); v != "" {
        d, err := time.ParseDuration(v)
        if err != nil {
            http.Error(w, "Invalid duration", http.StatusBadRequest)
            return
        }

        entry.Expiration = now + int64(d/time.Second)
    }

    if v := q.Get("expiration"); v != "" {
        t, err := time.Parse(time.RFC3339, v)
        if err != nil {
            http.Error(w, "Invalid expiration timestamp", http.StatusBadRequest)
            return
        }

        entry.Expiration = t.Unix()
    }

    rbl := rblKey(ip)
    ptr := reverseKey(ip)

    rblRecord := DNSRecord{
        Version:    1,
        Host:       entry.ReturnCode,
        TTL:        300,
        Source:     entry.Source,
        FirstSeen:  entry.FirstSeen,
        Expiration: entry.Expiration,
    }

    ptrRecord := PTRRecord{
        Host: reverseHost,
        TTL:  300,
    }

    etcdPut(rbl, rblRecord)
    etcdPut(ptr, ptrRecord)

    if gMultiInstanceMode == false {
        store.Lock()
        store.entries[ipstr] = &entry
        store.Unlock()
    }

    json.NewEncoder(w).Encode(entry)
}

func handleDelete(w http.ResponseWriter, r *http.Request) {

    stats.RequestsDelete.Add(1)
    stats.RequestsWriteActive.Add(1)
    defer stats.RequestsWriteActive.Add(-1)

    ipstr := r.PathValue("ip")

    ip := net.ParseIP(ipstr)

    if ip == nil {
        http.Error(w, "Invalid ip", 400)
        return
    }

    rbl := rblKey(ip)
    ptr := reverseKey(ip)

    etcdDelete(rbl)
    etcdDelete(ptr)

    if gMultiInstanceMode == false {
        store.Lock()
        delete(store.entries, ipstr)
        store.Unlock()
    }

    w.WriteHeader(http.StatusNoContent)
}

func handleList(w http.ResponseWriter, r *http.Request) {
    stats.RequestsList.Add(1)

    w.Header().Set("Content-Type", "application/json")

    store.RLock()
    defer store.RUnlock()

    if len(store.entries) == 0 {
        w.Write([]byte("{}"))
        return
    }

    result := make([]map[string]interface{}, 0, len(store.entries))

    for _, entry := range store.entries {
        result = append(result, entryToMap(entry))
    }

    json.NewEncoder(w).Encode(result)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {

    stats.RequestsHealth.Add(1)

    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}


func expirationWorker() {

    ticker := time.NewTicker(gExpCheckInterval)

    for {

        <-ticker.C

        now := time.Now().Unix()

        var expired []string

        store.RLock()

        for ip, entry := range store.entries {

            if entry.Expiration > 0 && entry.Expiration <= now {
                expired = append(expired, ip)
            }
        }

        store.RUnlock()

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

            store.Lock()
            delete(store.entries, ipstr)
            store.Unlock()

            logMsg("Expired block removed: %s", ipstr)
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

func startReadListener(addr string) {

    mux := http.NewServeMux()

    RegisterReadHandler (mux)

    go func() {
        logListerner("Lookup", addr)

        err := http.ListenAndServe(addr, mux)
        if err != nil {
            logMsg("Lookup listener stopped: %v", err)
        }
    }()
}

func startWriteListener(addr string) {

    mux := http.NewServeMux()

    RegisterReadHandler (mux)
    RegisterWriteHandler (mux)


    go func() {
        logListerner("API", addr)
        err := http.ListenAndServe(addr, mux)
        if err != nil {
            logMsg("API Listener stopped: %v", err)
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
            logMsg("SIGHUP received - Reloading configuration")
            /* LATER ... */

        case syscall.SIGINT, syscall.SIGTERM:
            logMsg("Shutdown signal received: %v", sig)
            shutdown()
            os.Exit(0)
        }
    }
}

func shutdown() {

    logLine("Shutting down ...")
    gShutdownRequested = true

    time.Sleep(time.Second)

    logLine("Shutdown completed")
}

func main() {

    // Have full control over logging
    log.SetFlags(0)

    // Always read this first
    gMultiInstanceMode = getEnvBool     (env_openbl_MultiInstanceMode, defaultMultiInstance)
    gLogJSON           = getEnvBool     (env_openbl_LogJSON, defaultLogJSON)
    gLogLevel          = getEnvLogLevel (env_openbl_LogLevel, defaultLogLevel)
    gMetricListnerAddr = getEnv         (env_openbl_MetricsListenAddr, defaultMetricsAddr)
    gEtcdEndpoint      = getEnv         (env_openbl_EtcEndpoint, defaultEtcEndpoint)

    var printVersion  = flag.Bool("version",   false, "print version")
    var showGoVersion = flag.Bool("goversion", false, "show the go runtime version")

    flag.Parse()

    if *printVersion {
        logMsg("%s", gVersionStr)
        return
    }

    logSpace()

    if *showGoVersion {
        showRuntimeInfo()
        return
    }

    logSpace()
    logMsg("Open-Blocklist V%s", gVersionStr)
    logMsg("%s", dashLine(25))
    logSpace()

    logMsg("%s", copyright)
    logSpace()
    logSpace()

    showCfg("Description", "Variable", "Default", "Current")
    logMsg("%s", dashLine(160))

    logLevelValues := fmt.Sprintf("%s|%s|%s|%s|%s", LOG_NONE, LOG_ERROR, LOG_INFO, LOG_VERBOSE, LOG_DEBUG)

    showCfg("Lookup   listen address",      env_openbl_LookupListenAddr,  formatStr(defaultLookupListenAddr), gLookupListenAddr)
    showCfg("API      listen address",      env_openbl_ApiListenAddr,     formatStr(defaultApiListenAddr),    gApiListenAddr)
    showCfg("Metrics  listen address",      env_openbl_MetricsListenAddr, formatStr(defaultMetricsAddr),      gMetricListnerAddr)
    showCfg("etcd endpoint URL",            env_openbl_EtcEndpoint,       formatStr(defaultEtcEndpoint),      gEtcdEndpoint)
    showCfg("Multi instance mode",          env_openbl_MultiInstanceMode, defaultMultiInstance,               gMultiInstanceMode)
    showCfg(logLevelValues,                 env_openbl_LogLevel,          defaultLogLevel,                    gLogLevel)
    showCfg("Log output is in JSON format", env_openbl_LogJSON,           defaultLogJSON,                     gLogJSON)

    showRuntimeInfo()
    logSpace()

    go handleSignals()

    waitForEtcd (gEtcdEndpoint, 2 * time.Minute)

     // Load existing data
    loadFromEtcd()

    logSpace()

    go expirationWorker()

    if gMultiInstanceMode {
        logMsg("Running in multi-instance mode (watch enabled)")
        startEtcWatcher()

    } else {
        logMsg("Running in single-instance mode")
    }

    startReadListener(gLookupListenAddr)
    startWriteListener(gApiListenAddr)

    if gMetricListnerAddr != "" {
        startMetricsListener(gMetricListnerAddr)
    }

    select {}
}
