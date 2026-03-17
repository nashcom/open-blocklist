// smtproxy - SMTP Proxy in Go / metrics routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "bufio"
    "fmt"
    "net/http"
    "strconv"
    "strings"
    "runtime/metrics"
)

func writeMetricString(w *bufio.Writer, name string, help string, metricType string, value string, labels map[string]string) {

    w.WriteString("# HELP ")
    w.WriteString(name)
    w.WriteByte(' ')
    w.WriteString(help)
    w.WriteByte('\n')

    w.WriteString("# TYPE ")
    w.WriteString(name)
    w.WriteByte(' ')
    w.WriteString(metricType)
    w.WriteByte('\n')

    w.WriteString(name)

    if len(labels) > 0 {
        w.WriteByte('{')

        first := true
        for k, v := range labels {
            if !first {
                w.WriteByte(',')
            }

            w.WriteString(k)
            w.WriteString(`="`)
            w.WriteString(v)
            w.WriteByte('"')

            first = false
        }

        w.WriteByte('}')
    }

    w.WriteByte(' ')
    w.WriteString(value)
    w.WriteByte('\n')
}

func writeMetric(w *bufio.Writer, name string, help string, metricType string, value int64, labels map[string]string) {

    writeMetricString(
        w,
        name,
        help,
        metricType,
        strconv.FormatInt(value, 10),
        labels,
    )
}

func writeMetricFloat(w *bufio.Writer, name string, help string, metricType string, value float64, labels map[string]string) {

    writeMetricString(
        w,
        name,
        help,
        metricType,
        strconv.FormatFloat(value, 'f', -1, 64),
        labels,
    )
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {

    stats.MetricsRequests.Add(1)

    w.Header().Set("Content-Type", "text/plain; version=0.0.4")
    bw := bufio.NewWriter(w)

    writeMetric(
        bw,
        "open-blocklist_build",
        fmt.Sprintf("Build number (version %s, platform %s)", gVersionStr, gBuildPlatform),
        "gauge",
        VersionBuild,
        nil)

    writeMetric(
        bw,
        "open-blocklist_go_build",
        fmt.Sprintf("Go runtime build number (%s)", gGoVersion),
        "gauge",
        gGoVersionBuild,
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_lookup_total",
        "Total lookup requests",
        "counter",
        stats.RequestsLookup.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_auth_total",
        "Total authentication requests",
        "counter",
        stats.RequestsAuth.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_put_total",
        "Total PUT requests",
        "counter",
        stats.RequestsPut.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_delete_total",
        "Total DELETE requests",
        "counter",
        stats.RequestsDelete.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_list_total",
        "Total list requests",
        "counter",
        stats.RequestsList.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_health_total",
        "Total health check requests",
        "counter",
        stats.RequestsHealth.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_requests_write_active",
        "Current active write requests",
        "gauge",
        stats.RequestsWriteActive.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_config_errors_total",
        "Total configuration errors detected during startup or reload",
        "counter",
        stats.ConfigErrors.Load(),
        nil)

    // DNS stats

    writeMetric(
        bw,
        "open-blocklist_dns_invalid_query_total",
        "Total invalid DNS queries",
        "counter",
        stats.ReqDnsInvalidQuery.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_dns_wrong_zone_total",
        "Total DNS queries outside RBL zone",
        "counter",
        stats.ReqDnsWrongZone.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_dns_blocked_total",
        "Total DNS queries resulting in a block",
        "counter",
        stats.ReqDnsBlocked.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_dns_not_listed_total",
        "Total DNS queries not listed (NXDOMAIN)",
        "counter",
        stats.ReqDnsNotListed.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_dns_other_query_type_total",
        "Total DNS queries with unsupported query types",
        "counter",
        stats.ReqDnsOtherQueryType.Load(),
        nil)

    // Endpoint stats

    writeMetric(
        bw,
        "open-blocklist_metrics_requests_total",
        "Total requests to endpoint "+ gEndpointMetrics,
        "counter",
        stats.MetricsRequests.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_invalid_endpoint_requests_total",
        "Total requests to unknown endpoints",
        "counter",
        stats.InvalidEndpointRequests.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_health_probe_success_total",
        "Total successful "+gEndpointHealth+" probe requests",
        "counter",
        stats.HealthSuccess.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_health_probe_failure_total",
        "Total failed "+gEndpointHealth+" probe requests",
        "counter",
        stats.HealthFailure.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_liveness_probe_success_total",
        "Total successful "+gEndpointLive+" probe requests",
        "counter",
        stats.LivenessSuccess.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_liveness_probe_failure_total",
        "Total failed "+gEndpointLive+" probe requests",
        "counter",
        stats.LivenessFailure.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_readiness_probe_success_total",
        "Total successful "+gEndpointReady+" probe requests",
        "counter",
        stats.ReadinessSuccess.Load(),
        nil)

    writeMetric(
        bw,
        "open-blocklist_readiness_probe_failure_total",
        "Total failed "+gEndpointReady+" probe requests",
        "counter",
        stats.ReadinessFailure.Load(),
        nil)

    writeRuntimeMetrics(bw)

    bw.Flush()
}

// Simple check for now always OK

func healthCheck() (bool){

    return true
}

func readyCheck() (bool){

    return true
}

func aliveCheck() (bool){

    return true
}

func healthHandler(w http.ResponseWriter, r *http.Request) {

    healthy := healthCheck()

    if gLogLevel >= LOG_DEBUG {
        logMsg(LOG_DEBUG, "Health Request [%s] : %v", gEndpointReady, healthy)
    }

    if healthy {
        stats.HealthSuccess.Add(1)
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("ready"))

    } else {
        stats.HealthFailure.Add(1)
        http.Error(w, fmt.Sprintf("not healthy"), http.StatusServiceUnavailable)
    }
}

func readyHandler(w http.ResponseWriter, r *http.Request) {

    ready := readyCheck()

    if gLogLevel >= LOG_DEBUG {
        logMsg(LOG_DEBUG, "Ready Request [%s] : %v", gEndpointReady, ready)
    }

    if ready {
        stats.ReadinessSuccess.Add(1)
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("ready"))

    } else {
        stats.ReadinessFailure.Add(1)
        http.Error(w, fmt.Sprintf("not ready"), http.StatusServiceUnavailable)
    }
}

func liveHandler(w http.ResponseWriter, r *http.Request) {

    alive := aliveCheck();

    if gLogLevel >= LOG_DEBUG {
        logMsg(LOG_DEBUG, "Live Request [%s] : %v", gEndpointLive, alive)
    }

    if alive {
        stats.LivenessSuccess.Add(1)
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("alive"))

    } else {
        stats.LivenessFailure.Add(1)
        http.Error(w, fmt.Sprintf("not alive"), http.StatusServiceUnavailable)
    }
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
    stats.InvalidEndpointRequests.Add(1)
    http.NotFound(w, r)
}

func startMetricsListener(addr string) {

    mux := http.NewServeMux()

    mux.HandleFunc(gEndpointMetrics, metricsHandler)
    mux.HandleFunc(gEndpointHealth,  healthHandler)
    mux.HandleFunc(gEndpointLive,    liveHandler)
    mux.HandleFunc(gEndpointReady,   readyHandler)
    mux.HandleFunc("/",              notFoundHandler)


    go func() {
        logListerner(gEndpointMetrics, addr)

        err := http.ListenAndServe(addr, mux)
        if err != nil {
            logMsg(LOG_INFO, "Metrics listener stopped: %v", err)
        }
    }()
}


var runtimeMetricNames = []string{
    "/memory/classes/heap/objects:bytes",
    "/memory/classes/heap/free:bytes",
    "/memory/classes/heap/released:bytes",
    "/memory/classes/total:bytes",

    "/gc/cycles/total:gc-cycles",
    "/gc/heap/allocs:bytes",
    "/gc/heap/frees:bytes",

    "/sched/goroutines:goroutines",

    "/cpu/classes/user:cpu-seconds",
    "/cpu/classes/system:cpu-seconds",
    "/cpu/classes/gc:cpu-seconds",
}

var runtimeSamples []metrics.Sample

func initRuntimeMetrics() {
    runtimeSamples = make([]metrics.Sample, len(runtimeMetricNames))

    for i, n := range runtimeMetricNames {
        runtimeSamples[i].Name = n
    }
}

func writeRuntimeMetrics(bw *bufio.Writer) {
    if runtimeSamples == nil {
        initRuntimeMetrics()
    }

    metrics.Read(runtimeSamples)

    for _, s := range runtimeSamples {
        name := sanitizeMetricName(s.Name)

        switch s.Value.Kind() {

        case metrics.KindUint64:

            writeMetric(
                bw,
                "go_"+name,
                "Go runtime metric "+s.Name,
                "gauge",
                int64 (s.Value.Uint64()),
                nil)

        case metrics.KindFloat64:

            writeMetricFloat(
                bw,
                "go_"+name,
                "Go runtime metric "+s.Name,
                "gauge",
                s.Value.Float64(),
                nil)

        }
    }
}


func sanitizeMetricName(n string) string {
    n = strings.ReplaceAll(n, "/", "_")
    n = strings.ReplaceAll(n, ":", "_")
    n = strings.ReplaceAll(n, "-", "_")
    return n
}

