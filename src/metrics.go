// smtproxy - SMTP Proxy in Go / metrics routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "bufio"
    "fmt"
    "net/http"
    "strconv"
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
        logMsg("Health Request [%s] : %v", gEndpointReady, healthy)
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
        logMsg("Ready Request [%s] : %v", gEndpointReady, ready)
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
        logMsg("Live Request [%s] : %v", gEndpointLive, alive)
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
            logMsg("Metrics listener stopped: %v", err)
        }
    }()
}
