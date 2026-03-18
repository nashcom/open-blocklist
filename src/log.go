//open-blocklist - An open blocklist tool - log routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "log"
    "fmt"
    "net/http"
    "os"
    "time"
    "github.com/miekg/dns"
)


func showCfg(description, variableName, defaultValue, currentValue any) {
    logMsg(LOG_INFO, "%-34s  %-40s %-40v  %v", variableName, description, defaultValue, currentValue)
}

func showInfo(description, currentValue any) {
    logMsg(LOG_INFO, "%-15s:  %v", description, currentValue)
}

func (l LogLevel) LowerCaseStr() string {

    switch l {

    case LOG_NONE:
        return "none"

    case LOG_ERROR:
        return "error"

    case LOG_INFO:
        return "info"

    case LOG_VERBOSE:
        return "verbose"

    case LOG_DEBUG:
        return "debug"

    default:
        return "unknown"
    }
}

func logLine(level LogLevel, msg string) {

    ts := time.Now().UTC().Format(time.RFC3339)

    if gLogJSON {
        log.Printf(`{"ts":"%s","type":"event","level":"%s","msg":%q}`, ts, level.LowerCaseStr(), msg)
        return
    }

    log.Println(ts + "   " + level.String() + ": " + msg)
}

func logSpace() {

    if gLogJSON {
        return
    }

    if gLogLevel < LOG_INFO {
        return
    }

    ts := time.Now().UTC().Format(time.RFC3339)
    log.Println(ts)
}

func logMsg(level LogLevel, format string, args ...any) {

    if level > gLogLevel {
        return
    }

    logLine(level, fmt.Sprintf(format, args ...))
}

func logFatal(format string, args ...any) {

    logLine(LOG_ERROR, fmt.Sprintf(format, args ...))
    os.Exit(1)
}

func logListerner(info string, addr string) {

    if addr == "" {
        // No listen address

    } else {
        logMsg (LOG_INFO, "Listening  [%-10s]  on %s", info, addr)
    }
}

func logHttpReq(r *http.Request, start time.Time, requestName string, status string) {

    duration := time.Since(start)
    ts := time.Now().UTC().Format(time.RFC3339)

    if gLogJSON {
        log.Printf(`{"ts":"%s","type":"http","request":%q,"method":%q,"uri":%q,"duration_seconds":%f,"status":%q}`,
            ts,
            requestName,
            r.Method,
            r.RequestURI,
            duration.Seconds(),
            status,
        )
        return
    }

    if gLogLevel < LOG_DEBUG {
        return
    }

    logMsg(LOG_DEBUG, "[HTTP-REQ: %s] %s %s %v (%.6f seconds) -> %s",
        requestName,
        r.Method,
        r.RequestURI,
        duration,
        duration.Seconds(),
        status,
    )
}

func logDnsReq(r *dns.Msg, start time.Time, status string) {

    duration := time.Since(start)
    ts := time.Now().UTC().Format(time.RFC3339)
    q  := r.Question[0]

    if gLogJSON {
        log.Printf(`{"ts":"%s","type":"dns","request":%q,"qtype":%s,"duration_seconds":%f,"status":%s}`,
            ts,
            q.Name,
            dns.TypeToString[q.Qtype],
            duration.Seconds(),
            status,
        )
        return
    }

    if gLogLevel < LOG_DEBUG {
        return
    }

    logMsg(LOG_DEBUG, "[DNS Requery: %s] %s %v (%.6f seconds) -> %s",
        dns.TypeToString[q.Qtype],
        q.Name,
        duration,
        duration.Seconds(),
        status,
    )
}
