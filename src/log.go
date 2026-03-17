//open-blocklist - An open blocklist tool - log routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "log"
    "fmt"
    "os"
    "time"
)

func showCfg(description, variableName, defaultValue, currentValue any) {
    logMsg("%-34s  %-40s %-40v  %v", variableName, description, defaultValue, currentValue)
}

func showInfo(description, currentValue any) {
    logMsg("%-15s:  %v", description, currentValue)
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

func logLine(msg string) {

    ts := time.Now().UTC().Format(time.RFC3339)

    if gLogJSON {
        log.Printf(`{"ts":"%s","type":"%s","msg":%q}`, ts, "event", msg)
        return
    }

    log.Println(ts + "   " + msg)
}

func logSpace() {

    if gLogJSON {
        return
    }

    logLine("")
}

func logMsg(format string, args ...any) {
    logLine(fmt.Sprintf(format, args ...))
}

func logFatal(format string, args ...any) {

    logLine(fmt.Sprintf(format, args ...))
    os.Exit(1)
}

func logListerner(info string, addr string) {

    if addr == "" {
        // No listen address

    } else {
        logMsg ("Listening  [%-10s]  on %s", info, addr)
    }
}