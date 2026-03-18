// open-blocklist - An open blocklist tool - log routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
package main

import (
    "fmt"
    "net/http"
    "os"
    "time"

    "github.com/miekg/dns"
)

func LogSetFile(path string) error {
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
    if err != nil {
        return err
    }
    logWriter = f
    return nil
}

// Async writer config
const (
    // asyncBufBytes is the target size of the in-process log channel buffer.
    // Each slot holds one formatted log line (a []byte).
    // Assuming ~200 bytes average per line:
    //   50_000 slots × 200 B ≈ 10 MB
    //   100_000 slots × 200 B ≈ 20 MB
    // Adjust via LogSetChannelSize() before the first log call.
    defaultChannelSize = 50_000

    // poolBufSize is the pre-allocated capacity of each scratch buffer.
    // 8 KB comfortably fits any single log line without a grow.
    poolBufSize = 8_192
)

// Async writer state
var (
    logCh      chan []byte    // buffered channel; worker owns os.Stdout
    logDone    chan struct{}   // closed when worker exits
)

// bufPool is a pool of *[]byte scratch buffers.
// Using a pointer so the slice header (len/cap/ptr) is stable across pool ops.
var bufPool = newBufPool()

type pool struct{ ch chan *[]byte }

func newBufPool() *pool {
    p := &pool{ch: make(chan *[]byte, 256)}
    for i := 0; i < 64; i++ {
        b := make([]byte, 0, poolBufSize)
        p.ch <- &b
    }
    return p
}

func (p *pool) get() *[]byte {
    select {
    case b := <-p.ch:
        *b = (*b)[:0]
        return b
    default:
        b := make([]byte, 0, poolBufSize)
        return &b
    }
}

func (p *pool) put(b *[]byte) {
    *b = (*b)[:0]
    select {
    case p.ch <- b:
    default:
        // pool full — let GC reclaim it
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// LogInit starts the async writer goroutine.
// Call once from main(), before any logging.
// channelSize controls how many log lines can be buffered in-process.
// Pass 0 to use the default (50_000, ~10 MB at ~200 B/line).
func LogInit(channelSize int) {
    if channelSize <= 0 {
        channelSize = defaultChannelSize
    }
    logCh = make(chan []byte, channelSize)
    logDone = make(chan struct{})
    go asyncLogWorker()
}

// LogFlush blocks until every queued entry has been written to stdout,
// then shuts down the worker. Call this before os.Exit / graceful shutdown.
func LogFlush() {
    if logCh == nil {
        return
    }
    close(logCh)
    <-logDone
}

// asyncLogWorker is the single goroutine that owns os.Stdout.
// No mutex needed — serialization comes from the channel.
func asyncLogWorker() {
    defer close(logDone)
    for msg := range logCh {
        logWriter.Write(msg) //nolint:errcheck
        bufPool.put(&msg)
    }
}

// send copies the scratch buffer to an immutable message and enqueues it.
// The scratch buffer is returned to the pool immediately so the caller's
// goroutine can reuse it without waiting for the worker.
func send(bp *[]byte) {
    msg := make([]byte, len(*bp))
    copy(msg, *bp)
    bufPool.put(bp)

    select {
    case logCh <- msg:
    default:
        // Channel full — synchronous fallback so we never drop silently.
        logWriter.Write(msg) //nolint:errcheck
        stats.LogDropped.Add(1)
    }
}

// ---------------------------------------------------------------------------
// Low-level buffer helpers (zero alloc)
// ---------------------------------------------------------------------------

// appendTimestamp appends an RFC3339-UTC timestamp into b.
func appendTimestamp(b []byte, t time.Time) []byte {
    return t.UTC().AppendFormat(b, time.RFC3339)
}

// appendQuoted appends a JSON-safe double-quoted string.
// Handles \n \r \t \" \\ and low control characters.
func appendQuoted(b []byte, s string) []byte {
    b = append(b, '"')
    for i := 0; i < len(s); i++ {
        c := s[i]
        switch c {
        case '"':
            b = append(b, '\\', '"')
        case '\\':
            b = append(b, '\\', '\\')
        case '\n':
            b = append(b, '\\', 'n')
        case '\r':
            b = append(b, '\\', 'r')
        case '\t':
            b = append(b, '\\', 't')
        default:
            if c < 0x20 {
                const hex = "0123456789abcdef"
                b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
            } else {
                b = append(b, c)
            }
        }
    }
    return append(b, '"')
}

// ---------------------------------------------------------------------------
// LogLevel helpers (unchanged from your original)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Core log functions
// ---------------------------------------------------------------------------

func logLine(level LogLevel, msg string) {
    now := time.Now()
    bp := bufPool.get()
    b := *bp

    if gLogJSON {
        b = append(b, `{"ts":"`...)
        b = appendTimestamp(b, now)
        b = append(b, `","type":"event","level":"`...)
        b = append(b, level.LowerCaseStr()...)
        b = append(b, `","msg":`...)
        b = appendQuoted(b, msg)
        b = append(b, '}', '\n')
    } else {
        b = appendTimestamp(b, now)
        b = append(b, "   "...)
        b = append(b, level.String()...)
        b = append(b, ": "...)
        b = append(b, msg...)
        b = append(b, '\n')
    }

    *bp = b
    send(bp)
}

func logSpace() {
    if gLogJSON {
        return
    }
    if gLogLevel < LOG_INFO {
        return
    }
    now := time.Now()
    bp := bufPool.get()
    b := *bp
    b = appendTimestamp(b, now)
    b = append(b, '\n')
    *bp = b
    send(bp)
}

func logMsg(level LogLevel, format string, args ...any) {
    if level > gLogLevel {
        return
    }
    logLine(level, fmt.Sprintf(format, args...))
}

func logFatal(format string, args ...any) {
    logLine(LOG_ERROR, fmt.Sprintf(format, args...))
    LogFlush()
    os.Exit(1)
}

func showCfg(description, variableName, defaultValue, currentValue any) {
    logMsg(LOG_INFO, "%-34s  %-40s %-40v  %v", variableName, description, defaultValue, currentValue)
}

func showInfo(description, currentValue any) {
    logMsg(LOG_INFO, "%-15s:  %v", description, currentValue)
}

func logListerner(info string, addr string) {
    if addr == "" {
        return
    }
    logMsg(LOG_INFO, "Listening  [%-10s]  on %s", info, addr)
}

func logHttpReq(r *http.Request, start time.Time, requestName string, status string) {
    now := time.Now()
    duration := now.Sub(start)

    bp := bufPool.get()
    b := *bp

    if gLogJSON {
        b = append(b, `{"ts":"`...)
        b = appendTimestamp(b, now)
        b = append(b, `","type":"http","request":`...)
        b = appendQuoted(b, requestName)
        b = append(b, `,"method":`...)
        b = appendQuoted(b, r.Method)
        b = append(b, `,"uri":`...)
        b = appendQuoted(b, r.RequestURI)
        b = append(b, `,"duration_seconds":`...)
        b = fmt.Appendf(b, "%f", duration.Seconds())
        b = append(b, `,"status":`...)
        b = appendQuoted(b, status)
        b = append(b, '}', '\n')
    } else {
        if gLogLevel < LOG_DEBUG {
            bufPool.put(bp)
            return
        }
        b = appendTimestamp(b, now)
        b = append(b, "   DEBUG: [HTTP-REQ: "...)
        b = append(b, requestName...)
        b = append(b, "] "...)
        b = append(b, r.Method...)
        b = append(b, ' ')
        b = append(b, r.RequestURI...)
        b = append(b, ' ')
        b = fmt.Appendf(b, "%v (%.6f seconds) -> %s\n", duration, duration.Seconds(), status)
    }

    *bp = b
    send(bp)
}

func logDnsReq(r *dns.Msg, start time.Time, status string) {
    now := time.Now()
    duration := now.Sub(start)
    q := r.Question[0]

    bp := bufPool.get()
    b := *bp

    if gLogJSON {
        b = append(b, `{"ts":"`...)
        b = appendTimestamp(b, now)
        b = append(b, `","type":"dns","request":`...)
        b = appendQuoted(b, q.Name)
        b = append(b, `,"qtype":`...)
        b = appendQuoted(b, dns.TypeToString[q.Qtype])
        b = fmt.Appendf(b, `,"duration_seconds":%f,"status":`, duration.Seconds())
        b = appendQuoted(b, status)
        b = append(b, '}', '\n')
    } else {
        if gLogLevel < LOG_DEBUG {
            bufPool.put(bp)
            return
        }
        b = appendTimestamp(b, now)
        b = append(b, "   DEBUG: [DNS-REQ: "...)
        b = append(b, dns.TypeToString[q.Qtype]...)
        b = append(b, "] "...)
        b = append(b, q.Name...)
        b = append(b, ' ')
        b = fmt.Appendf(b, "%v (%.6f seconds) -> %s\n", duration, duration.Seconds(), status)
    }

    *bp = b
    send(bp)
}
