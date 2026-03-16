// open-blocklist - An open blocklist tool / helper routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "bufio"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "net"
    "net/http"
    "os"
    "runtime"
    "strconv"
    "strings"
    "time"
)

func showRuntimeInfo() {

    logSpace()
    logMsg("Runtime")
    logMsg("-------------------------")
    logSpace()

    info, err := readOSRelease()
    if err == nil {
        showInfo("Name", info["PRETTY_NAME"])
        showInfo("ID", info["ID"])
        showInfo("Version", info["VERSION_ID"])
    }

    showInfo("Go version", runtime.Version())
    showInfo("OS", runtime.GOOS)
    showInfo("Arch", runtime.GOARCH)
    showInfo("Platform", gBuildPlatform)

    showInfo("CPUs", runtime.NumCPU())
    showInfo("PID", os.Getpid())

    showInfo("UID/GID",   strconv.Itoa(os.Getuid())  + ":" + strconv.Itoa(os.Getgid()))
    showInfo("EUID/EGID", strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid()))
}

func formatStr(s string) string {
    if s == "" {
        return "[]"
    }

    return s
}

func fileExists(filename string) bool {
    _, err := os.Stat(filename)
    return err == nil
}

func dashLine(width int) string {
    return strings.Repeat("-", width)
}

func sleepWithShutdownCheck(n int) bool {
    for i := 0; i < n; i++ {
        if gShutdownRequested {
            return true
        }

        time.Sleep(time.Second)
    }

    return false
}

func getEnv(key, fallback string) string {
    if v := os.Getenv(key); v != "" {
        return v
    }
    return fallback
}

func getEnvLogLevel(key string, fallback LogLevel) LogLevel {

    if v := os.Getenv(key); v != "" {
        level, err := ParseLogLevel(v)

        if err == nil {
            return level
        } else {
            logMsg("ERROR: Invalid log level [%s] for environment variable %s : %v", v, key, err)
        }
    }

    return fallback
}

func getEnvInt64(key string, fallback int64) int64 {

    if v := os.Getenv(key); v != "" {
        if n, err := strconv.ParseInt(v, 10, 64); err == nil {
            return n
        } else {
            logMsg("ERROR: Invalid numeric value [%s] for environment variable %s : %v", v, key, err)
        }
    }

    return fallback
}

func getEnvInt(key string, fallback int) int {

    if v := os.Getenv(key); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            return n
        } else {
            logMsg("ERROR: Invalid numeric value [%s] for environment variable %s : %v", v, key, err)
        }
    }

    return fallback
}

func getEnvBool(key string, fallback bool) bool {
    val, exists := os.LookupEnv(key)
    if !exists || val == "" {
        return fallback
    }

    parsed, err := strconv.ParseBool(val)
    if err != nil {
        logMsg("Warning: Invalid bool value [%s] for environment variable %s : %v", parsed, key, err)
        return fallback
    }

    return parsed
}

func formatBytes(b int64) string {

    const unit = 1024

    if b < unit {
        return fmt.Sprintf("%dB", b)
    }

    div, exp := int64(unit), 0

    for n := b / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }

    value := float64(b) / float64(div)

    return fmt.Sprintf("%.2f %cB",
        value,
        "KMGTPE"[exp],
    )
}

func parseGoVersionBuild(v string) int64 {

    if !strings.Contains(v, "go") {
        return 0
    }

    i := strings.Index(v, "go")
    v = v[i+2:]

    parts := strings.Split(v, ".")

    var major, minor, patch int64

    if len(parts) > 0 {
        major, _ = strconv.ParseInt(parts[0], 10, 64)
    }

    if len(parts) > 1 {
        minor, _ = strconv.ParseInt(parts[1], 10, 64)
    }

    if len(parts) > 2 {
        p := parts[2]

        for i := 0; i < len(p); i++ {
            if p[i] < '0' || p[i] > '9' {
                p = p[:i]
                break
            }
        }

        patch, _ = strconv.ParseInt(p, 10, 64)
    }

    return major*10000 + minor*100 + patch
}

func readOSRelease() (map[string]string, error) {

    file, err := os.Open("/etc/os-release")
    if err != nil {
        return nil, err
    }
    defer file.Close()

    data := make(map[string]string)
    scanner := bufio.NewScanner(file)

    for scanner.Scan() {
        line := scanner.Text()

        if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
            continue
        }

        parts := strings.SplitN(line, "=", 2)
        key := parts[0]
        val := strings.Trim(parts[1], `"`)

        data[key] = val
    }

    return data, scanner.Err()
}

var httpClient = &http.Client{
    Timeout: 2 * time.Second,
}

func waitForEtcd(endpoint string, maxWait time.Duration) {
    url := endpoint + "/health"

    retryInterval  :=  2 * time.Second
    reportInterval := 10 * time.Second

    start := time.Now()
    nextReport := start

    for {
        resp, err := httpClient.Get(url)
        if err == nil && resp.StatusCode == http.StatusOK {
            resp.Body.Close()
            logMsg("etcd is available")
            return
        }

        if resp != nil {
            resp.Body.Close()
        }

        now := time.Now()

        if now.After(nextReport) {
            logMsg("Waiting for etcd at %s (elapsed %d)", endpoint, int(now.Sub(start).Seconds()))
            nextReport = now.Add(reportInterval)
        }

        if now.Sub(start) > maxWait {
            logFatal("Etcd did not become available within %s", maxWait)
        }

        time.Sleep(retryInterval)
    }
}


func b64(s string) string {
    return base64.StdEncoding.EncodeToString([]byte(s))
}

func b64d(s string) string {
    b, _ := base64.StdEncoding.DecodeString(s)
    return string(b)
}

func ipv4Parts(ip net.IP) []string {

    v4 := ip.To4()

    return []string{
        fmt.Sprintf("%d", v4[0]),
        fmt.Sprintf("%d", v4[1]),
        fmt.Sprintf("%d", v4[2]),
        fmt.Sprintf("%d", v4[3]),
    }
}

func ipv6Nibbles(ip net.IP) []string {

    ip = ip.To16()

    hexstr := hex.EncodeToString(ip)

    var out []string

    for _, c := range hexstr {
        out = append(out, string(c))
    }

    return out
}

func rblKey(ip net.IP) string {

    if ip.To4() != nil {

        p := ipv4Parts(ip)

        return fmt.Sprintf("%s/%s/%s/%s/%s",
            rblPrefix, p[0], p[1], p[2], p[3])
    }

    p := ipv6Nibbles(ip)

    return fmt.Sprintf("%s/%s",
        rblPrefix, strings.Join(p, "/"))
}

func reverseKey(ip net.IP) string {

    if ip.To4() != nil {

        p := ipv4Parts(ip)

        return fmt.Sprintf("%s/arpa/in-addr/%s/%s/%s/%s",
            skyPrefix,
            p[0], p[1], p[2], p[3])
    }

    p := ipv6Nibbles(ip)

    return fmt.Sprintf("%s/arpa/ip6/%s",
        skyPrefix,
        strings.Join(p, "/"))
}

func lookup(ip string) (*BlockEntry, bool) {

    store.RLock()
    entry, ok := store.entries[ip]
    store.RUnlock()

    return entry, ok
}

func epochToISO(ts int64) string {

    if ts == 0 {
        return ""
    }

    return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}

func remainingSeconds(exp int64) int64 {

    if exp == 0 {
        return 0
    }

    now := time.Now().Unix()

    remaining := exp - now

    if remaining < 0 {
        return 0
    }

    return remaining
}

func remainingDuration(exp int64) string {

    if exp == 0 {
        return "permanent"
    }

    r := remainingSeconds(exp)

    return (time.Duration(r) * time.Second).String()
}


func IPv4StringToUint32(s string) (uint32, error) {

    parts := strings.Split(s, ".")
    if len(parts) != 4 {
        return 0, fmt.Errorf("invalid IPv4 address")
    }

    a, err := strconv.Atoi(parts[0])
    if err != nil || a > 255 {
        return 0, fmt.Errorf("invalid IPv4 address")
    }

    b, err := strconv.Atoi(parts[1])
    if err != nil || b > 255 {
        return 0, fmt.Errorf("invalid IPv4 address")
    }

    c, err := strconv.Atoi(parts[2])
    if err != nil || c > 255 {
        return 0, fmt.Errorf("invalid IPv4 address")
    }

    d, err := strconv.Atoi(parts[3])
    if err != nil || d > 255 {
        return 0, fmt.Errorf("invalid IPv4 address")
    }

    return uint32(a)<<24 |
        uint32(b)<<16 |
        uint32(c)<<8 |
        uint32(d), nil
}

func Uint32ToIPv4(v uint32) string {

    return fmt.Sprintf("%d.%d.%d.%d",
        byte(v>>24),
        byte(v>>16),
        byte(v>>8),
        byte(v),
    )
}

func Uint32ToIPv4Bytes(v uint32) [4]byte {

    return [4]byte{
        byte(v >> 24),
        byte(v >> 16),
        byte(v >> 8),
        byte(v),
    }
}

func IPv4BytesToUint32(b [4]byte) uint32 {

    return uint32(b[0])<<24 |
        uint32(b[1])<<16 |
        uint32(b[2])<<8 |
        uint32(b[3])
}

func IsIPv4(s string) bool {
    return strings.Count(s, ".") == 3
}

func FastIPv4ToUint32(s string) (uint32, error) {

    var a, b, c, d int
    n, err := fmt.Sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d)

    if err != nil || n != 4 ||
        a > 255 || b > 255 || c > 255 || d > 255 {

        return 0, fmt.Errorf("invalid IPv4 address")
    }

    return uint32(a)<<24 |
        uint32(b)<<16 |
        uint32(c)<<8 |
        uint32(d), nil
}

type IPv6Key [16]byte


func IsIPv6(s string) bool {
    return strings.Contains(s, ":")
}

func IPv6StringToKey(s string) (IPv6Key, error) {

    ip := net.ParseIP(s)
    if ip == nil {
        return IPv6Key{}, fmt.Errorf("invalid IPv6 address")
    }

    ip = ip.To16()
    if ip == nil {
        return IPv6Key{}, fmt.Errorf("invalid IPv6 address")
    }

    var key IPv6Key
    copy(key[:], ip)

    return key, nil
}

func IPv6KeyToString(key IPv6Key) string {
    return net.IP(key[:]).String()
}

func KeyToIPv6(key IPv6Key) net.IP {
    return net.IP(key[:])
}

func IPv6ToKey(ip net.IP) IPv6Key {

    var key IPv6Key

    ip16 := ip.To16()
    if ip16 != nil {
        copy(key[:], ip16)
    }

    return key
}

