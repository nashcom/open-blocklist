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
    "syscall"
    "time"
)

func parseInt64(s string) int64 {
    v, _ := strconv.ParseInt(s, 10, 64)
    return v
}

func showRuntimeInfo() {

    logSpace()
    logMsg(LOG_INFO, "Runtime")
    logMsg(LOG_INFO, "-------------------------")
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

    var sysInfo syscall.Sysinfo_t
    syscall.Sysinfo(&sysInfo)
    unit := float64(sysInfo.Unit)

    showInfo("Total RAM", fmt.Sprintf("%.1f GB", float64(sysInfo.Totalram) * unit / 1024 / 1024 / 1024))
    showInfo("Free RAM",  fmt.Sprintf("%.1f GB", float64(sysInfo.Freeram) * unit / 1024 / 1024 / 1024))
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
            logMsg(LOG_ERROR, "ERROR: Invalid log level [%s] for environment variable %s : %v", v, key, err)
        }
    }

    return fallback
}

func getEnvInt64(key string, fallback int64) int64 {

    if v := os.Getenv(key); v != "" {
        if n, err := strconv.ParseInt(v, 10, 64); err == nil {
            return n
        } else {
            logMsg(LOG_ERROR, "ERROR: Invalid numeric value [%s] for environment variable %s : %v", v, key, err)
        }
    }

    return fallback
}

func getEnvInt(key string, fallback int) int {

    if v := os.Getenv(key); v != "" {
        if n, err := strconv.Atoi(v); err == nil {
            return n
        } else {
            logMsg(LOG_ERROR, "ERROR: Invalid numeric value [%s] for environment variable %s : %v", v, key, err)
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
        logMsg(LOG_ERROR, "Warning: Invalid bool value [%s] for environment variable %s : %v", parsed, key, err)
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
        major = parseInt64(parts[0])
    }

    if len(parts) > 1 {
        minor =parseInt64(parts[1])
    }

    if len(parts) > 2 {
        p := parts[2]

        for i := 0; i < len(p); i++ {
            if p[i] < '0' || p[i] > '9' {
                p = p[:i]
                break
            }
        }

        patch = parseInt64(p)
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
            SKY_DNS_PREFIX,
            p[0], p[1], p[2], p[3])
    }

    p := ipv6Nibbles(ip)

    return fmt.Sprintf("%s/arpa/ip6/%s",
        SKY_DNS_PREFIX,
        strings.Join(p, "/"))
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


// IPv4StrToUint32 parses an IPv4 address string into a uint32.
// Returns 0 for any invalid input — negative octets, out-of-range values,
// wrong number of octets, or any non-numeric character.
func IPv4StrToUint32(s string) uint32 {

    var result uint32
    var octet  uint32
    dots := 0

    for i := 0; i < len(s); i++ {
        c := s[i]
        if c >= '0' && c <= '9' {
            octet = octet*10 + uint32(c-'0')
            if octet > 255 {
                return 0
            }
        } else if c == '.' {
            if dots == 3 {
                return 0
            }
            result = result<<8 | octet
            octet  = 0
            dots++
        } else {
            return 0
        }
    }

    if dots != 3 {
        return 0
    }

    return result<<8 | octet
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
    return IPv4StrToUint32(s) != 0 || s == "0.0.0.0"
}

func Uint32ToIPv4Str(n uint32) string {

    var buf [15]byte // max "255.255.255.255"
    pos := 0

    pos += appendUint8(buf[pos:], byte(n>>24))
    buf[pos] = '.'
    pos++

    pos += appendUint8(buf[pos:], byte(n>>16))
    buf[pos] = '.'
    pos++

    pos += appendUint8(buf[pos:], byte(n>>8))
    buf[pos] = '.'
    pos++

    pos += appendUint8(buf[pos:], byte(n))

    return string(buf[:pos])
}

func appendUint8(dst []byte, v byte) int {

    if v >= 100 {
        dst[0] = '0' + v/100
        dst[1] = '0' + (v/10)%10
        dst[2] = '0' + v%10
        return 3
    }
    if v >= 10 {
        dst[0] = '0' + v/10
        dst[1] = '0' + v%10
        return 2
    }

    dst[0] = '0' + v
    return 1
}


type IPv6Key [16]byte


func IsIPv6(s string) bool {
    return strings.Contains(s, ":")
}

func IsValidIP(s string) bool {
    return net.ParseIP(s) != nil
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

