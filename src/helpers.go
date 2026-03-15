// open-blocklist - An open blocklist tool / helper routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "bufio"
    "fmt"
    "runtime"
    "os"
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
