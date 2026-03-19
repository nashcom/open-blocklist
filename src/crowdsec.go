// open-blocklist - CrowdSec bouncer integration
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "encoding/json"
    "fmt"
    "net"
    "net/http"
    "strings"
    "time"
)

const (
    env_openbl_CrowdSecEnabled      = "OPENBL_CROWDSEC_ENABLED"
    env_openbl_CrowdSecLAPIURL      = "OPENBL_CROWDSEC_LAPI_URL"
    env_openbl_CrowdSecAPIKey       = "OPENBL_CROWDSEC_API_KEY"
    env_openbl_CrowdSecPollInterval = "OPENBL_CROWDSEC_POLL_INTERVAL"

    defaultCrowdSecLAPIURL = "http://crowdsec:8080"
)

var (
    gCrowdSecEnabled      bool
    gCrowdSecLAPIURL      string
    gCrowdSecAPIKey       string
    gCrowdSecPollInterval time.Duration
)

// csDecision is a single decision returned by the CrowdSec LAPI.
type csDecision struct {
    ID       int64  `json:"id"`
    Value    string `json:"value"`    // IP address or CIDR range
    Type     string `json:"type"`     // "ban", "captcha", "throttle", etc. → stored in Action
    Origin   string `json:"origin"`   // "crowdsec", "cscli", "lists", etc.
    Scenario string `json:"scenario"` // scenario that triggered the decision
    Duration string `json:"duration"` // remaining duration, e.g. "3h59m49.264308s"
    Scope    string `json:"scope"`    // "ip", "range", "country", etc.
}

type csDecisionStream struct {
    New     []*csDecision `json:"new"`
    Deleted []*csDecision `json:"deleted"`
}

func initCrowdSec() {
    gCrowdSecEnabled      = getEnvBool(env_openbl_CrowdSecEnabled, false)
    gCrowdSecLAPIURL      = getEnv(env_openbl_CrowdSecLAPIURL, defaultCrowdSecLAPIURL)
    gCrowdSecAPIKey       = getEnv(env_openbl_CrowdSecAPIKey, "")
    gCrowdSecPollInterval = 30 * time.Second

    if s := getEnv(env_openbl_CrowdSecPollInterval, ""); s != "" {
        d, err := time.ParseDuration(s)
        if err != nil {
            logMsg(LOG_ERROR, "Invalid CrowdSec poll interval %q: %v", s, err)
        } else {
            gCrowdSecPollInterval = d
        }
    }
}

func startCrowdSecBouncer() {

    if !gCrowdSecEnabled {
        return
    }

    if gCrowdSecAPIKey == "" {
        logMsg(LOG_ERROR, "CrowdSec enabled but %s is not set", env_openbl_CrowdSecAPIKey)
        return
    }

    logMsg(LOG_INFO, "Starting CrowdSec bouncer (LAPI: %s, poll: %s)", gCrowdSecLAPIURL, gCrowdSecPollInterval)
    go crowdSecLoop()
}

func crowdSecLoop() {

    client := &http.Client{Timeout: 30 * time.Second}
    startup := true

    for {
        stream, err := fetchCrowdSecDecisions(client, startup)
        if err != nil {
            logMsg(LOG_ERROR, "CrowdSec fetch failed: %v", err)
            time.Sleep(gCrowdSecPollInterval)
            continue
        }

        if startup {
            crowdSecReconcile(stream)
            startup = false
        } else {
            for _, d := range stream.New {
                crowdSecApply(d)
            }
            for _, d := range stream.Deleted {
                crowdSecRemove(d)
            }
        }

        time.Sleep(gCrowdSecPollInterval)
    }
}

func fetchCrowdSecDecisions(client *http.Client, startup bool) (*csDecisionStream, error) {
    url := gCrowdSecLAPIURL + "/v1/decisions/stream"
    if startup {
        url += "?startup=true"
    }

    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("X-Api-Key", gCrowdSecAPIKey)

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("CrowdSec LAPI returned %d", resp.StatusCode)
    }

    var stream csDecisionStream
    if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
        return nil, err
    }

    return &stream, nil
}

// crowdSecReconcile handles the startup=true response.
// It applies all current CrowdSec decisions and removes any entries that
// were previously synced from CrowdSec but are no longer present in the LAPI.
// This covers the case where the service restarted and missed deletion events.

func crowdSecReconcile(stream *csDecisionStream) {

    // Build a set of canonical values from CrowdSec's current decisions.
    csValues := make(map[string]bool, len(stream.New))

    for _, d := range stream.New {
        if strings.Contains(d.Value, "/") {
            _, network, err := net.ParseCIDR(d.Value)
            if err == nil {
                csValues[network.String()] = true
            }
        } else {
            if ip := net.ParseIP(d.Value); ip != nil {
                csValues[ip.String()] = true
            }
        }
    }

    // Find stale IP entries (previously synced from CrowdSec, no longer in LAPI).
    var staleIPs []string
    ipTable.RLock()

    for ip, entry := range ipTable.entries {
        if strings.HasPrefix(entry.Source, "crowdsec") && !csValues[ip] {
            staleIPs = append(staleIPs, ip)
        }
    }

    ipTable.RUnlock()

    for _, ipstr := range staleIPs {
        if parsed := net.ParseIP(ipstr); parsed != nil {
            etcdDelete(rblKey(parsed))
            etcdDelete(reverseKey(parsed))
        }
        if !gMultiInstanceMode {
            ipTable.Lock()
            delete(ipTable.entries, ipstr)
            ipTable.Unlock()
        }
        logMsg(LOG_INFO, "CrowdSec reconcile: removed stale IP %s", ipstr)
    }

    // Find stale CIDR entries.
    var staleCIDRs []string

    cidrTable.RLock()
    for _, e := range cidrTable.entries {
        if strings.HasPrefix(e.Source, "crowdsec") && !csValues[e.CIDR] {
            staleCIDRs = append(staleCIDRs, e.CIDR)
        }
    }
    cidrTable.RUnlock()

    for _, cidr := range staleCIDRs {
        etcdDeleteCIDR(cidr)
        if !gMultiInstanceMode {
            cidrTable.remove(cidr)
        }
        logMsg(LOG_INFO, "CrowdSec reconcile: removed stale CIDR %s", cidr)
    }

    // Apply all current decisions.
    for _, d := range stream.New {
        crowdSecApply(d)
    }

    logMsg(LOG_INFO, "CrowdSec reconcile complete: %d decisions, %d stale IPs, %d stale CIDRs removed",
        len(stream.New), len(staleIPs), len(staleCIDRs))
}

// crowdSecApply adds or updates a single CrowdSec decision in the blocklist.
func crowdSecApply(d *csDecision) {

    source := "crowdsec"
    if d.Origin != "" && d.Origin != "crowdsec" {
        source = "crowdsec:" + d.Origin
    }

    var expiration int64
    if d.Duration != "" {
        dur, err := time.ParseDuration(d.Duration)
        if err != nil {
            logMsg(LOG_ERROR, "CrowdSec: invalid duration %q for %s: %v", d.Duration, d.Value, err)
        } else {
            expiration = time.Now().Add(dur).Unix()
        }
    }

    now := time.Now().Unix()

    if strings.Contains(d.Value, "/") {
        crowdSecApplyCIDR(d, source, now, expiration)
    } else {
        crowdSecApplyIP(d, source, now, expiration)
    }
}

func crowdSecApplyIP(d *csDecision, source string, now, expiration int64) {

    ip := net.ParseIP(d.Value)
    if ip == nil {
        logMsg(LOG_ERROR, "CrowdSec: invalid IP %q", d.Value)
        return
    }
    ipstr := ip.String()

    entry := BlockEntry{
        IP:         ipstr,
        Source:     source,
        Scenario:   d.Scenario,
        Action:     d.Type,
        ReturnCode: IPv4StrToUint32(defaultReturn),
        FirstSeen:  now,
        LastSeen:   now,
        Expiration: expiration,
    }

    // Preserve first_seen across updates.
    if existing, ok := ipTableLookup(ipstr); ok && existing != nil {
        entry.FirstSeen = existing.FirstSeen
    }

    rec := BlockRecord{
        Version:    1,
        Host:       defaultReturn,
        TTL:        gRecordTTL,
        Source:     entry.Source,
        Scenario:   entry.Scenario,
        Action:     entry.Action,
        FirstSeen:  entry.FirstSeen,
        LastSeen:   entry.LastSeen,
        Expiration: entry.Expiration,
    }

    etcdPut(rblKey(ip), rec)
    etcdPut(reverseKey(ip), PTRRecord{Host: gReverseHost, TTL: gPtrTTL})

    if !gMultiInstanceMode {
        ipTable.Lock()
        ipTable.entries[ipstr] = &entry
        ipTable.Unlock()
    }

    logMsg(LOG_VERBOSE, "CrowdSec: blocked IP %s (scenario=%s action=%s)", ipstr, d.Scenario, d.Type)
}

func crowdSecApplyCIDR(d *csDecision, source string, now, expiration int64) {
    _, network, err := net.ParseCIDR(d.Value)
    if err != nil {
        logMsg(LOG_ERROR, "CrowdSec: invalid CIDR %q: %v", d.Value, err)
        return
    }
    cidr := network.String()

    entry := &CIDREntry{
        CIDR:       cidr,
        Net:        network,
        Source:     source,
        Scenario:   d.Scenario,
        Action:     d.Type,
        ReturnCode: IPv4StrToUint32(defaultReturn),
        FirstSeen:  now,
        LastSeen:   now,
        Expiration: expiration,
    }

    // Preserve first_seen across updates.
    if existing := cidrTable.findByCIDR(cidr); existing != nil {
        entry.FirstSeen = existing.FirstSeen
    }

    rec := BlockRecord{
        Version:    1,
        Host:       defaultReturn,
        TTL:        gRecordTTL,
        Source:     entry.Source,
        Scenario:   entry.Scenario,
        Action:     entry.Action,
        FirstSeen:  entry.FirstSeen,
        LastSeen:   entry.LastSeen,
        Expiration: entry.Expiration,
    }

    etcdPutCIDR(cidr, rec)

    if !gMultiInstanceMode {
        cidrTable.upsert(entry)
    }

    logMsg(LOG_VERBOSE, "CrowdSec: blocked CIDR %s (scenario=%s action=%s)", cidr, d.Scenario, d.Type)
}

// crowdSecRemove removes a single CrowdSec decision from the blocklist.
func crowdSecRemove(d *csDecision) {

    if strings.Contains(d.Value, "/") {
        _, network, err := net.ParseCIDR(d.Value)
        if err != nil {
            logMsg(LOG_ERROR, "CrowdSec: invalid CIDR %q: %v", d.Value, err)
            return
        }
        cidr := network.String()
        etcdDeleteCIDR(cidr)
        if !gMultiInstanceMode {
            cidrTable.remove(cidr)
        }
        logMsg(LOG_VERBOSE, "CrowdSec: unblocked CIDR %s", cidr)
    } else {
        ip := net.ParseIP(d.Value)
        if ip == nil {
            logMsg(LOG_ERROR, "CrowdSec: invalid IP %q", d.Value)
            return
        }
        etcdDelete(rblKey(ip))
        etcdDelete(reverseKey(ip))
        if !gMultiInstanceMode {
            ipstr := ip.String()
            ipTable.Lock()
            delete(ipTable.entries, ipstr)
            ipTable.Unlock()
        }
        logMsg(LOG_VERBOSE, "CrowdSec: unblocked IP %s", ip.String())
    }
}

