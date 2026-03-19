// open-blocklist - CIDR table
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
    "fmt"
    "net"
    "sync"
    "time"
)

// CIDREntry stores a blocked network range and its metadata.
type CIDREntry struct {
    CIDR       string     // canonical CIDR, e.g. "1.2.3.0/24"
    Net        *net.IPNet // parsed network for Contains() matching
    Source     string
    Scenario   string
    Action     string
    ReturnCode uint32
    FirstSeen  int64
    LastSeen   int64
    Expiration int64
}

type cidrTableStore struct {
    sync.RWMutex
    entries []*CIDREntry
}

var cidrTable cidrTableStore

var (
    cidrPrefix     = fmt.Sprintf("%s/internal/%s-cidr", SKY_DNS_PREFIX, RBL_ZONE)
    cidrPrefixScan = cidrPrefix + "/"
)

// lookup returns the first CIDR entry that contains ip, or nil.
// Sequential scan is fast enough for the expected scale (~2,000 entries).
// Expired entries are skipped and queued for asynchronous deletion.
func (t *cidrTableStore) lookup(ip net.IP) *CIDREntry {
    t.RLock()
    defer t.RUnlock()
    now := time.Now().Unix()
    for _, e := range t.entries {
        if e.Net.Contains(ip) {
            if e.Expiration > 0 && e.Expiration <= now {
                go deleteExpiredCIDR(e.CIDR)
                return nil
            }
            return e
        }
    }
    return nil
}

func deleteExpiredCIDR(cidr string) {

    etcdDeleteCIDR(cidr)

    if !gMultiInstanceMode {
        cidrTable.remove(cidr)
    }

    logMsg(LOG_INFO, "Lazy expiry: CIDR %s", cidr)
}

// findByCIDR returns the entry with the exact canonical CIDR string, or nil.
func (t *cidrTableStore) findByCIDR(cidr string) *CIDREntry {
    t.RLock()
    defer t.RUnlock()
    for _, e := range t.entries {
        if e.CIDR == cidr {
            return e
        }
    }
    return nil
}

// upsert adds a new entry or replaces the existing one with the same CIDR.
func (t *cidrTableStore) upsert(e *CIDREntry) {
    t.Lock()
    defer t.Unlock()
    for i, existing := range t.entries {
        if existing.CIDR == e.CIDR {
            t.entries[i] = e
            return
        }
    }
    t.entries = append(t.entries, e)
}

// remove deletes the entry for the given CIDR using swap-with-last for O(1) removal.
func (t *cidrTableStore) remove(cidr string) {
    t.Lock()
    defer t.Unlock()
    for i, e := range t.entries {
        if e.CIDR == cidr {
            last := len(t.entries) - 1
            t.entries[i] = t.entries[last]
            t.entries[last] = nil
            t.entries = t.entries[:last]
            return
        }
    }
}

func (t *cidrTableStore) len() int {
    t.RLock()
    n := len(t.entries)
    t.RUnlock()
    return n
}

// cidrEntryToMap returns a plain map suitable for JSON encoding.
// net.IPNet is not included — only the canonical CIDR string is used.
func cidrEntryToMap(e *CIDREntry) map[string]interface{} {
    return map[string]interface{}{
        "cidr":     e.CIDR,
        "source":   e.Source,
        "scenario": e.Scenario,
        "action":   e.Action,

        "first_seen":     e.FirstSeen,
        "first_seen_iso": epochToISO(e.FirstSeen),

        "last_seen":     e.LastSeen,
        "last_seen_iso": epochToISO(e.LastSeen),

        "expiration":     e.Expiration,
        "expiration_iso": epochToISO(e.Expiration),

        "remaining_seconds":  remainingSeconds(e.Expiration),
        "remaining_duration": remainingDuration(e.Expiration),

        "return_code": Uint32ToIPv4Str(e.ReturnCode),
    }
}

// cidrEntryToBlockEntry converts a CIDREntry for use in HTTP responses.
// The caller is responsible for overriding IP with the queried IP address.
func cidrEntryToBlockEntry(e *CIDREntry) *BlockEntry {
    return &BlockEntry{
        IP:         e.CIDR,
        Source:     e.Source,
        Scenario:   e.Scenario,
        Action:     e.Action,
        ReturnCode: e.ReturnCode,
        FirstSeen:  e.FirstSeen,
        LastSeen:   e.LastSeen,
        Expiration: e.Expiration,
    }
}
