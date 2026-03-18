// open-blocklist - etc code
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE


package main

import (
    "bufio"
    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "strconv"
    "strings"
    "time"
)


type watchResponse struct {
    Result struct {

        Header struct {
            Revision string `json:"revision"`
        } `json:"header"`

        Events []watchEvent `json:"events"`

        Created bool  `json:"created"`
        Canceled bool `json:"canceled"`

    } `json:"result"`
}

type watchEvent struct {
    Type string `json:"type"`
    KV   struct {
        Key            string `json:"key"`
        Value          string `json:"value"`
        CreateRevision int64  `json:"create_revision,string"`
        ModRevision    int64  `json:"mod_revision,string"`
        Version        int64  `json:"version,string"`
    } `json:"kv"`
}

func startEtcWatcher() {
    go watchLoop()
}


func prefixRangeEnd(prefix []byte) []byte {
    end := make([]byte, len(prefix))
    copy(end, prefix)

    for i := len(end) - 1; i >= 0; i-- {
        if end[i] < 0xff {
            end[i]++
            return end[:i+1]
        }
    }

    return []byte{0}
}


func updateRevision(rev int64) {
    if rev > gEtcdRevision.Load() {
        gEtcdRevision.Store(rev)
    }
}


func watchLoop() {

    prefix := []byte(rblPrefix)
    key := base64.StdEncoding.EncodeToString(prefix)

    rangeEndBytes := prefixRangeEnd(prefix)
    rangeEnd := base64.StdEncoding.EncodeToString(rangeEndBytes)

    logMsg(LOG_VERBOSE, "Watching for events for prefix: %s, key: %s", rblPrefix, key)

    for {
        rev := gEtcdRevision.Load()

        create := map[string]interface{}{
            "key":       key,
            "range_end": rangeEnd,
        }

        if rev > 0 {
            create["start_revision"] = rev + 1
            logMsg(LOG_VERBOSE, "Starting watch from revision: %d", rev+1)
        }

        req := map[string]interface{}{
            "create_request": create,
        }

        body, _ := json.Marshal(req)

        request, err := http.NewRequest(
            "POST",
            gEtcdEndpoint+"/v3/watch",
            bytes.NewReader(body),
        )

        if err != nil {
            logMsg(LOG_ERROR, "Watch request creation failed: %v", err)
            time.Sleep(3 * time.Second)
            continue
        }

        request.Header.Set("Content-Type", "application/json")

        client := &http.Client{
            Timeout: 0,
        }

        resp, err := client.Do(request)

        if err != nil {
            logMsg(LOG_ERROR, "Etcd watch connect failed: %v", err)
            time.Sleep(3 * time.Second)
            continue
        }

        logMsg(LOG_INFO, "Etcd watch connected")

        scanner := bufio.NewScanner(resp.Body)

        buf := make([]byte, 0, 1024*1024)
        scanner.Buffer(buf, 1024*1024)

        for scanner.Scan() {

            line := scanner.Bytes()
            var msg watchResponse

            err := json.Unmarshal(line, &msg)
            if err != nil {
                logMsg(LOG_ERROR, "JSON Unmarshal failed: %v", err)
                continue
            }

            // Update revision from header
            if msg.Result.Header.Revision != "" {

                newRev, err := strconv.ParseInt(msg.Result.Header.Revision, 10, 64)

                if err == nil {

                    old := gEtcdRevision.Load()

                    if newRev > old {
                        gEtcdRevision.Store(newRev)
                        logMsg(LOG_INFO, "Revision updated: %d -> %d", old, newRev)
                    }
                }
            }

            for _, ev := range msg.Result.Events {

                keyBytes, _ := base64.StdEncoding.DecodeString(ev.KV.Key)
                ip := ipFromKey(string(keyBytes))

                if ip == "" {
                    logMsg(LOG_ERROR, "No IP address found")
                    continue
                }

                if ev.Type == "DELETE" {

                    logMsg(LOG_INFO, "Delete event received for: %v", ip)

                    ipTable.Lock()
                    delete(ipTable.entries, ip)
                    ipTable.Unlock()

                    continue
                }

                logMsg(LOG_INFO, "Update event received for: %v", ip)

                valueBytes, _ := base64.StdEncoding.DecodeString(ev.KV.Value)

                var rec DNSRecord

                err := json.Unmarshal(valueBytes, &rec)
                if err != nil {
                    logMsg(LOG_ERROR, "JSON decode of value failed: %v", err)
                    continue
                }

                if net.ParseIP(ip) == nil {
                    logMsg(LOG_ERROR, "Cannot parse IP address")
                    continue
                }

                entry := BlockEntry{
                    IP:             ip,
                    Source:         rec.Source,
                    ReturnCode:     FastIPv4StrToUint32(rec.Host),
                    FirstSeen:      rec.FirstSeen,
                    Expiration:     rec.Expiration,
                    CreateRevision: ev.KV.CreateRevision,
                    ModRevision:    ev.KV.ModRevision,
                }

                logMsg(LOG_INFO, "Entry received: %v", entry)

                ipTable.Lock()
                ipTable.entries[ip] = &entry
                ipTable.Unlock()
            }
        }

        if err := scanner.Err(); err != nil {
            logMsg(LOG_ERROR, "Watch scanner error: %v", err)
        }

        resp.Body.Close()

        logMsg(LOG_ERROR, "Watch connection closed, reconnecting")
        time.Sleep(2 * time.Second)
    }
}

func ipFromKey(key string) string {

    parts := strings.Split(key, "/")

    if len(parts) < 4 {
        return ""
    }

    ipParts := parts[len(parts)-4:]

    ip := strings.Join(ipParts, ".")

    if net.ParseIP(ip) != nil {
        return ip
    }

    return ""
}


func loadFromEtcd() {

    kvs, revision, err := etcdRange(rblPrefixScan)

    if err != nil {
        logFatal("Etcd load failed: %v", err)
        return
    }

    gEtcdRevision.Store(revision)

    logMsg (LOG_INFO, "Loading Etcd revision: %d", revision)

    for _, kv := range kvs {

        key := b64d(kv.Key)
        val := b64d(kv.Value)

        var rec DNSRecord

        json.Unmarshal([]byte(val), &rec)

        parts := strings.Split(key, "/")

        if len(parts) < 4 {
            continue
        }

        ip := fmt.Sprintf("%s.%s.%s.%s",
            parts[len(parts)-4],
            parts[len(parts)-3],
            parts[len(parts)-2],
            parts[len(parts)-1])

        ipTable.entries[ip] = &BlockEntry{
            IP:             ip,
            Source:         rec.Source,
            ReturnCode:     FastIPv4StrToUint32(rec.Host),
            FirstSeen:      rec.FirstSeen,
            Expiration:     rec.Expiration,
            CreateRevision: parseInt64(kv.CreateRevision),
            ModRevision:    parseInt64(kv.ModRevision),
        }
    }

    logMsg(LOG_INFO, "Loaded entries from etcd: %d (last revision: %d)", ipTableLen(), revision)
}


func etcdPut(key string, value interface{}) error {

    data, _ := json.Marshal(value)

    body := map[string]string{
        "key":   b64(key),
        "value": b64(string(data)),
    }

    payload, _ := json.Marshal(body)

    resp, err := http.Post(
        gEtcdEndpoint+"/v3/kv/put",
        "application/json",
        bytes.NewBuffer(payload),
    )

    if err != nil {
        return err
    }

    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return fmt.Errorf("etcd put failed")
    }

    return nil
}

func etcdDelete(key string) {

    body := map[string]string{
        "key": b64(key),
    }

    data, _ := json.Marshal(body)

    http.Post(
        gEtcdEndpoint+"/v3/kv/deleterange",
        "application/json",
        bytes.NewBuffer(data),
    )
}

func etcdRange(prefix string) ([]EtcdKV, int64, error) {

    body := map[string]string{
        "key":       b64(prefix),
        "range_end": b64(prefix + "\xff"),
    }

    data, _ := json.Marshal(body)

    resp, err := http.Post(
        gEtcdEndpoint+"/v3/kv/range",
        "application/json",
        bytes.NewBuffer(data),
    )

    if err != nil {
        return nil, 0, err
    }

    defer resp.Body.Close()

    raw, _ := io.ReadAll(resp.Body)

    var r struct {
        Header struct {
            Revision string `json:"revision"`
        } `json:"header"`

        Kvs []EtcdKV `json:"kvs"`
    }

    json.Unmarshal(raw, &r)

    revision, _ := strconv.ParseInt(r.Header.Revision, 10, 64)

    return r.Kvs, revision, nil
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
            logMsg(LOG_INFO, "etcd is available")
            return
        }

        if resp != nil {
            resp.Body.Close()
        }

        now := time.Now()

        if now.After(nextReport) {
            logMsg(LOG_INFO, "Waiting for etcd at %s (elapsed %d)", endpoint, int(now.Sub(start).Seconds()))
            nextReport = now.Add(reportInterval)
        }

        if now.Sub(start) > maxWait {
            logFatal("Etcd did not become available within %s", maxWait)
        }

        time.Sleep(retryInterval)
    }
}

