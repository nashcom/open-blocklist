package main

import (
    "fmt"
    "strings"
    "github.com/miekg/dns"
)


func startDNSListener(addr string) {

    logListerner("DNS", addr)

    if addr == "" {
        return
    }

    dns.HandleFunc(".", handleDNSRequest)

    udpServer := &dns.Server{
        Addr: addr,
        Net:  "udp",
    }

    tcpServer := &dns.Server{
        Addr: addr,
        Net:  "tcp",
    }

    go func() {

        logListerner("DNS-UDP", addr)

        if err := udpServer.ListenAndServe(); err != nil {
            logFatal("DNS UDP server failed: %v", err)
        }
    }()

    go func() {

        logListerner("DNS-TCP", addr)

        if err := tcpServer.ListenAndServe(); err != nil {
            logFatal("DNS TCP server failed: %v", err)
        }
    }()
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
    msg := new(dns.Msg)
    msg.SetReply(r)
    msg.Authoritative = true

    if len(r.Question) == 0 {
        msg.Rcode = dns.RcodeFormatError
        _ = w.WriteMsg(msg)

        stats.ReqDnsInvalidQuery.Add(1)
        return
    }
    if len(r.Question) > 1 {
        logMsg("DNS query: unexpected multiple questions (%d), using first", len(r.Question))
    }

    q := r.Question[0]

    switch q.Qtype {
    case dns.TypeA:
        logMsg("DNS query: name=%s type=%s", q.Name, dns.TypeToString[q.Qtype])

        if !dns.IsSubDomain(gRBLZone, q.Name) {

            msg.Rcode = dns.RcodeRefused
            break  // fall through to w.WriteMsg

            stats.ReqDnsWrongZone.Add(1)
            return
        }

        ip, ok := rblQueryToIP(q.Name)
        if !ok {
            // Malformed label count — not a valid RBL query
            msg.Rcode = dns.RcodeFormatError

            stats.ReqDnsInvalidQuery.Add(1)
            break
        }

        entry, blocked := lookup(ip)
        if blocked {

            rr, _ := dns.NewRR(q.Name + " 10 IN A " + entry.ReturnCode)
            msg.Answer = append(msg.Answer, rr)
            msg.Rcode  = dns.RcodeSuccess

            stats.ReqDnsBlocked.Add(1)

        } else {
            // Known zone, not listed -> NXDOMAIN (RBL semantics)
            msg.Rcode = dns.RcodeNameError
            stats.ReqDnsNotListed.Add(1)
        }

    default:
        logMsg("DNS query: name=%s type=%s (ignored)", q.Name, dns.TypeToString[q.Qtype])
        // Not our query type — no reply

        msg.Rcode = dns.RcodeRefused
        stats.ReqDnsOtherQueryType.Add(1)
        break
    }

    _ = w.WriteMsg(msg)
}

// rblQueryToIP extracts and reverses the IP address encoded in an RBL query name.
// Supports IPv4 (4 labels) and IPv6 nibble format (32 labels).
// Returns the IP string and true on success, or empty string and false if the
// label count is unrecognised.

func rblQueryToIP(qname string) (string, bool) {
    // Strip the zone suffix and any trailing dot to isolate the address labels
    name := strings.TrimSuffix(qname, gRBLZone)
    name = strings.TrimSuffix(name, ".")
    labels := strings.Split(name, ".")

    switch len(labels) {
    case 4:
        // IPv4: "4.3.2.1" -> "1.2.3.4"
        return fmt.Sprintf("%s.%s.%s.%s",
            labels[3], labels[2], labels[1], labels[0]), true

    case 32:
        // IPv6 nibble format: reverse 32 hex labels, group into 4-char blocks
        reversed := make([]string, 32)
        for i := 0; i < 32; i++ {
            reversed[i] = labels[31-i]
        }
        hex := strings.Join(reversed, "")
        parts := make([]string, 8)
        for i := range parts {
            parts[i] = hex[i*4 : i*4+4]
        }
        return strings.Join(parts, ":"), true

    default:
        return "", false
    }
}
