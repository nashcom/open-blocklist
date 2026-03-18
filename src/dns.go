// open-blocklist - An open blocklist tool / dns routines
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

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
        logMsg(LOG_ERROR, "[DNS Query]: Unexpected multiple questions (%d), using first", len(r.Question))
    }

    q := r.Question[0]
    queryType := dns.TypeToString[q.Qtype]

    logMsg(LOG_DEBUG, "[DNS Requery]: Type=%s Name=%s", queryType, q.Name)

    switch q.Qtype {

    case dns.TypeA, dns.TypeAAAA:

        if !dns.IsSubDomain(gRBLZone, q.Name) {

            msg.Rcode = dns.RcodeRefused

            logMsg(LOG_VERBOSE, "[DNS Result/Refused]: Type=%s Name=%s", queryType, q.Name)
            stats.ReqDnsWrongZone.Add(1)
            break  // fall through to w.WriteMsg
        }

        ip, ok := rblQueryToIP(q.Name)
        if !ok {
            // Malformed label count — not a valid RBL query
            msg.Rcode = dns.RcodeFormatError

            logMsg(LOG_VERBOSE, "[DNS Result/Malformed]: Type=%s Name=%s", queryType, q.Name)
            stats.ReqDnsInvalidQuery.Add(1)
            break
        }

        entry, blocked := ipTableLookup(ip)
        if blocked {

            rr, _ := dns.NewRR(q.Name + " 10 IN A " + Uint32ToIPv4Str(entry.ReturnCode))
            msg.Answer = append(msg.Answer, rr)
            msg.Rcode  = dns.RcodeSuccess

            logMsg(LOG_VERBOSE, "[DNS Result/Found]: Type=%s Name=%s", queryType, q.Name)
            stats.ReqDnsBlocked.Add(1)

        } else {
            // Known zone, not listed -> NXDOMAIN (RBL semantics)
            msg.Rcode = dns.RcodeNameError

            logMsg(LOG_VERBOSE, "[DNS Result/NotFound]: Type=%s Name=%s", queryType, q.Name)
            stats.ReqDnsNotListed.Add(1)
        }

    case dns.TypePTR:

        logMsg(LOG_VERBOSE, "[DNS Query/PTR]: name=%s type=%s", q.Name, queryType)

        if !dns.IsSubDomain("in-addr.arpa.", q.Name) {
            msg.Rcode = dns.RcodeRefused

            logMsg(LOG_VERBOSE, "[DNS Result/NO-IN-ARPA]: Type=%s Name=%s", queryType, q.Name)
            stats.ReqDnsWrongZone.Add(1)
            break
        }

        ip, ok := ptrQueryToIP(q.Name)
        if !ok {
            msg.Rcode = dns.RcodeFormatError

            logMsg(LOG_VERBOSE, "[DNS Result/Invalid Query]: name=%s type=%s", q.Name, queryType)
            stats.ReqDnsInvalidQuery.Add(1)
            break
        }

        // entry
        _ , blocked := ipTableLookup(ip)

        if blocked {
            rr, _ := dns.NewRR(q.Name + " 10 IN PTR " + reverseHost + ".")
            msg.Answer = append(msg.Answer, rr)
            msg.Rcode = dns.RcodeSuccess

            logMsg(LOG_VERBOSE, "[DNS Result/Blocked]: name=%s type=%s", q.Name, queryType)
            stats.ReqDnsBlocked.Add(1)

        } else {
            // Not listed -> NXDOMAIN (RBL semantics)
            msg.Rcode = dns.RcodeNameError

            logMsg(LOG_VERBOSE, "[DNS Result/NotFound]: name=%s type=%s", q.Name, queryType)
            stats.ReqDnsNotListed.Add(1)
        }

    default:
        msg.Rcode = dns.RcodeRefused

        logMsg(LOG_VERBOSE, "[DNS Result/Unhandled]: name=%s type=%s", q.Name, queryType)
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

// ptrQueryToIP extracts the IP from a reverse DNS query name.
// e.g. 4.3.2.1.in-addr.arpa. -> 1.2.3.4
func ptrQueryToIP(qname string) (string, bool) {
    name := strings.TrimSuffix(qname, "in-addr.arpa.")
    name = strings.TrimSuffix(name, ".")
    labels := strings.Split(name, ".")
    if len(labels) != 4 {
        return "", false
    }
    // Reverse the labels
    return fmt.Sprintf("%s.%s.%s.%s",
        labels[3], labels[2], labels[1], labels[0]), true
}
