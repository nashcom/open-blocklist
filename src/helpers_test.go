// open-blocklist - An open blocklist tool - helper unit tests
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
package main

import (
    "testing"
)

func TestIPv4StrToUint32(t *testing.T) {
    cases := []struct {
        in   string
        want uint32
    }{
        {"1.2.3.4",           0x01020304},
        {"0.0.0.0",           0x00000000},
        {"255.255.255.255",   0xFFFFFFFF},
        {"127.0.0.1",         0x7F000001},
        {"192.168.1.100",     0xC0A80164},
        {"10.0.0.1",          0x0A000001},
        {"256.0.0.1",         0},          // octet out of range
        {"",                  0},          // empty
        {"not.an.ip.address", 0},          // non-numeric
        {"1.2.3",             0},          // too few octets
        {"1.2.3.4.5",         0},          // too many octets
        {"1.2.3.-1",          0},          // negative (catches the '-' char)
        {"1.2.3.4x",          0},          // trailing garbage
    }

    for _, tc := range cases {
        got := IPv4StrToUint32(tc.in)
        if got != tc.want {
            t.Errorf("IPv4StrToUint32(%q) = 0x%08X, want 0x%08X", tc.in, got, tc.want)
        }
    }
}

func TestUint32ToIPv4Str(t *testing.T) {
    cases := []struct {
        in   uint32
        want string
    }{
        {0x01020304, "1.2.3.4"},
        {0x00000000, "0.0.0.0"},
        {0xFFFFFFFF, "255.255.255.255"},
        {0x7F000001, "127.0.0.1"},
        {0xC0A80164, "192.168.1.100"},
    }

    for _, tc := range cases {
        got := Uint32ToIPv4Str(tc.in)
        if got != tc.want {
            t.Errorf("Uint32ToIPv4Str(0x%08X) = %q, want %q", tc.in, got, tc.want)
        }
    }
}

func TestRoundtripIPv4(t *testing.T) {
    ips := []string{
        "1.2.3.4",
        "10.0.0.1",
        "172.16.0.100",
        "192.168.255.255",
        "255.255.255.255",
        "0.0.0.0",
    }

    for _, ip := range ips {
        n := IPv4StrToUint32(ip)
        got := Uint32ToIPv4Str(n)
        if got != ip {
            t.Errorf("roundtrip(%q) → 0x%08X → %q", ip, n, got)
        }
    }
}

func TestIsIPv4(t *testing.T) {
    valid := []string{
        "1.2.3.4",
        "0.0.0.0",
        "255.255.255.255",
        "192.168.1.1",
        "127.0.0.1",
    }
    invalid := []string{
        "",
        "not.an.ip.address",
        "256.0.0.1",
        "1.2.3",
        "::1",
        "2001:db8::1",
        "1.2.3.4.5",
    }

    for _, s := range valid {
        if !IsIPv4(s) {
            t.Errorf("IsIPv4(%q) = false, want true", s)
        }
    }
    for _, s := range invalid {
        if IsIPv4(s) {
            t.Errorf("IsIPv4(%q) = true, want false", s)
        }
    }
}
