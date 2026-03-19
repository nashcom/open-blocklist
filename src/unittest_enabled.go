//go:build unittest

// open-blocklist - An open blocklist tool - unit tests
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
package main

import "fmt"

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------

type unitTest struct {
    name   string
    passed bool
    msg    string
}

type testSuite struct {
    name    string
    tests   []unitTest
    passed  int
    failed  int
}

func newSuite(name string) *testSuite {
    return &testSuite{name: name}
}

func (s *testSuite) check(name string, ok bool, format string, args ...any) {
    msg := ""
    if !ok {
        msg = fmt.Sprintf(format, args...)
    }
    s.tests = append(s.tests, unitTest{name: name, passed: ok, msg: msg})
    if ok {
        s.passed++
    } else {
        s.failed++
    }
}

func (s *testSuite) equalU32(name string, got, want uint32) {
    s.check(name, got == want, "got 0x%08X, want 0x%08X", got, want)
}

func (s *testSuite) equalStr(name string, got, want string) {
    s.check(name, got == want, "got %q, want %q", got, want)
}

func (s *testSuite) isTrue(name string, got bool) {
    s.check(name, got, "expected true")
}

func (s *testSuite) isFalse(name string, got bool) {
    s.check(name, !got, "expected false")
}

func (s *testSuite) hasError(name string, err error) {
    s.check(name, err != nil, "expected error, got nil")
}

func (s *testSuite) noError(name string, err error) {
    s.check(name, err == nil, "unexpected error: %v", err)
}

func (s *testSuite) report() {
    logMsg(LOG_INFO, "Suite %-30s  %d passed  %d failed", s.name, s.passed, s.failed)
    for _, t := range s.tests {
        if !t.passed {
            logMsg(LOG_ERROR, "  FAIL  %s — %s", t.name, t.msg)
        }
    }
}

// ---------------------------------------------------------------------------
// IP conversion test suite
// ---------------------------------------------------------------------------

func testIPConversion() *testSuite {
    s := newSuite("IP conversion")

    // -- IPv4StrToUint32 ----------------------------------------------------

    s.equalU32("IPv4StrToUint32 1.2.3.4",           IPv4StrToUint32("1.2.3.4"),           0x01020304)
    s.equalU32("IPv4StrToUint32 0.0.0.0",           IPv4StrToUint32("0.0.0.0"),           0x00000000)
    s.equalU32("IPv4StrToUint32 255.255.255.255",    IPv4StrToUint32("255.255.255.255"),   0xFFFFFFFF)
    s.equalU32("IPv4StrToUint32 127.0.0.1",          IPv4StrToUint32("127.0.0.1"),         0x7F000001)
    s.equalU32("IPv4StrToUint32 10.0.0.1",           IPv4StrToUint32("10.0.0.1"),          0x0A000001)
    s.equalU32("IPv4StrToUint32 256.0.0.1",          IPv4StrToUint32("256.0.0.1"),         0)
    s.equalU32("IPv4StrToUint32 empty",              IPv4StrToUint32(""),                  0)
    s.equalU32("IPv4StrToUint32 non-numeric",        IPv4StrToUint32("not.an.ip.address"), 0)
    s.equalU32("IPv4StrToUint32 too few octets",     IPv4StrToUint32("1.2.3"),             0)
    s.equalU32("IPv4StrToUint32 too many octets",    IPv4StrToUint32("1.2.3.4.5"),         0)
    s.equalU32("IPv4StrToUint32 negative octet",     IPv4StrToUint32("1.2.3.-1"),          0)
    s.equalU32("IPv4StrToUint32 trailing garbage",   IPv4StrToUint32("1.2.3.4x"),          0)

    // -- Uint32ToIPv4Str ----------------------------------------------------

    s.equalStr("Uint32ToIPv4Str 0x01020304", Uint32ToIPv4Str(0x01020304), "1.2.3.4")
    s.equalStr("Uint32ToIPv4Str 0x00000000", Uint32ToIPv4Str(0x00000000), "0.0.0.0")
    s.equalStr("Uint32ToIPv4Str 0xFFFFFFFF", Uint32ToIPv4Str(0xFFFFFFFF), "255.255.255.255")
    s.equalStr("Uint32ToIPv4Str 0x7F000001", Uint32ToIPv4Str(0x7F000001), "127.0.0.1")

    // -- Roundtrip ----------------------------------------------------------

    for _, ip := range []string{"1.2.3.4", "10.0.0.1", "192.168.1.100", "255.255.255.255", "0.0.0.0"} {
        got := Uint32ToIPv4Str(IPv4StrToUint32(ip))
        s.equalStr("roundtrip "+ip, got, ip)
    }

    // -- IsIPv4 -------------------------------------------------------------

    for _, ip := range []string{"1.2.3.4", "0.0.0.0", "255.255.255.255", "127.0.0.1"} {
        s.isTrue("IsIPv4 valid "+ip, IsIPv4(ip))
    }
    for _, ip := range []string{"", "not.an.ip.address", "256.0.0.1", "1.2.3", "::1", "2001:db8::1"} {
        s.isFalse("IsIPv4 invalid "+ip, IsIPv4(ip))
    }

    // -- IsIPv6 -------------------------------------------------------------

    for _, ip := range []string{"::1", "2001:db8::1", "fe80::1"} {
        s.isTrue("IsIPv6 valid "+ip, IsIPv6(ip))
    }
    for _, ip := range []string{"", "1.2.3.4", "not-an-ip"} {
        s.isFalse("IsIPv6 invalid "+ip, IsIPv6(ip))
    }

    // -- IsValidIP ----------------------------------------------------------

    for _, ip := range []string{"1.2.3.4", "0.0.0.0", "255.255.255.255", "::1", "2001:db8::1"} {
        s.isTrue("IsValidIP valid "+ip, IsValidIP(ip))
    }
    for _, ip := range []string{"", "256.0.0.1", "not.an.ip.address", "1.2.3", "1.2.3.4.5"} {
        s.isFalse("IsValidIP invalid "+ip, IsValidIP(ip))
    }

    return s
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func runUnitTests() bool {
    logSpace()
    logMsg(LOG_INFO, "Running unit tests")
    logMsg(LOG_INFO, "%s", dashLine(40))

    suites := []*testSuite{
        testIPConversion(),
    }

    totalPassed := 0
    totalFailed := 0

    for _, s := range suites {
        s.report()
        totalPassed += s.passed
        totalFailed += s.failed
    }

    logMsg(LOG_INFO, "%s", dashLine(40))
    logMsg(LOG_INFO, "Unit tests: %d passed  %d failed", totalPassed, totalFailed)
    logSpace()

    if totalFailed > 0 {
        logMsg(LOG_ERROR, "Unit tests FAILED — aborting startup")
        return false
    }

    logMsg(LOG_INFO, "Unit tests passed")
    logSpace()

    return true
}
