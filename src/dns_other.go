//go:build !linux

// open-blocklist - DNS socket tuning stub for non-Linux platforms
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import "net"

func setUDPReceiveBuffer(conn net.PacketConn) {
	// SO_RCVBUF tuning is Linux-only; no-op on other platforms.
}
