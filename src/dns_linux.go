//go:build linux

// open-blocklist - Linux-specific DNS socket tuning
// Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE

package main

import (
	"net"
	"syscall"
)

func setUDPReceiveBuffer(conn net.PacketConn) {
	rawConn, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		logMsg(LOG_ERROR, "DNS: cannot get raw conn for SO_RCVBUF: %v", err)
		return
	}

	rawConn.Control(func(fd uintptr) {
		// Request 4 MiB; the kernel may cap this at net.core.rmem_max.
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4*1024*1024); err != nil {
			logMsg(LOG_ERROR, "DNS: failed to set SO_RCVBUF: %v", err)
		}
	})
}
