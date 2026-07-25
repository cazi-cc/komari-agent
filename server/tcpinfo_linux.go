//go:build linux

package server

import (
	"crypto/tls"
	"net"

	"golang.org/x/sys/unix"
)

func tcpRetransmissions(conn net.Conn) int {
	if conn == nil {
		return 0
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return 0
	}
	total := 0
	_ = raw.Control(func(fd uintptr) {
		info, infoErr := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if infoErr == nil {
			total = int(info.Total_retrans)
		}
	})
	return total
}
