//go:build !linux

package server

import "net"

func tcpRetransmissions(_ net.Conn) int {
	return 0
}
