package reuseport

import (
	"context"
	"net"
)

// Listen announces on the local network address. See net.Listen for more information.
// If SO_REUSEPORT is available it will be set on the socket.
func Listen(network, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: control}
	return lc.Listen(context.Background(), network, addr)
}

// ListenPacket announces on the local network address. See net.ListenPacket for more information.
// If SO_REUSEPORT is available it will be set on the socket.
func ListenPacket(network, addr string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: control}
	return lc.ListenPacket(context.Background(), network, addr)
}
