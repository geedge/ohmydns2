package reuseport

import (
	"context"
	"net"
	"runtime"
	"syscall"

	"ohmydns2/plugin/pkg/log"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"
)

func control(network, address string, c syscall.RawConn) error {
	if runtime.GOOS == "windows" {
		c.Control(func(fd uintptr) {
			// 注意到windows缺少REUSEPORT调用，使用REUSEADDR代替
			if err := windows.SetsockoptInt(windows.Handle(int(fd)), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
				log.Warningf("Failed to set SO_REUSEPORT on socket: %s", err)
			}

		})
		return nil
	}
	if runtime.GOOS == "linux" {
		// *unix system
		c.Control(func(fd uintptr) {
			if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
				log.Warningf("Failed to set SO_REUSEPORT on socket: %s", err)
			}
		})
	}

	return nil
}

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
