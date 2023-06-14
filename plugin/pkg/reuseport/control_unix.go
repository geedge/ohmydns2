//go:build linux
// +build linux

package reuseport

import (
	"golang.org/x/sys/unix"
	"ohmydns2/plugin/pkg/log"
	"runtime"
	"syscall"
)

func control(network, address string, c syscall.RawConn) error {
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
