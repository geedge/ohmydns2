//go:build windows
// +build windows

package reuseport

import (
	"ohmydns2/plugin/pkg/log"
	"runtime"
	"syscall"
)

func control(networking, address string, c syscall.RawConn) error {
	if runtime.GOOS == "windows" {
		c.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
				log.Warningf("Failed to set SO_REUSEADDR on socket: %s", err)
			}
		})
	}

	return nil
}
