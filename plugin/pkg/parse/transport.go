package parse

import (
	"ohmydns2/plugin/pkg/transport"
	"strings"
)

// Transport 函数返回 s 中定义的传输协议和一个删除传输前缀的字符串(如果有)。如果未定义传输协议，则默认为传输DNS(Do53)
func Transport(s string) (trans string, addr string) {
	switch {
	case strings.HasPrefix(s, transport.TLS+"://"):
		s = s[len(transport.TLS+"://"):]
		return transport.TLS, s

	case strings.HasPrefix(s, transport.DNS+"://"):
		s = s[len(transport.DNS+"://"):]
		return transport.DNS, s

	case strings.HasPrefix(s, transport.GRPC+"://"):
		s = s[len(transport.GRPC+"://"):]
		return transport.GRPC, s

	case strings.HasPrefix(s, transport.HTTPS+"://"):
		s = s[len(transport.HTTPS+"://"):]

		return transport.HTTPS, s
	case strings.HasPrefix(s, transport.UNIX+"://"):
		s = s[len(transport.UNIX+"://"):]
		return transport.UNIX, s
	}

	return transport.DNS, s
}
