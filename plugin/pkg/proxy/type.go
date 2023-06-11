package proxy

import "net"

type transportType int

const (
	typeUDP transportType = iota
	typeTCP
	typeTLS
	typeHTTPS
	typeTotalCount // keep this last
)

func stringToTransportType(s string) transportType {
	switch s {
	case "udp":
		return typeUDP
	case "tcp":
		return typeTCP
	case "tcp-tls":
		return typeTLS
	case "tcp-https":
		return typeHTTPS
	}

	return typeUDP
}

func (t *Transport) transportTypeFromConn(pc *persistConn) transportType {
	if _, ok := pc.c.Conn.(*net.UDPConn); ok {
		return typeUDP
	}

	if t.tlsConfig == nil {
		return typeTCP
	}
	// TODO:判断HTTPS和TLS
	return typeTLS
}
