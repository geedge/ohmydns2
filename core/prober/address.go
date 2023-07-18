package prober

import (
	"fmt"
	"net"
	"strings"
)

type addr struct {
	Port      string
	Transport string // HTTP
	Address   string // used for bound addr - validation of overlapping
}

// String returns the string representation of addr.
func (a addr) String() string {
	s := "探测服务: " + a.Transport + "://" + ":" + a.Port
	if a.Address != "" {
		s += " on " + a.Address
	}
	return s
}

// SplitProtocolHostPort splits a full formed address like "dns://[::1]:53" into parts.
func SplitProtocolHostPort(address string) (protocol string, ip string, port string, err error) {
	parts := strings.Split(address, "://")
	switch len(parts) {
	case 1:
		ip, port, err := net.SplitHostPort(parts[0])
		return "", ip, port, err
	case 2:
		ip, port, err := net.SplitHostPort(parts[1])
		return parts[0], ip, port, err
	default:
		return "", "", "", fmt.Errorf("provided value is not in an address format : %s", address)
	}
}

type zoneOverlap struct {
	registeredAddr map[addr]addr // each zoneAddr is registered once by its key
	unboundOverlap map[addr]addr // the "no bind" equiv Addr is registered by its original key
}

func newOverlapZone() *zoneOverlap {
	return &zoneOverlap{registeredAddr: make(map[addr]addr), unboundOverlap: make(map[addr]addr)}
}

// registerAndCheck adds a new zoneAddr for validation, it returns information about existing or overlapping with already registered
// we consider that an unbound address is overlapping all bound addresses for same zone, same port
func (zo *zoneOverlap) registerAndCheck(a addr) (existingZone *addr, overlappingZone *addr) {
	existingZone, overlappingZone = zo.check(a)
	if existingZone != nil || overlappingZone != nil {
		return existingZone, overlappingZone
	}
	// there is no overlap, keep the current zoneAddr for future checks
	zo.registeredAddr[a] = a
	zo.unboundOverlap[a.unbound()] = a
	return nil, nil
}

// check validates a zoneAddr for overlap without registering it
func (zo *zoneOverlap) check(a addr) (existingAddr *addr, overlappingAddr *addr) {
	if exist, ok := zo.registeredAddr[a]; ok {
		// exact same zone already registered
		return &exist, nil
	}
	uz := a.unbound()
	if already, ok := zo.unboundOverlap[uz]; ok {
		if a.Address == "" {
			// current is not bound to an address, but there is already another zone with a bind address registered
			return nil, &already
		}
		if _, ok := zo.registeredAddr[uz]; ok {
			// current zone is bound to an address, but there is already an overlapping zone+port with no bind address
			return nil, &uz
		}
	}
	// there is no overlap
	return nil, nil
}

// unbound returns an unbound version of the zoneAddr
func (a addr) unbound() addr {
	return addr{Address: "", Port: a.Port, Transport: a.Transport}
}
