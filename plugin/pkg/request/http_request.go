package request

import (
	"net/http"
)

// HTTPRequest contains some connection state and is useful in plugin.
type HTTPRequest struct {
	Req *http.Request
	W   http.ResponseWriter

	// Optional lowercased zone of this query.
	Zone string

	// Cache size after first call to Size or Do. If size is zero nothing has been cached yet.
	// Both Size and Do set these values (and cache them).
	size uint16 // UDP buffer size, or 64K in case of TCP.

	// Caches
	family    int8   // transport's family.
	ip        string // client's ip.
	port      string // client's port.
	localPort string // server's port.
	localIP   string // server's ip.
}
