package forward

import (
	"net"
	"ohmydns2/plugin/dnstap/msg"
	"ohmydns2/plugin/pkg/proxy"
	"ohmydns2/plugin/pkg/request"
	"strconv"
	"time"

	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

// toDnstap will send the forward and received message to the dnstap plugin.
func toDnstap(f *Forward, host string, state request.Request, opts proxy.Options, reply *dns.Msg, start time.Time) {
	h, p, _ := net.SplitHostPort(host)      // this is preparsed and can't err here
	port, _ := strconv.ParseUint(p, 10, 32) // same here
	ip := net.ParseIP(h)

	var ta net.Addr = &net.UDPAddr{IP: ip, Port: int(port)}
	t := state.Proto()
	switch {
	case opts.ForceTCP:
		t = "tcp"
	case opts.PreferUDP:
		t = "udp"
	}

	if t == "tcp" {
		ta = &net.TCPAddr{IP: ip, Port: int(port)}
	}

	for _, t := range f.tapPlugins {
		// Query
		q := new(tap.Message)
		msg.SetQueryTime(q, start)
		// Forwarder dnstap messages are from the perspective of the downstream server
		// (upstream is the forward server)
		msg.SetQueryAddress(q, state.W.RemoteAddr())
		msg.SetResponseAddress(q, ta)
		if t.IncludeRawMessage {
			buf, _ := state.Req.Pack()
			q.QueryMessage = buf
		}
		msg.SetType(q, tap.Message_FORWARDER_QUERY)
		t.TapMessage(q)

		// Response
		if reply != nil {
			r := new(tap.Message)
			if t.IncludeRawMessage {
				buf, _ := reply.Pack()
				r.ResponseMessage = buf
			}
			msg.SetQueryTime(r, start)
			msg.SetQueryAddress(r, state.W.RemoteAddr())
			msg.SetResponseAddress(r, ta)
			msg.SetResponseTime(r, time.Now())
			msg.SetType(r, tap.Message_FORWARDER_RESPONSE)
			t.TapMessage(r)
		}
	}
}
