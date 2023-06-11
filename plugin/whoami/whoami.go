package whoami

import (
	"context"
	"net"
	"ohmydns2/plugin/pkg/request"
	"strconv"

	"github.com/miekg/dns"
)

type Whoami struct{}

func (wh Whoami) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{Req: r, W: w}

	a := new(dns.Msg)
	a.SetReply(r)
	a.Authoritative = true

	ip := state.IP()
	var rr dns.RR

	switch state.Family() {
	case 1:
		rr := new(dns.A)
		rr.Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeA, Class: state.QClass()}
		rr.A = net.ParseIP(ip)
	case 2:
		rr := new(dns.AAAA)
		rr.Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: state.QClass()}
		rr.AAAA = net.ParseIP(ip)
	}

	srv := new(dns.SRV)
	srv.Hdr = dns.RR_Header{Name: "_" + state.Proto() + "." + state.QName(), Rrtype: dns.TypeSRV, Class: state.QClass()}
	// 只请求根的特殊情况
	if state.QName() == "." {
		srv.Hdr.Name = "_" + state.Proto() + state.QName()
	}
	port, _ := strconv.ParseUint(state.Port(), 10, 16)
	srv.Port = uint16(port)
	srv.Target = "."

	a.Extra = []dns.RR{rr, srv}

	w.WriteMsg(a)

	return 0, nil
}

func (wh Whoami) Name() string {
	return name
}

const name = "whoami"
