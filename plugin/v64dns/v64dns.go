package v64dns

import (
	"context"
	"net"
	olog "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/pkg/request"
	"ohmydns2/plugin/v64dns/analyze"

	"github.com/miekg/dns"
)

// 针对v64dns请求的抽象
type v64Request struct {
	eid string // 请求归属的实验ID
}

// V64dns代表了水印权威
type V64dns struct {
	zone     string
	ipv4NS   string
	ipv6NS   string
	V4NSAddr string
	V6NSAddr string
	p        Policy           // 生成响应的策略
	a        analyze.Analyzer // 分析器配置
}

// ServeDNS
//
//	@Description: v64dns主要处理程序
//	@receiver d
//	@param ctx
//	@param w
//	@param r
//	@return int
//	@return error
func (v V64dns) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	// 请求的源地址
	switch v.VaildRequest(state.QName()) {
	case 0:
		//	正常请求
		v64 := &v64Request{eid: "test"}
		ip := state.IP()
		msg = v.ResponseHandler(msg, net.ParseIP(ip), *v64)
	case 2:
		log.Info("按照mini请求处理")
		//	Qname mini
		msg = v.ResponseNS(msg)
	case 1:
		return 0, nil
	}

	err := w.WriteMsg(msg)
	if err != nil {
		olog.Info(err.Error())
		return dns.RcodeServerFailure, err
	}
	return 0, nil
}

// 实现Handler接口
func (v V64dns) Name() string {
	return name
}

const name = "v64dns"
