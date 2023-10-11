package v64dns

import (
	"context"
	"github.com/miekg/dns"
	olog "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/pkg/request"
	"ohmydns2/plugin/v64dns/analyze"
	"strings"
)

// 针对v64dns请求的抽象
//type v64Request struct {
//	eid string // 请求归属的实验ID
//}

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
	// 请求域名
	qname := strings.ToLower(state.QName())
	switch v.VaildRequest(qname) {
	case 0:
		//	正常请求
		log.Info("Receive:" + state.QName() + "====>" + state.Type())
		//v64 := &v64Request{eid: v.ExtractEid(state.QName())}
		//ip := state.IP()
		msg = v.ResponseHandler(msg, state)
	case 2:
		log.Info("按照mini请求处理")
		//	Qname mini
		msg = v.ResponseNSorAdd(msg, state, 1)
	case 1:
		//其他请求不响应
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
