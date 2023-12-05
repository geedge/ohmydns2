package v64dns

import (
	"github.com/miekg/dns"
	"net"
	"ohmydns2/plugin/pkg/request"
	"strconv"
	"strings"
)

// Policy 定义了权威生成记录可用的方法
type Policy struct {
	v4domain    string
	v6domain    string
	v4subdomain string
	v6subdomain string
	ipEmbed     bool
	maxLen      int  //解析链最大长度
	dmChange    bool //是否切换域名
}

// ResponseHandler 跨栈解析响应主要处理函数
func (v V64dns) ResponseHandler(msg *dns.Msg, state request.Request) *dns.Msg {
	step, _ := strconv.Atoi(string(rune(state.QName()[1])))

	// 未到达最后一步
	if step < v.p.maxLen {
		return v.ResponseCNAME(msg, state)
	}
	// 到达最后一步
	switch state.QType() {
	// 只处理TXT，CNAME，AAAA记录
	case dns.TypeTXT, dns.TypeCNAME, dns.TypeAAAA:
		return v.ResponseTXT(msg, state)
	case dns.TypeNS:
		return v.ResponseNSorAdd(msg, state, 0)
	default:
		log.Info("no")
		// 不符合要求的请求类型直接返回空响应
		return msg
	}
}

// ResponseTXT 响应TXT，认为到达最后一步
func (v V64dns) ResponseTXT(msg *dns.Msg, state request.Request) *dns.Msg {
	qname := strings.ToLower(state.QName())

	// 记录关联关系
	dSlice := strings.Split(strings.ToLower(qname), ".")
	if len(dSlice) > 4 {
		// 将最近一次编码拆分开
		cList := strings.Split(dSlice[len(dSlice)-5], "-")
		iaddr := ""
		// 首部编码如果长度为4则为IPv6地址编码，否则为IPv4的
		if len(cList[0]) == 4 {
			iaddr = strings.ReplaceAll(dSlice[len(dSlice)-6], "-", ":")
			msg = v.SetAuthAdd(msg, state, 4)
		} else {
			iaddr = strings.ReplaceAll(dSlice[len(dSlice)-6], "-", ".")
			msg = v.SetAuthAdd(msg, state, 6)
		}
		iaddr = net.ParseIP(iaddr).String()
		oaddr := state.IP()
		// 调用Python
		go v.a.Go2py([]string{iaddr, oaddr, "1"})

	}

	answer := new(dns.TXT)
	answer.Txt = []string{state.QName()}
	answer.Hdr = dns.RR_Header{Name: state.QName(), Ttl: 3600, Class: dns.ClassINET, Rrtype: dns.TypeTXT}
	msg.Answer = append(msg.Answer, answer)
	return msg
}

// ResponseNSorAdd  0返回NS记录应答，1返回胶水记录
func (v V64dns) ResponseNSorAdd(msg *dns.Msg, state request.Request, flag int) *dns.Msg {
	qname := strings.ToLower(state.QName())
	//sub := ""
	//for _, qs := range strings.Split(qname, ".") {
	//	switch v.MatchType(qs) {
	//	case 2:
	//		sub = qs
	//	}
	//}

	answer := new(dns.NS)
	answer.Hdr.Ttl = 3600
	answer.Hdr.Class = dns.ClassINET
	answer.Hdr.Rrtype = dns.TypeNS
	answer.Hdr.Name = state.QName()

	if strings.ContainsAny(qname, v.p.v6domain) {
		answer.Ns = v.ipv6NS
		msg = v.SetAuthAdd(msg, state, 6)
	} else {
		answer.Ns = v.ipv4NS
		msg = v.SetAuthAdd(msg, state, 4)
	}

	if flag == 0 {
		msg.Answer = append(msg.Answer, answer)
	}

	return msg
}

// ResponseCNAME 响应CNAME记录，生成方式为：
// [进度标识].[随机数].[水印].[子域名].[实验域名]
// ====>[进度标识].[随机数].[水印].<新水印>.<新子域名>.[实验域名]
func (v V64dns) ResponseCNAME(msg *dns.Msg, state request.Request) *dns.Msg {
	qname := state.QName()

	dSlice := strings.Split(strings.ToLower(qname), ".")
	if len(dSlice) > 4 {
		// 将最近一次编码拆分开
		cList := strings.Split(dSlice[len(dSlice)-5], "-")
		iaddr := ""
		// 首部编码如果长度为4则为IPv6地址编码，否则为IPv4的
		if len(cList[0]) == 4 {
			iaddr = strings.ReplaceAll(dSlice[len(dSlice)-6], "-", ":")
			msg = v.SetAuthAdd(msg, state, 4)
		} else {
			iaddr = strings.ReplaceAll(dSlice[len(dSlice)-6], "-", ".")
			msg = v.SetAuthAdd(msg, state, 6)
		}
		iaddr = net.ParseIP(iaddr).String()
		oaddr := state.IP()
		// 调用Python脚本
		step, _ := strconv.Atoi(string(rune(state.QName()[1])))
		if step == 1 {
			go v.a.Go2py([]string{iaddr, oaddr, "0"})
		} else {
			go v.a.Go2py([]string{iaddr, oaddr, "1"})
		}

	}

	answer := new(dns.CNAME)
	answer.Hdr = dns.RR_Header{
		Name:   qname,
		Rrtype: dns.TypeCNAME,
		Class:  dns.ClassINET,
		Ttl:    1,
	}

	// 响应内容
	// 实验进度+1
	answer.Target += nextProgress(dSlice[0]) + "."
	// 内容填充
	for _, i := range dSlice[1 : len(dSlice)-5] {
		answer.Target += i + "."
	}
	answer.Target += ip2id(state.IP()) + "."
	answer.Target += dSlice[len(dSlice)-5] + "."
	answer.Target += v.changeSubDomain(dSlice[len(dSlice)-4]) + "."
	for _, i := range dSlice[len(dSlice)-3 : len(dSlice)-1] {
		answer.Target += i + "."
	}
	msg.Answer = append(msg.Answer, answer)
	log.Debug(answer)
	return msg
}

const (
	v6 = 0
	v4 = 1
	//interval = 20
)
