package v64dns

import (
	"net"
	"ohmydns2/plugin/v64dns/analyze"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Policy 定义了权威生成记录可用的方法
type Policy struct {
	v4domain    string
	v6domain    string
	v4subdomain string
	v6subdomain string
	ipEmbed     bool
	maxLen      int //解析链最大长度
}

// expobject 代表了每个实验对象
type expobject struct {
	eid      string
	interval int  //实验对象的等待间隔，超过则认为实验过程存在问题导致只有部分请求
	isAll    bool //实验对象对应过程是否完整
	progress int  // 实验进度
	chain    []net.IP
}

// 向域名链中添加IP
func (e expobject) Addchain(ip net.IP) {
	e.chain = append(e.chain, ip)
}

// 停止实验，根据倒计时停止
func (e expobject) Stop(a analyze.Analyzer) {
	// 如果到达时间限制则通过管道通知停止
	timeTicker := time.NewTicker(1 * time.Second)
	i := e.interval
	for {
		<-timeTicker.C
		i--
		// 计时结束或者完成本次实验之后停止
		if i == 0 || e.isAll {
			el.c <- e.eid
			a.AnalyzeChain(e.chain)

			break
		}
	}
}

// 增加实验进度
func (e expobject) AddProgress() {
	e.progress += 1
}

type explist struct {
	m sync.Mutex
	l map[string]expobject
	c chan string
}

var el = NewExpList()

// 为explist创建空间
func NewExpList() *explist {
	el := new(explist)
	el.c = make(chan string, 5)
	el.l = make(map[string]expobject)
	return el
}

// 持续监听管道信息，删除对应eid
func (el *explist) Stop() {
	for {
		eid := <-el.c
		el.m.Lock()
		delete(el.l, eid)
		el.m.Unlock()
	}
}

// 增加实验对象
func (el *explist) Add(eid string, sip net.IP) {
	el.m.Lock()
	n := expobject{
		eid:      "",
		interval: interval,
		isAll:    false,
		progress: 1,
		chain:    []net.IP{sip},
	}
	el.l[eid] = n
	el.m.Unlock()
}

func (v V64dns) ResponseHandler(msg *dns.Msg, sip net.IP, v64r v64Request) *dns.Msg {
	switch msg.Question[0].Qtype {
	case dns.TypeTXT, dns.TypeCNAME:
		if eo, ok := el.l[v64r.eid]; ok {
			//	存在该实验id
			step := strings.Split(msg.Question[0].Name, ".")[0][1]
			if int(step) < v.p.maxLen {
				eo.Addchain(sip)
				eo.AddProgress()
				// 未到达最后一步
				return v.ResponseCNAME(msg, sip)
			}
			// 到达最后一步
			eo.isAll = true
			return v.ResponseTXT(msg)
		}
		//不存在，则认为是新到来的
		el.Add(v64r.eid, sip)
		return v.ResponseCNAME(msg, sip)

	case dns.TypeNS:
		return v.ResponseNS(msg)
	default:
		// 不符合要求的请求类型直接返回空响应
		return msg.SetReply(msg)
	}
}

// ResponseTXT 响应TXT，认为到达最后一步
func (v V64dns) ResponseTXT(msg *dns.Msg) *dns.Msg {
	qname := msg.Question[0].Name
	expid := ""
	sub := ""
	for _, qs := range strings.Split(qname, ".") {
		switch v.MatchType(qs) {
		case 5:
			expid = qs
		case 2:
			sub = qs
		}
	}
	ans := el.l[expid].IPchain2Str()

	answer := new(dns.TXT)
	answer.Txt = ans
	answer.Hdr.Class = dns.ClassINET
	answer.Hdr.Ttl = 3600
	answer.Hdr.Name = qname
	answer.Hdr.Rrtype = dns.TypeTXT

	res := msg.SetReply(msg)
	res = v.SetAuthAdd(res, sub)
	res.Answer = append(res.Answer, answer)
	return res
}

// ResponseNS 返回NS记录
func (v V64dns) ResponseNS(msg *dns.Msg) *dns.Msg {
	qname := msg.Question[0].Name
	sub := ""
	for _, qs := range strings.Split(qname, ".") {
		switch v.MatchType(qs) {
		case 2:
			sub = qs
		}
	}

	answer := new(dns.NS)
	answer.Hdr.Ttl = 3600
	answer.Hdr.Class = dns.ClassINET
	answer.Hdr.Rrtype = dns.TypeNS
	answer.Hdr.Name = qname

	if sub == v.p.v6subdomain {
		answer.Ns = v.ipv6NS
	} else {
		answer.Ns = v.ipv4NS
	}
	res := msg.SetReply(msg)
	res = v.SetAuthAdd(res, sub)
	res.Answer = append(res.Answer, answer)

	return res
}

// ResponseCNAME 响应CNAME记录
func (v V64dns) ResponseCNAME(msg *dns.Msg, sip net.IP) *dns.Msg {
	qname := msg.Question[0].Name
	var (
		maskPart  = ""
		subdomain = ""
		zone      = ""
		ran       = ""
		prog      = ""
		expid     = ""
	)

	for _, qs := range strings.Split(qname, ".") {
		switch v.MatchType(qs) {
		case 1:
			maskPart += qs + "."
		case 2:
			subdomain = changeSubDomain(qs)
		case 5:
			expid = qs
		case 4:
			prog = nextProgress(qs)
		case 3:
			ran = qs
		default:
			if qs != "" {
				zone = zone + qs + "."
			}

		}
	}
	maskPart = maskPart + strings.ReplaceAll(sip.String(), ".", "-")
	answer := new(dns.CNAME)
	answer.Hdr = dns.RR_Header{
		Name:   qname,
		Rrtype: dns.TypeCNAME,
		Class:  dns.ClassINET,
		Ttl:    1,
	}

	// 响应内容
	answer.Target = prog + "." + expid + "." + maskPart + "." + ran + "." + subdomain + "." + zone

	msg = v.SetAuthAdd(msg, subdomain)
	msg.Answer = append(msg.Answer, answer)

	return msg
}

const (
	v6       = 0
	v4       = 1
	interval = 20
)
