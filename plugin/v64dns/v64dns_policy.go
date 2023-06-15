package v64dns

import (
	"net"
	olog "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/v64dns/analyze"
	"strconv"
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
	interval int       //实验对象的等待间隔，超过则认为实验过程存在问题导致只有部分请求
	isAll    chan bool //实验对象对应过程是否完整
	progress int       // 实验进度
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
		select {
		case <-timeTicker.C:
			i--
			if i == 0 {
				el.c <- e.eid
				close(e.isAll)
				return
			}
		case t := <-e.isAll:
			if t == true {
				el.c <- e.eid
				close(e.isAll)
				return
			}
		}
	}
}

// 增加实验进度,返回1代表未处理，0代表进度增加
func (e expobject) AddProgress(step int) int {
	if step < e.progress {
		return 1
	}
	e.progress += 1
	return 0
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
		olog.Info("delete  " + eid)
		delete(el.l, eid)
		el.m.Unlock()
	}
}

// 增加实验对象
func (el *explist) Add(eid string, sip net.IP, a analyze.Analyzer) {
	el.m.Lock()
	n := expobject{
		eid:      eid,
		interval: interval,
		isAll:    make(chan bool),
		progress: 1,
		chain:    []net.IP{sip},
	}
	el.l[eid] = n
	go n.Stop(a)
	el.m.Unlock()
}

func (v V64dns) ResponseHandler(msg *dns.Msg, sip net.IP, v64r v64Request) *dns.Msg {
	step, _ := strconv.Atoi(string(rune(strings.Split(msg.Question[0].Name, ".")[0][1])))
	switch msg.Question[0].Qtype {
	case dns.TypeTXT, dns.TypeCNAME:
		olog.Info(el.l)
		if eo, ok := el.l[v64r.eid]; ok {
			//	存在该实验id
			if step < v.p.maxLen {
				ret := eo.AddProgress(step)
				if ret == 0 {
					eo.Addchain(sip)
				}
				// 未到达最后一步
				return v.ResponseCNAME(msg, sip)
			}
			// 到达最后一步
			eo.isAll <- true
			return v.ResponseTXT(msg)
		}
		olog.Info("add " + v64r.eid)
		//不存在，可能是新到来的也可能是以前的
		if step != 1 {
			// 曾经的，直接返回
			return msg
		}
		// 新的实验，响应CNAME
		el.Add(v64r.eid, sip, v.a)
		return v.ResponseCNAME(msg, sip)

	case dns.TypeNS:
		return v.ResponseNS(msg)
	default:
		// 不符合要求的请求类型直接返回空响应
		return msg
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
	answer.Hdr = dns.RR_Header{Name: qname, Ttl: 3600, Class: dns.ClassINET, Rrtype: dns.TypeTXT}

	msg = v.SetAuthAdd(msg, sub)
	msg.Answer = append(msg.Answer, answer)
	return msg
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
	msg = v.SetAuthAdd(msg, sub)
	msg.Answer = append(msg.Answer, answer)

	return msg
}

// ResponseCNAME 响应CNAME记录
func (v V64dns) ResponseCNAME(msg *dns.Msg, sip net.IP) *dns.Msg {
	qname := msg.Question[0].Name
	var (
		maskPart     = ""
		subdomain    = ""
		zone         = ""
		ran          = ""
		prog         = ""
		expid        = ""
		newsubdomain = ""
	)

	for _, qs := range strings.Split(qname, ".") {
		switch v.MatchType(qs) {
		case 1:
			maskPart += qs + "."
		case 2:
			subdomain = qs
			newsubdomain = changeSubDomain(qs)
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
	answer.Target = prog + "." + expid + "." + maskPart + "." + ran + "." + newsubdomain + "." + zone

	msg = v.SetAuthAdd(msg, subdomain)
	msg.Answer = append(msg.Answer, answer)

	return msg
}

const (
	v6       = 0
	v4       = 1
	interval = 20
)
