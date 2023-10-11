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

// expobject 代表了每个实验对象
//type expobject struct {
//	eid      string
//	interval int       //实验对象的等待间隔，超过则认为实验过程存在问题导致只有部分请求
//	isAll    chan bool //实验对象对应过程是否完整
//	progress int       // 实验进度
//	chain    []net.IP
//}
//
//// 向域名链中添加IP
//func (e expobject) Addchain(ip net.IP) {
//	e.chain = append(e.chain, ip)
//}
//
//// 停止实验，根据倒计时或者信号量停止
//func (e expobject) Stop() {
//	// 如果到达时间限制则通过管道通知停止
//	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.interval)*time.Second)
//	defer cancel()
//	defer close(e.isAll)
//	ticker := time.NewTicker(1 * time.Second)
//	for range ticker.C {
//		select {
//		case <-ctx.Done():
//			break
//		case t := <-e.isAll:
//			if t == true {
//				break
//			}
//		default:
//			continue
//		}
//	}
//	EL.c <- e.eid
//}
//
//// 增加实验进度,返回1代表未处理，0代表进度增加
//func (e expobject) AddProgress(step int) int {
//	if step < e.progress {
//		return 1
//	}
//	e.progress += 1
//	return 0
//}
//
//type explist struct {
//	m      sync.Mutex
//	l      map[string]expobject
//	c      chan string   // eid传递管道（接受）
//	Ipchan chan []net.IP // IP链传递管道（发送）
//}
//
//var EL = NewExpList()
//
//// 为explist创建空间
//func NewExpList() *explist {
//	el := new(explist)
//	el.c = make(chan string, 5)
//	el.l = make(map[string]expobject)
//	el.Ipchan = make(chan []net.IP, 128)
//	return el
//}
//
//// 持续监听管道信息，删除对应eid
//func (el *explist) Stop() {
//	for {
//		eid := <-el.c
//		el.m.Lock()
//		analyze.A.Go2py(el.l[eid].IPchain2Str())
//		delete(el.l, eid)
//		el.m.Unlock()
//	}
//}
//
//// 增加实验对象
//func (el *explist) Add(eid string, sip net.IP) {
//	el.m.Lock()
//	n := expobject{
//		eid:      eid,
//		interval: interval,
//		isAll:    make(chan bool),
//		progress: 1,
//		chain:    []net.IP{sip},
//	}
//	el.l[eid] = n
//	go n.Stop()
//	el.m.Unlock()
//}

// ResponseHandler 跨栈解析响应主要处理函数
func (v V64dns) ResponseHandler(msg *dns.Msg, state request.Request) *dns.Msg {
	step, _ := strconv.Atoi(string(rune(state.QName()[1])))

	// 未到达最后一步
	if step < v.p.maxLen {

		return v.ResponseCNAME(msg, state)
	}

	switch state.QType() {
	// 只处理TXT，CNAME，AAAA记录
	case dns.TypeTXT, dns.TypeCNAME, dns.TypeAAAA:
		if step < v.p.maxLen {
			// 未到达最后一步
			return v.ResponseCNAME(msg, state)
		}
		// 到达最后一步
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
	sub := ""
	for _, qs := range strings.Split(qname, ".") {
		switch v.MatchType(qs) {
		case 2:
			sub = qs
		}
	}
	//ans := EL.l[expid].IPchain2Str()

	answer := new(dns.TXT)
	answer.Txt = []string{state.QName()}
	answer.Hdr = dns.RR_Header{Name: qname, Ttl: 3600, Class: dns.ClassINET, Rrtype: dns.TypeTXT}

	if sub == v.p.v4subdomain {
		msg = v.SetAuthAdd(msg, 4)
	} else {
		msg = v.SetAuthAdd(msg, 6)
	}

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
		msg = v.SetAuthAdd(msg, 6)
	} else {
		answer.Ns = v.ipv4NS
		msg = v.SetAuthAdd(msg, 4)
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
	//var (
	//	maskPart     = ""
	//	subdomain    = ""
	//	zone         = ""
	//	ran          = ""
	//	prog         = ""
	//	expid        = ""
	//	newsubdomain = ""
	//)

	dSlice := strings.Split(strings.ToLower(qname), ".")
	if len(dSlice) > 4 {
		// 将最近一次编码拆分开
		cList := strings.Split(dSlice[len(dSlice)-4], "-")
		iaddr := ""
		// 首部编码如果长度为4则为IPv6地址编码，否则为IPv4的
		if len(cList[0]) == 4 {
			iaddr = strings.ReplaceAll(dSlice[len(dSlice)-4], "-", ":")
			msg = v.SetAuthAdd(msg, 4)
		} else {
			iaddr = strings.ReplaceAll(dSlice[len(dSlice)-4], "-", ".")
			msg = v.SetAuthAdd(msg, 6)
		}
		iaddr = net.ParseIP(iaddr).String()
		//oaddr := state.IP()
		// 调用Python脚本
		//go v.a.Go2py([]string{iaddr, oaddr})
	}

	//for _, qs := range strings.Split(qname, ".") {
	//	switch v.MatchType(qs) {
	//	case 1:
	//		maskPart += qs + "."
	//	case 2:
	//		subdomain = qs
	//newsdm := v.changeSubDomain(qs, v.p.dmChange)
	//	case 5:
	//		expid = qs
	//	case 4:
	//		prog = nextProgress(qs)
	//	case 3:
	//		ran = qs
	//	default:
	//		if qs != "" {
	//			zone = zone + qs + "."
	//		}
	//
	//	}
	//}
	//maskPart = maskPart + ip2id(sip)
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
	for _, i := range dSlice[1 : len(dSlice)-4] {
		answer.Target += i + "."
	}
	answer.Target += ip2id(state.IP()) + "."
	answer.Target += v.changeSubDomain(dSlice[len(dSlice)-4]) + "."
	for _, i := range dSlice[len(dSlice)-3 : len(dSlice)-1] {
		answer.Target += i + "."
	}
	msg.Answer = append(msg.Answer, answer)
	log.Debug(answer)
	return msg
}

const (
	v6       = 0
	v4       = 1
	interval = 20
)
