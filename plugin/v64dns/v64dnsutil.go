package v64dns

import (
	"net"
	"ohmydns2/plugin/pkg/request"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// 判断接收到的域名是否实验可用，0为正常，1代表非实验需要，2代表可能是QName最小化的请求
func (v V64dns) VaildRequest(d string) int {
	//获取到每一级域名的字符串
	ds := strings.Split(d, ".")
	//判断是否为目标域名
	if strings.Contains(d, v.zone) {
		//判断是否有解析进度,含有c且长度为2认为存在标识
		if strings.Contains(ds[0], "c") && len(ds[0]) == 2 {
			return 0
			//p, err := strconv.Atoi(strings.Split(ds[0], "")[1])
			//if err != nil {
			//	print(err)
			//	return 1
			//}
			//长度也一致
			//if p == len(ds)-6 {
			//	return 0
			//}
		}
		//不存在解析进度，则可能为Qname最小化的请求，返回2
		return 2
	}
	return 1
}

// AuthInfo
//
//	@Description: 添加权威服务器的授权信息
//	@receiver v
//	@param d dns响应
//	@param iptype IP类型，0代表v6，1代表v4
//	@return *dns.Msg
//	@return error
func (v *V64dns) AuthInfo(d *dns.Msg, iptype int) (*dns.Msg, error) {
	rr := new(dns.NS)
	rr.Hdr = dns.RR_Header{Class: dns.ClassINET, Ttl: 3600, Rrtype: dns.TypeNS}

	if iptype == 0 {
		rr.Hdr.Name = v.p.v6domain
		rr.Ns = v.ipv6NS
	} else {
		rr.Hdr.Name = v.p.v4domain
		rr.Ns = v.ipv4NS
	}
	d.Ns = append(d.Ns, rr)
	return d, nil
}

// AdditionalInfo
//
//	@Description: 添加胶水记录
//	@receiver v
//	@param d dns响应
//	@param iptype IP类型，0代表v6，1代表v4
//	@return *dns.Msg
//	@return error
func (v *V64dns) AdditionalInfo(d *dns.Msg, state request.Request, iptype int) (*dns.Msg, error) {
	// 根据不同的NS返回额外信息
	if iptype == 0 {
		dnsadd := new(dns.AAAA)
		dnsadd.Hdr = dns.RR_Header{Name: v.ipv6NS, Ttl: 3600, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
		a, _, _ := net.ParseCIDR(v.V6NSAddr + "/64")
		//a := net.ParseIP(state.LocalIP())
		dnsadd.AAAA = a.To16()
		d.Extra = append(d.Extra, dnsadd)
	} else {
		dnsadd := new(dns.A)
		dnsadd.Hdr = dns.RR_Header{Name: v.ipv4NS, Ttl: 3600, Class: dns.ClassINET, Rrtype: dns.TypeA}
		a, _, _ := net.ParseCIDR(v.V4NSAddr + "/24")
		//a := net.ParseIP(state.LocalIP())
		dnsadd.A = a.To4()
		d.Extra = append(d.Extra, dnsadd)
	}
	return d, nil
}

// 根据各级域名特征判断其类型，0为zone，1为水印部分，2为v4/v6子域名，3为随机数，4为进度标识，5为实验对象
func (v V64dns) MatchType(s string) int {
	if strings.Contains(s, "rip") {
		return 5
	}
	if s == v.p.v4subdomain || s == v.p.v6subdomain {
		return 2
	}
	if strings.Contains(s, "-") && len(s) > 5 {
		return 1
	}
	if len(s) == 2 && string(s[0]) == "c" {
		return 4
	}
	for _, i := range strings.Split(v.zone, ".") {
		if s == i {
			return 0
		}
	}
	return 3
}

// 切换域名
func (v V64dns) changeSubDomain(s string) string {
	// 切换标志位为false，直接返回原域名
	if !v.p.dmChange {
		return s
	}
	switch s {
	case v.p.v4subdomain:
		return v.p.v6subdomain
	case v.p.v6subdomain:
		return v.p.v4subdomain
	default:
		log.Error("子域名错误")
		return "v64"
	}
}

// 修改进度标识
func nextProgress(s string) string {
	n, _ := strconv.Atoi(string(s[1]))
	n = n + 1
	return string(s[0]) + strconv.Itoa(n)
}

// 封装函数，同时添加权威信息和胶水记录，根据子域名切换，domainType=6 or 4
func (v V64dns) SetAuthAdd(res *dns.Msg, state request.Request, domaintype int) *dns.Msg {
	if domaintype == 6 {
		res, _ = v.AdditionalInfo(res, state, v6)
		res, _ = v.AuthInfo(res, v6)
	} else {
		res, _ = v.AdditionalInfo(res, state, v4)
		res, _ = v.AuthInfo(res, v4)
	}
	return res
}

// 从域名中提取eid
func (v V64dns) ExtractEid(qname string) string {
	for _, qs := range strings.Split(qname, ".") {
		if v.MatchType(qs) == 5 {
			return qs
		}
	}
	return ""
}

func ip2id(ip string) string {
	i := ip
	if strings.Contains(i, ".") {
		return strings.ReplaceAll(i, ".", "-")
	} else {
		return strings.ReplaceAll(i, ":", "-")
	}
}
