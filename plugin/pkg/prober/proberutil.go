package prober

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"ohmydns2/plugin/pkg/log"
	"strconv"
	"strings"

	"github.com/pochard/commons/randstr"
)

// 数字到IP
func uint32toIP4(ipInt uint32) string {
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt(int64((ipInt>>24)&0xff), 10)
	b1 := strconv.FormatInt(int64((ipInt>>16)&0xff), 10)
	b2 := strconv.FormatInt(int64((ipInt>>8)&0xff), 10)
	b3 := strconv.FormatInt(int64((ipInt & 0xff)), 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

// ip到数字
func ip2Long(ip string) uint32 {
	var long uint32
	err := binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	if err != nil {
		log.Errorf("proberutil/ip2long:  %v", err.Error())
		return 0
	}
	return long
}

// 生成可用于IPv4探测的地址
func GenGlobIPv4() chan net.IP {
	c := make(chan net.IP)
	// 从1.0.0.0开始,到223.255.255.255结束（ICANN已分配地址）
	go func() {
		for n := ip2Long("1.0.0.0"); n < ip2Long("223.255.255.255"); n++ {
			ip := net.ParseIP(uint32toIP4(n))
			// 地址全球单播且不是私有地址
			if ip.IsGlobalUnicast() && !ip.IsPrivate() {
				c <- ip
			}
		}
		close(c)
	}()
	return c
}

// MakeProbe 生成探针的封装
func (p *Prober) makeProbe(ip net.IP) string {
	if p.Ptype == defaultPtype {
		return MakeProbev64(ip)
	}
	return ""
}

// 构造v64需要的探针
func MakeProbev64(ip net.IP) string {
	ipstr := ip2Eid(ip)
	return fmt.Sprintf("c1.rip%v.%v.%v.%v.", ipstr, strings.ToLower(randstr.RandomAlphanumeric(5)), defaultStartsubv64, defaultTarget)
}

func MakeTestProbev64(subv64 string, targetzone string) string {
	ipstr := ip2Eid(net.ParseIP("0.0.0.0"))
	return fmt.Sprintf("c1.rip%v.%v.%v.%v", ipstr, strings.ToLower(randstr.RandomAlphanumeric(5)), subv64, targetzone)
}

func ip2Eid(ip net.IP) string {
	i := ip.String()
	if strings.Contains(i, ":") {
		return strings.ReplaceAll(i, ":", "-")
	}
	return strings.ReplaceAll(i, ".", "-")
}
