package qname

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/pochard/commons/randstr"
	"net"
	"ohmydns2/plugin"
	"ohmydns2/plugin/pkg/prober"
	"strconv"
	"strings"
)

type Qname struct {
	next        plugin.Prober
	setFromFile string
	targetip    net.IP
}

func (q Qname) ProbeDNS(ctx context.Context, c *dns.Client, msg *dns.Msg) (int, error) {
	param := ctx.Value(prober.Paramkey).(map[string][]string)
	// api中设定了qname参数，则以该参数为准
	if v, ok := param["qname"]; ok {
		msg.Question[0].Name = generateQname(v[0], ctx)
		// 交由下一个插件处理
		return plugin.PNextOrFailure(q.Name(), q.next, ctx, c, msg)
	}
	if q.setFromFile != "" {
		// api中未设定，读取配置文件
		msg.Question[0].Name = generateQname(q.setFromFile, ctx)
		return plugin.PNextOrFailure(q.Name(), q.next, ctx, c, msg)
	}
	log.Error("未指定参数")
	return 2, errors.New(q.Name() + ": 未指定参数")

}

func (q Qname) Name() string {
	return "qname"
}

func generateQname(arg string, ctx context.Context) string {
	args := strings.Split(arg, ".")
	qname := ""
	for _, v := range args {
		// 含有（ { [的视为函数部分
		p, ok := intersectionStringsList(v, funcList)
		if ok {
			i := strings.Index(v, p) //进入循环表明一定有匹配
			if f, fok := funcMap[v[:i]]; fok {
				qname += f(v[i+1:len(v)-1], ctx)
			}
		}
		// 不含直接添加
		qname += v + "."
	}
	return qname
}

// 返回一定长度的随机字符串+"."
func rand(d string, _ context.Context) string {
	num, _ := strconv.Atoi(d)
	return strings.ToLower(randstr.RandomAlphanumeric(num)) + "."
}

// 起始水印标识生成+"."，如果为null则不生成
func genMask(d string, ctx context.Context) string {
	if d == "null" || d == "" {
		return ""
	}
	return d + ip2id(ctx.Value(prober.Target).(net.IP)) + "."
}

func ip2id(ip net.IP) string {
	// v4地址
	if strings.Contains(ip.String(), ".") {
		return strings.ReplaceAll(ip.String(), ".", "-")
	}
	return strings.ReplaceAll(ip.String(), ":", "-")
}

var funcList = []string{"(", ")", "{", "}", "[", "]"}

// 表达式中的函数与实际处理函数的映射
var funcMap = map[string]func(string, context.Context) string{
	"rand":  rand,
	"smask": genMask,
}
