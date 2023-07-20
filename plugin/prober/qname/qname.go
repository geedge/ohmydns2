package qname

import (
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/pochard/commons/randstr"
	"ohmydns2/core/prober"
	"ohmydns2/plugin"
	"strconv"
	"strings"
)

type Qname struct {
	next        plugin.Prober
	setFromFile string
}

func (q Qname) ProbeDNS(ctx context.Context, c *dns.Client, msg *dns.Msg) (int, error) {
	param := ctx.Value(prober.Paramkey).(map[string][]string)
	// api中设定了qname参数，则以该参数为准
	if v, ok := param["qname"]; ok {
		msg.Question[0].Name = generateQname(v[0])
		// 交由下一个插件处理
		return plugin.PNextOrFailure(q.Name(), q.next, ctx, c, msg)
	}
	if q.setFromFile != "" {
		// api中未设定，读取配置文件
		msg.Question[0].Name = generateQname(q.setFromFile)
		return plugin.PNextOrFailure(q.Name(), q.next, ctx, c, msg)
	}
	return 2, errors.New(q.Name() + ": 未指定参数")

}

func (q Qname) Name() string {
	return "qname"
}

func generateQname(arg string) string {
	args := strings.Split(arg, ".")
	qname := ""
	for _, v := range args {
		// 含有（ { [的视为函数部分
		p, ok := intersectionStringsList(v, funcList)
		if ok {
			i := strings.Index(v, p) //进入循环表明一定有匹配
			if f, fok := funcMap[v[:i]]; fok {
				qname += f(v[i+1:len(v)-1]) + "."
			}
		}
		// 不含直接添加
		qname += v + "."
	}
	return qname
}

func rand(d string) string {
	num, _ := strconv.Atoi(d)
	return strings.ToLower(randstr.RandomAlphanumeric(num))
}

// 起始水印标识生成
func genMask(d string) string {
	if d == "null" {
		return
	}
}

var funcList = []string{"(", ")", "{", "}", "[", "]"}

// 表达式中的函数与实际处理函数的映射
var funcMap = map[string]func(str string) string{
	"rand":  rand,
	"smask": genMask,
}
