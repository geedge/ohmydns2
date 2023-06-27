package v64dns

import (
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"
	olog "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/v64dns/analyze"
	"strconv"

	"github.com/coredns/caddy"
)

func init() { plugin.Register("v64dns", setup) }

// 读取参数
func setup(c *caddy.Controller) error {
	v64dnsserver, err := parseArg(c)
	if err != nil {
		log.Error("参数存在问题")
		return err
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return v64dnsserver
	})
	return nil
}

// 解析参数
func parseArg(c *caddy.Controller) (*V64dns, error) {
	v := new(V64dns)
	v.p.maxLen = chain_maxlen

	for c.Next() {
		arg := c.RemainingArgs()
		v.zone = plugin.OriginsFromArgsOrServerBlock(arg, c.ServerBlockKeys)[0]

		for c.NextBlock() {
			switch c.Val() {
			case "v4ns":
				args := c.RemainingArgs()
				if len(args) != 2 {
					//	缺少参数
					log.Error("v4ns缺少参数，请检查")
				}
				v.ipv4NS = args[0] + "." + v.zone
				v.V4NSAddr = args[1]
			case "v6ns":
				args := c.RemainingArgs()
				if len(args) != 2 {
					//	缺少参数
					log.Error("v6ns缺少参数，请检查")
				}
				v.ipv6NS = args[0] + "." + v.zone
				v.V6NSAddr = args[1]
			case "chain":
				args := c.RemainingArgs()
				if len(args) != 2 {
					//	缺少参数
					log.Error("域名链缺少参数，请检查")
				}
				v.p.v4domain = args[0] + "." + v.zone
				v.p.v6domain = args[1] + "." + v.zone
				v.p.v6subdomain = args[1]
				v.p.v4subdomain = args[0]
			case "ip-embed":
				v.p.ipEmbed = true
			case "chain-mlen":
				if !c.Next() {
					return nil, c.ArgErr()
				}
				v.p.maxLen, _ = strconv.Atoi(c.Val())
			case "analyze":
				args := c.RemainingArgs()
				if len(args) != 4 {
					//	缺少参数
					log.Error("analyze参数错误，请检查")
				}
				//创建Analyzer对象
				err := analyze.NewAnalyzer(args[0], args[1], args[2], args[3])
				if err != nil {
					return nil, err
				}
			}
		}
		break
	}
	// 监控停止信号
	go EL.Stop()
	return v, nil
}

var log = olog.NewWithPlugin("v64dns")

const (
	chain_maxlen = 4
)
