package atk

import (
	"github.com/coredns/caddy"
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"
	log2 "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/pkg/proxy"
	"strconv"
	"time"
)

func init() { plugin.Register("atk", setup) }

func setup(c *caddy.Controller) error {
	atk := new(Atk)
	c.Next()
	// domain1 domain2 factor
	args := c.RemainingArgs()
	// fdns or adns
	atk.serveType = args[0]
	if atk.serveType == "fdns" {
		atk.target = args[1]
		p := proxy.NewProxy(atk.target+":53", "dns")

		// 开启代理连接管理
		dur, _ := time.ParseDuration("10s")
		p.Start(dur)
		atk.proxies = append(atk.proxies, p)
		atk.magni, _ = strconv.Atoi(args[2])

	} else {
		atk.zoneip4 = args[1]
		atk.ip4NS = args[2]
		atk.ip4Addr = args[3]
		atk.zoneip6 = args[4]
		atk.ip6NS = args[5]
		atk.ip6Addr = args[6]
		atk.magni, _ = strconv.Atoi(args[7])
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return atk
	})

	return nil
}

var log = log2.NewWithPlugin("atk")
