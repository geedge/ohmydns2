package atk

import (
	"github.com/coredns/caddy"
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"
	log2 "ohmydns2/plugin/pkg/log"
	"strconv"
)

func init() { plugin.Register("atk", setup) }

func setup(c *caddy.Controller) error {
	atk := new(Atk)
	c.Next()
	// domain1 domain2 factor
	args := c.RemainingArgs()
	atk.zoneip4 = args[0]
	atk.ip4NS = args[1]
	atk.ip4Addr = args[2]
	atk.zoneip6 = args[3]
	atk.ip6NS = args[4]
	atk.ip6Addr = args[5]
	atk.magni, _ = strconv.Atoi(args[6])

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return atk
	})

	return nil
}

var log = log2.NewWithPlugin("atk")
