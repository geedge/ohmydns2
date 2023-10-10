package rtest

import (
	"github.com/coredns/caddy"
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"
	log2 "ohmydns2/plugin/pkg/log"
)

func init() { plugin.Register("rtest", setup) }

func setup(c *caddy.Controller) error {
	rt := new(Rtest)
	c.Next()

	args := c.RemainingArgs()
	rt.addr = args[1]
	rt.ns = args[0]
	rt.datachan = rt.newCSVwriterAndWrite(args[2])

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return rt
	})

	return nil
}

var log = log2.NewWithPlugin("rtest")
