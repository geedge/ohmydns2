package prober

import (
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"

	"github.com/coredns/caddy"
)

func init() { plugin.ProbeRegister("prober-v64", setup) }

func setup(c *caddy.Controller) error {
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Prober{Next: next}
	})
	return nil
}
