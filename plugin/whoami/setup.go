package whoami

import (
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"

	"github.com/coredns/caddy"
)

func init() { plugin.Register("whoami", setup) }

func setup(c *caddy.Controller) error {
	c.Next()
	if c.NextArg() {
		return plugin.Error("whoami", c.ArgErr())
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Whoami{}
	})
	return nil
}
