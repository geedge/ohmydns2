package probe53

import (
	"github.com/coredns/caddy"
	"ohmydns2/core/prober"
	"ohmydns2/plugin"
	"ohmydns2/plugin/pkg/log"
	//"ohmydns2/plugin/pkg/prober"
)

func init() {
	plugin.ProbeRegister("probe53", setup)
}

func setup(c *caddy.Controller) error {
	p := new(Probe53)
	prober.GetPBConfig(c).AddPlugin(func(next plugin.Prober) plugin.Prober {
		return p
	})
	return nil
}

var logger = log.NewWithPlugin("probe53")
