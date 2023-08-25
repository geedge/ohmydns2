package qname

import (
	"github.com/coredns/caddy"
	"ohmydns2/core/prober"
	"ohmydns2/plugin"
	olog "ohmydns2/plugin/pkg/log"
)

func init() { plugin.ProbeRegister("qname", setup) }

func setup(c *caddy.Controller) error {
	qname := new(Qname)
	// 存在参数，加载到结构体中
	if c.NextArg() {
		qname.setFromFile = c.RemainingArgs()[0]
	}

	prober.GetPBConfig(c).AddPlugin(func(next plugin.Prober) plugin.Prober {
		return qname
	})

	return nil
}

var log = olog.NewWithPlugin("qname")
