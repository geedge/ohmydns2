package plugin

import (
	"context"

	"github.com/coredns/caddy"
)

type (
	// Pplugin 是一个中间层，它定义了一个用于探测的插件传递链，前一个 Handler 处理完成之后将紧接着传递到下一个 Handler。
	Pplugin func(Prober) Prober

	Prober interface {
		Probe(context.Context) (int, error)
		Name() string
	}

	// ProberFunc is a convenience type like dns.HandlerFunc, except
	// ServeDNS returns an rcode and an error. See Handler
	// documentation for more information.
	ProberFunc func(context.Context) (int, error)
)

// Register registers your plugin with OhmyDNS2 and allows it to be called when the server is running.
func ProbeRegister(name string, action caddy.SetupFunc) {
	caddy.RegisterPlugin(name, caddy.Plugin{
		ServerType: "dns",
		Action:     action,
	})
}
