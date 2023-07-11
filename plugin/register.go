package plugin

import "github.com/coredns/caddy"

// Register registers your plugin with OhmyDNS2 and allows it to be called when the server is running.
func Register(name string, action caddy.SetupFunc) {
	caddy.RegisterPlugin(name, caddy.Plugin{
		ServerType: "dns",
		Action:     action,
	})
}

// ProbeRegister registers your plugin with OhmyDNS2 and allows it to be called when the prober is running.
func ProbeRegister(name string, action caddy.SetupFunc) {
	caddy.RegisterPlugin(name, caddy.Plugin{
		ServerType: "dns",
		Action:     action,
	})
}
