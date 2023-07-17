package prober

import (
	"fmt"
	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/miekg/dns"
	"net"
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"
	"ohmydns2/plugin/pkg/parse"
	"ohmydns2/plugin/pkg/transport"
	"time"
)

const proberType = "dnsprober"

func init() {
	caddy.RegisterServerType(proberType, caddy.ServerType{
		Directives: func() []string { return Directives },
		DefaultInput: func() caddy.Input {
			return caddy.CaddyfileInput{
				Filepath:       "Ohmyfile",
				Contents:       []byte(".:" + Port + " {\nprober_show\nlog\n}\n"),
				ServerTypeName: proberType,
			}
		},
		NewContext: newPBContext,
	})
}

func newPBContext(i *caddy.Instance) caddy.Context {
	return &probeContext{keysToConfigs: make(map[string]*PBConfig)}
}

type probeContext struct {
	keysToConfigs map[string]*PBConfig

	// configs is the master list of all site configs.
	configs []*PBConfig
}

func (p *probeContext) saveConfig(key string, cfg *PBConfig) {
	p.configs = append(p.configs, cfg)
	p.keysToConfigs[key] = cfg
}

// Compile-time check to ensure dnsContext implements the caddy.Context interface
var _ caddy.Context = &probeContext{}

// InspectServerBlocks make sure that everything checks out before
// executing directives and otherwise prepares the directives to
// be parsed and executed.
func (p *probeContext) InspectServerBlocks(sourceFile string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	// Normalize and check all the zone names and check for duplicates
	for ib, s := range serverBlocks {
		// Walk the s.Keys and expand any reverse address in their proper DNS in-addr zones. If the expansions leads for
		// more than one reverse zone, replace the current value and add the rest to s.Keys.
		Addrs := []addr{}
		for ik, k := range s.Keys {
			trans, k1 := parse.Transport(k) // get rid of any dns:// or other scheme.
			hosts, port, err := plugin.SplitHostPort(k1)
			// We need to make this a fully qualified domain name to catch all errors here and not later when
			// plugin.Normalize is called again on these strings, with the prime difference being that the domain
			// name is fully qualified. This was found by fuzzing where "ȶ" is deemed OK, but "ȶ." is not (might be a
			// bug in miekg/dns actually). But here we were checking ȶ, which is OK, and later we barf in ȶ. leading to
			// "index out of range".
			for ih := range hosts {
				_, _, err := plugin.SplitHostPort(dns.Fqdn(hosts[ih]))
				if err != nil {
					return nil, err
				}
			}
			if err != nil {
				return nil, err
			}

			if port == "" {
				switch trans {
				case transport.PROBER:
					port = transport.PROBERPort
				}
			}

			if len(hosts) > 1 {
				s.Keys[ik] = hosts[0] + ":" + port // replace for the first
				for _, h := range hosts[1:] {      // add the rest
					s.Keys = append(s.Keys, h+":"+port)
				}
			}
			for _ = range hosts {
				Addrs = append(Addrs, addr{Port: port, Transport: trans})
			}
		}

		serverBlocks[ib].Keys = s.Keys // important to save back the new keys that are potentially created here.

		var firstConfigInBlock *PBConfig

		for ik := range s.Keys {
			za := Addrs[ik]
			s.Keys[ik] = za.String()
			// Save the config to our master list, and key it for lookups.
			cfg := &PBConfig{
				ListenHosts: []string{""},
				Port:        za.Port,
				Transport:   za.Transport,
			}

			// Set reference to the first config in the current block.
			// This is used later by MakeServers to share a single plugin list
			// for all zones in a server block.
			if ik == 0 {
				firstConfigInBlock = cfg
			}
			cfg.firstConfigInBlock = firstConfigInBlock

			keyConfig := keyForConfig(ib, ik)
			p.saveConfig(keyConfig, cfg)
		}
	}
	return serverBlocks, nil
}

// MakeServers uses the newly-created siteConfigs to create and return a list of server instances.
func (p *probeContext) MakeServers() ([]caddy.Server, error) {
	// Copy the Plugin, ListenHosts and Debug from first config in the block
	// to all other config in the same block . Doing this results in zones
	// sharing the same plugin instances and settings as other zones in
	// the same block.
	for _, c := range p.configs {
		c.Plugin = c.firstConfigInBlock.Plugin
		c.ListenHosts = c.firstConfigInBlock.ListenHosts
		c.Debug = c.firstConfigInBlock.Debug
		c.Stacktrace = c.firstConfigInBlock.Stacktrace

		// Fork TLSConfig for each encrypted connection
		c.TLSConfig = c.firstConfigInBlock.TLSConfig.Clone()
		c.ReadTimeout = c.firstConfigInBlock.ReadTimeout
		c.WriteTimeout = c.firstConfigInBlock.WriteTimeout
		c.IdleTimeout = c.firstConfigInBlock.IdleTimeout
		c.TsigSecret = c.firstConfigInBlock.TsigSecret
	}

	// we must map (group) each config to a bind address
	groups, err := groupConfigsByListenAddr(p.configs)
	if err != nil {
		return nil, err
	}
	// then we create a server for each group
	var servers []caddy.Server
	for addr, group := range groups {
		// switch on addr
		switch tr, _ := parse.Transport(addr); tr {
		case transport.PROBER:
			s, err := NewProberHTTP(addr, group)
			if err != nil {
				return nil, err
			}
			servers = append(servers, s)
		}
	}

	//// For each server config, check for View Filter plugins
	//for _, c := range p.configs {
	//	// Add filters in the plugin.cfg order for consistent filter func evaluation order.
	//	for _, d := range Directives {
	//		if vf, ok := c.registry[d].(Viewer); ok {
	//			if c.ViewName != "" {
	//				return nil, fmt.Errorf("multiple views defined in server block")
	//			}
	//			c.ViewName = vf.ViewName()
	//			c.FilterFuncs = append(c.FilterFuncs, vf.Filter)
	//		}
	//	}
	//}

	// Verify that there is no overlap on the zones and listen addresses
	// for unfiltered server configs
	errValid := p.validateZonesAndListeningAddresses()
	if errValid != nil {
		return nil, errValid
	}

	return servers, nil
}

// AddPlugin adds a plugin to a site's plugin stack.
func (pc PBConfig) AddPlugin(m plugin.Pplugin) {
	pc.Plugin = append(pc.Plugin, m)
}

// registerHandler adds a handler to a site's handler registration. Handlers
//
//	use this to announce that they exist to other plugin.
func (pc PBConfig) registerProber(p plugin.Prober) {
	if pc.registry == nil {
		pc.registry = make(map[string]plugin.Prober)
	}

	// Just overwrite...
	pc.registry[p.Name()] = p
}

// Handler returns the plugin handler that has been added to the config under its name.
// This is useful to inspect if a certain plugin is active in this server.
// Note that this is order dependent and the order is defined in directives.go, i.e. if your plugin
// comes before the plugin you are checking; it will not be there (yet).
func (pc PBConfig) Handler(name string) plugin.Prober {
	if pc.registry == nil {
		return nil
	}
	if h, ok := pc.registry[name]; ok {
		return h
	}
	return nil
}

// Handlers returns a slice of plugins that have been registered. This can be used to
// inspect and interact with registered plugins but cannot be used to remove or add plugins.
// Note that this is order dependent and the order is defined in directives.go, i.e. if your plugin
// comes before the plugin you are checking; it will not be there (yet).
func (pc PBConfig) Handlers() []plugin.Prober {
	if pc.registry == nil {
		return nil
	}
	hs := make([]plugin.Prober, 0, len(pc.registry))
	for k := range pc.registry {
		hs = append(hs, pc.registry[k])
	}
	return hs
}

func (p *probeContext) validateZonesAndListeningAddresses() error {
	//Validate addresses
	checker := newOverlapZone()
	for _, conf := range p.configs {
		for _, h := range conf.ListenHosts {
			// Validate the overlapping of ZoneAddr
			akey := addr{Transport: conf.Transport, Address: h, Port: conf.Port}
			var existZone, overlapZone *addr
			if len(conf.FilterFuncs) > 0 {
				// This config has filters. Check for overlap with other (unfiltered) configs.
				existZone, overlapZone = checker.check(akey)
			} else {
				// This config has no filters. Check for overlap with other (unfiltered) configs,
				// and register the zone to prevent subsequent zones from overlapping with it.
				existZone, overlapZone = checker.registerAndCheck(akey)
			}
			if existZone != nil {
				return fmt.Errorf("cannot serve %s - it is already defined", akey.String())
			}
			if overlapZone != nil {
				return fmt.Errorf("cannot serve %s - zone overlap listener capacity with %v", akey.String(), overlapZone.String())
			}
		}
	}
	return nil
}

// groupConfigsByListenAddr groups site configs by their listen
// (bind) address, so sites that use the same listener can be served
// on the same server instance. The return value maps the listen
// address (what you pass into net.Listen) to the list of site configs.
// This function does NOT vet the configs to ensure they are compatible.
func groupConfigsByListenAddr(configs []*PBConfig) (map[string][]*PBConfig, error) {
	groups := make(map[string][]*PBConfig)
	for _, conf := range configs {
		for _, h := range conf.ListenHosts {
			addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(h, conf.Port))
			if err != nil {
				return nil, err
			}
			addrstr := conf.Transport + "://" + addr.String()
			groups[addrstr] = append(groups[addrstr], conf)
		}
	}

	return groups, nil
}

// DefaultPort is the default port.
const DefaultPort = transport.PROBERPort

// These "soft defaults" are configurable by
// command line flags, etc.
var (
	// Port is the port we listen on by default.
	Port = DefaultPort

	// GracefulTimeout is the maximum duration of a graceful shutdown.
	GracefulTimeout time.Duration
)

var _ caddy.GracefulServer = new(dnsserver.Server)
