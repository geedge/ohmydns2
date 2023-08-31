package prober

import (
	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"net"
	"ohmydns2/core/dnsserver"
	"ohmydns2/plugin"
	"ohmydns2/plugin/pkg/parse"
	"ohmydns2/plugin/pkg/prober"
	"ohmydns2/plugin/pkg/transport"
)

const proberType = "dnsprober"

func init() {
	caddy.RegisterServerType(proberType, caddy.ServerType{
		Directives: func() []string { return Directives },
		DefaultInput: func() caddy.Input {
			return caddy.CaddyfileInput{
				Filepath:       "Ohmyfile",
				Contents:       []byte("probe://:" + Port + " {\nprober_show\nlog\n}\n"),
				ServerTypeName: proberType,
			}
		},
		NewContext: newPBContext,
	})
}

func newPBContext(*caddy.Instance) caddy.Context {
	return &ProbeContext{keysToConfigs: make(map[string]*prober.PBConfig)}
}

type ProbeContext struct {
	keysToConfigs map[string]*prober.PBConfig

	// configs is the master list of all site configs.
	configs []*prober.PBConfig
}

func (p *ProbeContext) saveConfig(key string, cfg *prober.PBConfig) {
	p.configs = append(p.configs, cfg)
	p.keysToConfigs[key] = cfg
}

// Compile-time check to ensure dnsContext implements the caddy.Context interface
var _ caddy.Context = &ProbeContext{}

// InspectServerBlocks make sure that everything checks out before
// executing directives and otherwise prepares the directives to
// be parsed and executed.
func (p *ProbeContext) InspectServerBlocks(_ string, serverBlocks []caddyfile.ServerBlock) ([]caddyfile.ServerBlock, error) {
	// Normalize and check all the zone names and check for duplicates
	for ib, s := range serverBlocks {
		Addrs := []addr{}
		// 每一个服务块的zone部分
		for ik, k := range s.Keys {
			trans, k1 := parse.Transport(k) // get rid of any dns:// or other scheme.
			// 不属于探测端的服务块不解析
			if trans != transport.PROBER {
				continue
			}
			port, err := plugin.SplitPort(k1)

			if err != nil {
				return nil, err
			}
			s.Keys[ik] = port
			Addrs = append(Addrs, addr{Port: port, Transport: transport.PROBERTRAN})
		}

		serverBlocks[ib].Keys = s.Keys // important to save back the new keys that are potentially created here.

		var firstConfigInBlock *prober.PBConfig

		for ik := range s.Keys {
			a := Addrs[ik]
			s.Keys[ik] = a.String()
			// Save the config to our master list, and key it for lookups.
			cfg := &prober.PBConfig{
				ListenHosts: []string{""},
				Port:        a.Port,
				Transport:   a.Transport,
			}

			// Set reference to the first config in the current block.
			// This is used later by MakeServers to share a single plugin list
			// for all zones in a server block.
			if ik == 0 {
				firstConfigInBlock = cfg
			}
			cfg.FirstConfigInBlock = firstConfigInBlock

			keyConfig := prober.KeyForConfig(ib, ik)
			p.saveConfig(keyConfig, cfg)
		}
	}
	return serverBlocks, nil
}

// MakeServers uses the newly-created siteConfigs to create and return a list of server instances.
func (p *ProbeContext) MakeServers() ([]caddy.Server, error) {
	// Copy the Plugin, ListenHosts and Debug from first config in the block
	// to all other config in the same block . Doing this results in zones
	// sharing the same plugin instances and settings as other zones in
	// the same block.
	for _, c := range p.configs {
		c.Plugin = c.FirstConfigInBlock.Plugin
		c.ListenHosts = c.FirstConfigInBlock.ListenHosts
		c.Debug = c.FirstConfigInBlock.Debug
		c.Stacktrace = c.FirstConfigInBlock.Stacktrace

		// Fork TLSConfig for each encrypted connection
		c.TLSConfig = c.FirstConfigInBlock.TLSConfig.Clone()
		c.ReadTimeout = c.FirstConfigInBlock.ReadTimeout
		c.WriteTimeout = c.FirstConfigInBlock.WriteTimeout
		c.IdleTimeout = c.FirstConfigInBlock.IdleTimeout
		c.TsigSecret = c.FirstConfigInBlock.TsigSecret
	}

	// we must map (group) each config to a bind address
	groups, err := groupConfigsByListenPort(p.configs)
	if err != nil {
		return nil, err
	}
	// then we create a server for each group
	var servers []caddy.Server
	for protaddr, group := range groups {
		// switch on addr
		switch tr, _ := parse.Transport(transport.PROBER + protaddr[len(transport.PROBERTRAN):]); tr {
		case transport.PROBER:
			s, e := NewProberHTTP(protaddr, group)
			if e != nil {
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
	//errValid := p.validateZonesAndListeningAddresses()
	//if errValid != nil {
	//	return nil, errValid
	//}

	return servers, nil
}

// GetConfig gets the Config that corresponds to c.
// If none exist nil is returned.
func GetPBConfig(c *caddy.Controller) *prober.PBConfig {
	ctx := c.Context().(*ProbeContext)
	key := prober.KeyForConfig(c.ServerBlockIndex, c.ServerBlockKeyIndex)
	if cfg, ok := ctx.keysToConfigs[key]; ok {
		return cfg
	}
	// we should only get here during tests because directive
	// actions typically skip the server blocks where we make
	// the configs.
	ctx.saveConfig(key, &prober.PBConfig{ListenHosts: []string{""}})
	return GetPBConfig(c)
}

// groupConfigsByListenPort 建立监听端口和配置文件之间的映射，与服务端不同的是，一个监听地址端口只对应一个配置文件
func groupConfigsByListenPort(configs []*prober.PBConfig) (map[string]*prober.PBConfig, error) {
	groups := make(map[string]*prober.PBConfig)
	for _, conf := range configs {
		for _, h := range conf.ListenHosts {
			tcpaddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(h, conf.Port))
			if err != nil {
				return nil, err
			}
			addrstr := conf.Transport + "://" + tcpaddr.String()
			groups[addrstr] = conf
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
	//GracefulTimeout time.Duration
)

var _ caddy.GracefulServer = new(dnsserver.Server)
