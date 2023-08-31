package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"ohmydns2/plugin"
	"ohmydns2/plugin/pkg/request"
	"time"
)

// PBConfig configuration for a single prober.
type PBConfig struct {

	// one or several hostnames to bind the server to.
	// defaults to a single empty string that denote the wildcard address
	ListenHosts []string

	// The port to listen on.
	Port string

	// Root points to a base directory we find user defined "things".
	// First consumer is the file plugin to looks for zone files in this place.
	Root string

	// Debug controls the panic/recover mechanism that is enabled by default.
	Debug bool

	// Stacktrace controls including stacktrace as part of log from recover mechanism, it is disabled by default.
	Stacktrace bool

	// 使用的传输协议，目前为HTTP
	Transport string

	// If this function is not nil it will be used to inspect and validate
	// HTTP requests. Although this isn't referenced in-tree, external plugins
	// may depend on it.
	HTTPRequestValidateFunc func(*http.Request) bool

	// FilterFuncs is used to further filter access
	// to this handler. E.g. to limit access to a reverse zone
	// on a non-octet boundary, i.e. /17
	FilterFuncs []FilterFunc

	// ViewName is the name of the Viewer PLugin defined in the Config
	ViewName string

	// TLSConfig when listening for encrypted connections (gRPC, DNS-over-TLS).
	TLSConfig *tls.Config

	// Timeouts for TCP, TLS and HTTPS servers.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// TSIG secrets, [name]key.
	TsigSecret map[string]string

	// Plugin stack.
	Plugin []plugin.Pplugin

	// Compiled plugin stack.
	PluginChain plugin.Prober

	// Plugin interested in announcing that they exist, so other plugin can call methods
	// on them should register themselves here. The name should be the name as return by the
	// Handler's Name method.
	registry map[string]plugin.Prober

	// FirstConfigInBlock is used to reference the first config in a server block, for the
	// purpose of sharing single instance of each plugin among all zones in a server block.
	FirstConfigInBlock *PBConfig

	// MetaCollector references the first MetadataCollector plugin, if one exists
	MetaCollector ProberMetadataCollector
}

// FilterFunc is a function that filters requests from the Config
type FilterFunc func(context.Context, *request.HTTPRequest) bool

// KeyForConfig builds a key for identifying the configs during setup time
func KeyForConfig(blocIndex int, blocKeyIndex int) string {
	return fmt.Sprintf("%d:%d", blocIndex, blocKeyIndex)
}

// AddPlugin adds a plugin to a site's plugin stack.
func (pc PBConfig) AddPlugin(m plugin.Pplugin) {
	pc.Plugin = append(pc.Plugin, m)
}

// registerHandler adds a prober to a site's prober registration.
func (pc PBConfig) RegisterProber(p plugin.Prober) {
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
