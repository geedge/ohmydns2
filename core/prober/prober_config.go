package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/coredns/caddy"
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
	pluginChain plugin.Prober

	// Plugin interested in announcing that they exist, so other plugin can call methods
	// on them should register themselves here. The name should be the name as return by the
	// Handler's Name method.
	registry map[string]plugin.Prober

	// firstConfigInBlock is used to reference the first config in a server block, for the
	// purpose of sharing single instance of each plugin among all zones in a server block.
	firstConfigInBlock *PBConfig

	// metaCollector references the first MetadataCollector plugin, if one exists
	metaCollector ProberMetadataCollector
}

// FilterFunc is a function that filters requests from the Config
type FilterFunc func(context.Context, *request.HTTPRequest) bool

// keyForConfig builds a key for identifying the configs during setup time
func keyForConfig(blocIndex int, blocKeyIndex int) string {
	return fmt.Sprintf("%d:%d", blocIndex, blocKeyIndex)
}

// GetConfig gets the Config that corresponds to c.
// If none exist nil is returned.
func GetPBConfig(c *caddy.Controller) *PBConfig {
	ctx := c.Context().(*probeContext)
	key := keyForConfig(c.ServerBlockIndex, c.ServerBlockKeyIndex)
	if cfg, ok := ctx.keysToConfigs[key]; ok {
		return cfg
	}
	// we should only get here during tests because directive
	// actions typically skip the server blocks where we make
	// the configs.
	ctx.saveConfig(key, &PBConfig{ListenHosts: []string{""}})
	return GetPBConfig(c)
}
