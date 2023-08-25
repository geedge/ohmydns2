package prober

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coredns/caddy"
	ot "github.com/opentracing/opentracing-go"
	"github.com/panjf2000/ants/v2"
	"net"
	"net/http"
	"ohmydns2/plugin"
	ohttp "ohmydns2/plugin/pkg/http"
	olog "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/pkg/prober"
	"ohmydns2/plugin/pkg/request"
	"ohmydns2/plugin/pkg/reuseport"
	"ohmydns2/plugin/pkg/trace"
	"ohmydns2/plugin/pkg/transport"
	"ohmydns2/plugin/prometheus/vars"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// ProbeServer represents an instance of a server, which serves
// DNS requests at a particular address (host and port). A
// server is capable of serving numerous zones on
// the same address and the listener may be stopped for
// graceful termination (POSIX only).
type ProbeServer struct {
	Addr string // Address we listen on

	server *http.Server // http服务
	m      sync.Mutex   // protects the servers

	conf         *PBConfig      // zones keyed by their port
	httpWg       sync.WaitGroup // used to wait on outstanding connections
	graceTimeout time.Duration  // the maximum duration of a graceful shutdown
	trace        trace.Trace    // the trace plugin for the server
	debug        bool           // disable recover()
	stacktrace   bool           // enable stacktrace in recover error log
	classChaos   bool           // allow non-INET class queries
	idleTimeout  time.Duration  // Idle timeout for TCP
	readTimeout  time.Duration  // Read timeout for TCP
	writeTimeout time.Duration  // Write timeout for TCP

	proberlist *prober.ProberAndGoroutList //探测器列表

	tsigSecret map[string]string
}

// response 是Prober控制响应的抽象
type response struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// MetadataCollector is a plugin that can retrieve metadata functions from all metadata providing plugins
type ProberMetadataCollector interface {
	Collect(context.Context, request.HTTPRequest) context.Context
}

// NewServer returns a new OhmyDNS2 probe server and compiles all plugins in to it.
func NewServer(addr string, conf *PBConfig) (*ProbeServer, error) {
	s := &ProbeServer{
		Addr:         addr,
		graceTimeout: 5 * time.Second,
		idleTimeout:  10 * time.Second,
		readTimeout:  3 * time.Second,
		writeTimeout: 5 * time.Second,
		tsigSecret:   make(map[string]string),
		proberlist: &prober.ProberAndGoroutList{
			Pl:     make(map[int]*prober.Prober),
			GRPool: new(ants.Pool),
		},
	}
	s.proberlist.GRPool, _ = ants.NewPool(goroutinePoolSize, ants.WithPreAlloc(true))
	olog.Infof("服务启动，监听地址: %v", addr)

	// We have to bound our wg with one increment
	// to prevent a "race condition" that is hard-coded
	// into sync.WaitGroup.Wait() - basically, an add
	// with a positive delta must be guaranteed to
	// occur before Wait() is called on the wg.
	// In a way, this kind of acts as a safety barrier.
	s.httpWg.Add(1)

	if conf.Debug {
		s.debug = true
		olog.D.Set()
	}
	s.stacktrace = conf.Stacktrace

	// append the config to the zone's configs
	s.conf = conf

	// set timeouts
	if conf.ReadTimeout != 0 {
		s.readTimeout = conf.ReadTimeout
	}
	if conf.WriteTimeout != 0 {
		s.writeTimeout = conf.WriteTimeout
	}
	if conf.IdleTimeout != 0 {
		s.idleTimeout = conf.IdleTimeout
	}

	//// copy tsig secrets
	//for key, secret := range conf.TsigSecret {
	//	s.tsigSecret[key] = secret
	//}

	// compile custom plugin for everything
	var stack plugin.Prober
	for i := len(conf.Plugin) - 1; i >= 0; i-- {
		stack = conf.Plugin[i](stack)

		// register the *handler* also
		conf.registerProber(stack)

		// If the current plugin is a MetadataCollector, bookmark it for later use. This loop traverses the plugin
		// list backwards, so the first MetadataCollector plugin wins.
		if mdc, ok := stack.(ProberMetadataCollector); ok {
			conf.metaCollector = mdc
		}

		if s.trace == nil && stack.Name() == "trace" {
			// we have to stash away the plugin, not the
			// Tracer object, because the Tracer won't be initialized yet
			if t, ok := stack.(trace.Trace); ok {
				s.trace = t
			}
		}
		// Unblock CH class queries when any of these plugins are loaded.
		if _, ok := EnableChaos[stack.Name()]; ok {
			s.classChaos = true
		}
		conf.PluginChain = stack
	}

	if !s.debug {
		// When reloading we need to explicitly disable debug logging if it is now disabled.
		olog.D.Clear()
	}

	return s, nil
}

// Compile-time check to ensure Server implements the caddy.GracefulServer interface
var _ caddy.GracefulServer = &ProbeServer{}

// Serve starts the server with an existing listener. It blocks until the server stops.
// This implements caddy.TCPServer interface.
func (ps *ProbeServer) Serve(l net.Listener) error {
	ps.m.Lock()

	ps.server = &http.Server{
		Addr: l.Addr().String(),
		Handler: http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(context.Background(), Key{}, ps)
			ctx = context.WithValue(ctx, LoopKey{}, 0)
			err, s := ps.ServeProbe(ctx, writer, r)
			if err != nil {
				olog.Errorf("prober_serve/Serve:  %v  \n  %v", err.Error(), s)
				return
			}
		}),
		DisableGeneralOptionsHandler: false,
		ReadTimeout:                  ps.readTimeout,
		WriteTimeout:                 ps.writeTimeout,
		IdleTimeout:                  ps.idleTimeout}

	ps.m.Unlock()

	return ps.server.ListenAndServe()
}

// ServePacket starts the server with an existing packetconn. It blocks until the server stops.
// This implements caddy.UDPServer interface.
func (ps *ProbeServer) ServePacket(p net.PacketConn) error {
	return nil
}

// Listen implements caddy.TCPServer interface.
func (ps *ProbeServer) Listen() (net.Listener, error) {
	l, err := reuseport.Listen("tcp", ps.Addr[len(transport.DNS+"://"):])
	if err != nil {
		return nil, err
	}
	return l, nil
}

// WrapListener Listen implements caddy.GracefulServer interface.
func (ps *ProbeServer) WrapListener(ln net.Listener) net.Listener {
	return ln
}

// ListenPacket implements caddy.UDPServer interface.
func (ps *ProbeServer) ListenPacket() (net.PacketConn, error) {
	p, err := reuseport.ListenPacket("udp", ps.Addr[len(transport.DNS+"://"):])
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Stop stops the server. It blocks until the server is
// totally stopped. On POSIX systems, it will wait for
// connections to close (up to a max timeout of a few
// seconds); on Windows it will close the listener
// immediately.
// This implements Caddy.Stopper interface.
func (ps *ProbeServer) Stop() (err error) {
	// 清空协程池
	defer ps.proberlist.GRPool.Release()
	if runtime.GOOS != "windows" {
		// force connections to close after timeout
		done := make(chan struct{})
		go func() {
			ps.httpWg.Done() // decrement our initial increment used as a barrier
			ps.httpWg.Wait()
			close(done)
		}()

		// Wait for remaining connections to finish or
		// force them all to close after timeout
		select {
		case <-time.After(ps.graceTimeout):
		case <-done:
		}
	}

	// Close the listener now; this stops the server without delay
	ps.m.Lock()
	// We might not have started and initialized the full set of servers
	if ps.server != nil {
		err = ps.server.Shutdown(context.Background())
	}

	ps.m.Unlock()
	return
}

// Address together with Stop() implement caddy.GracefulServer.
func (ps *ProbeServer) Address() string { return ps.Addr }

// ServeProbe 是每一个prober控制请求的入口
// It acts as a multiplexer for the requests zonename as
// defined in the request so that the correct zone
// (configuration and plugin stack) will handle the request.
func (ps *ProbeServer) ServeProbe(ctx context.Context, w http.ResponseWriter, req *http.Request) (error, string) {
	if !ps.debug {
		defer func() {
			// In case the user doesn't enable error plugin, we still
			// need to make sure that we stay alive up here
			if rec := recover(); rec != nil {
				if ps.stacktrace {
					olog.Errorf("Recovered from panic in server: %q %v\n%s", ps.Addr, rec, string(debug.Stack()))
				} else {
					olog.Errorf("Recovered from panic in server: %q %v", ps.Addr, rec)
				}
				vars.Panic.Inc()
				errorAndMetricsFunc(ps.Addr, w, "ProbeServer-ServeHTTP-Error", http.StatusInternalServerError)
			}
		}()
	}

	// Wrap the response writer in a ScrubWriter so we automatically make the reply fit in the client's buffer.
	//w = request.NewScrubWriter(r, w)

	// 获取请求参数
	param, _ := ohttp.ParseRequest(req)

	//// 用于探测的客户端(启用，嵌入prober结构体中)
	//c := new(dns.Client)

	pcf := ps.conf
	if pcf.PluginChain == nil { // can not get any plugins
		errorAndMetricsFunc(ps.Addr, w, "探测器缺少插件链", http.StatusNotImplemented)
		return errors.New("探测器缺少插件链"), "探测器缺少插件链"
	}
	if pcf.metaCollector != nil {
		// Collect metadata now, so it can be used before we send a request down the plugin chain.
		ctx = pcf.metaCollector.Collect(ctx, request.HTTPRequest{Req: req, W: w})
	}
	// 生成目标，开始探测
	targets, targetNum := getTarget(param[rangeParam])

	// 将探测配置添加到上下文中
	ctx = context.WithValue(ctx, prober.PAddrNum, targetNum)
	ctx = context.WithValue(ctx, prober.Pchain, ps.conf)

	// 创建并开始执行任务，返回探测器id
	proberid := ps.proberlist.AddProber(ctx, targets)

	// 都不匹配，尝试利用“.”指向的服务块
	//if z, ok := ps.zones["."]; ok {
	//
	//	for _, h := range z {
	//		if h.pluginChain == nil {
	//			continue
	//		}
	//
	//		if h.metaCollector != nil {
	//			// Collect metadata now, so it can be used before we send a request down the plugin chain.
	//			ctx = h.metaCollector.Collect(ctx, request.HTTPRequest{Req: req, W: w})
	//		}
	//
	//		// If all filter funcs pass, use this config.
	//		if passAllFilterFuncs(ctx, h.FilterFuncs, &request.HTTPRequest{Req: req, W: w}) {
	//			if h.ViewName != "" {
	//				// if there was a view defined for this Config, set the view name in the context
	//				ctx = context.WithValue(ctx, ViewKey{}, h.ViewName)
	//			}
	//			rcode, _ := h.pluginChain.ProbeDNS(ctx, c, msg)
	//			if !plugin.ClientWrite(rcode) {
	//				errorAndMetricsFunc(ps.Addr, w, " . --"+h.pluginChain.Name()+"错误", rcode)
	//			}
	//			return
	//		}
	//	}
	//}

	return nil, "成功创建探测器：" + proberid
}

// passAllFilterFuncs returns true if all filter funcs evaluate to true for the given request
func passAllFilterFuncs(ctx context.Context, filterFuncs []FilterFunc, req *request.HTTPRequest) bool {
	for _, ff := range filterFuncs {
		if !ff(ctx, req) {
			return false
		}
	}
	return true
}

// OnStartupComplete lists the sites served by this server
// and any relevant information, assuming Quiet is false.
func (ps *ProbeServer) OnStartupComplete() {
	if Quiet {
		return
	}

	out := startUpZones(transport.PROBER+"://", ps.Addr)
	if out != "" {
		fmt.Print(out)
	}
}

// Tracer returns the tracer in the server if defined.
func (ps *ProbeServer) Tracer() ot.Tracer {
	if ps.trace == nil {
		return nil
	}

	return ps.trace.Tracer()
}

// errorAndMetricsFunc 通过HTTP返回错误信息，并记录到Metrics中
func errorAndMetricsFunc(server string, w http.ResponseWriter, rs string, rc int) {
	defer vars.HTTPResponsesCount.WithLabelValues(server, http.StatusText(rc)).Inc()
	w.WriteHeader(rc)
	r := &response{Code: http.StatusInternalServerError, Msg: rs}
	msg, _ := json.Marshal(r)
	w.Write(msg)
	return

}

// 输入目标地址数据集，返回IP管道和目标地址数量，
func getTarget(s []string) (chan net.IP, int) {
	if s[0] == globalRange {
		//	全球探测
		return prober.GenGlobIPv4(), 0
	}
	// 局部探测
	ipchan := make(chan net.IP, 100)
	go func() {
		defer close(ipchan)
		for _, v := range s {
			ipchan <- net.ParseIP(v)
		}
	}()
	return ipchan, len(s)
}

const (
	Paramkey = "httpparam"
	Target   = "targetip"
)

type (
	// Key is the context key for the current server added to the context.
	Key struct{}

	// LoopKey is the context key to detect server wide loops.
	LoopKey struct{}

	// ViewKey is the context key for the current view, if defined
	ViewKey struct{}
)

// EnableChaos is a map with plugin names for which we should open CH class queries as we block these by default.
var EnableChaos = map[string]struct{}{
	"chaos":   {},
	"forward": {},
	"proxy":   {},
}

// Quiet mode will not show any informative output on initialization.
var Quiet bool
