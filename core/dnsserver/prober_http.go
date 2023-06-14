package dnsserver

import (
	"context"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"ohmydns2/plugin/pkg/doh"
	ohttp "ohmydns2/plugin/pkg/http"
	"ohmydns2/plugin/pkg/reuseport"
	"ohmydns2/plugin/pkg/transport"
	"ohmydns2/plugin/prometheus/vars"
	"strconv"

	"github.com/coredns/caddy"
)

const proberPath = "/prober"
const proberurl = "localhost"

type ProberWriter struct {
	laddr   net.Addr
	raddr   net.Addr
	request http.Request
}

type ProberHTTP struct {
	*Server
	httpServer   *http.Server
	listenAddr   net.Addr
	validRequest func(*http.Request) bool
}

// NewProberHTTP returns a new ohmydns prober(可用HTTP调用参数) and compiles all plugins in to it.
func NewProberHTTP(addr string, group []*Config) (*ProberHTTP, error) {
	s, err := NewServer(addr, group)
	if err != nil {
		return nil, err
	}

	// Use a custom request validation func or use the standard DoH path check.
	var validator func(*http.Request) bool
	for _, z := range s.zones {
		for _, conf := range z {
			validator = conf.HTTPRequestValidateFunc
		}
	}
	if validator == nil {
		validator = func(r *http.Request) bool { return r.URL.Path == proberPath }
	}

	srv := &http.Server{
		ReadTimeout:  s.readTimeout,
		WriteTimeout: s.writeTimeout,
		IdleTimeout:  s.idleTimeout,
		ErrorLog:     stdlog.New(&loggerAdapter{}, "", 0),
	}
	sh := &ProberHTTP{
		Server: s, httpServer: srv, validRequest: validator,
	}
	sh.httpServer.Handler = sh

	return sh, nil
}

// Compile-time check to ensure Server implements the caddy.GracefulServer interface
var _ caddy.GracefulServer = &Server{}

// Serve implements caddy.TCPServer interface.
func (p *ProberHTTP) Serve(l net.Listener) error {
	p.m.Lock()
	p.listenAddr = l.Addr()
	p.m.Unlock()

	return p.httpServer.Serve(l)
}

// ServePacket implements caddy.UDPServer interface.
func (p *ProberHTTP) ServePacket(pc net.PacketConn) error { return nil }

// Listen implements caddy.TCPServer interface.
func (p *ProberHTTP) Listen() (net.Listener, error) {
	l, err := reuseport.Listen("tcp", p.Addr[len("http://"):])
	if err != nil {
		return nil, err
	}
	return l, nil
}

// ListenPacket implements caddy.UDPServer interface.
func (p *ProberHTTP) ListenPacket() (net.PacketConn, error) { return nil, nil }

// OnStartupComplete lists the sites served by this server
// and any relevant information, assuming Quiet is false.
func (p *ProberHTTP) OnStartupComplete() {
	if Quiet {
		return
	}

	out := startUpZones(transport.PROBER+"://", p.Addr, p.zones)
	if out != "" {
		fmt.Print(out)
	}
}

// Stop stops the server. It blocks until the server is totally stopped.
func (p *ProberHTTP) Stop() error {
	p.m.Lock()
	defer p.m.Unlock()
	if p.httpServer != nil {
		p.httpServer.Shutdown(context.Background())
	}
	return nil
}

// ServeHTTP is the handler that gets the HTTP request and converts to the dns format, calls the plugin
// chain, converts it back and write it to the client.
func (p *ProberHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.validRequest(r) {
		http.Error(w, "", http.StatusNotFound)
		p.countResponse(http.StatusNotFound)
		return
	}

	// 解析请求
	param, _ := ohttp.ParseRequest(r)
	// 参数定义
	// act: res代表获取当前所有Prober状态，new代表新建Prober
	// ptype: 探针类型，v64代表IPv4-IPv6关联发现的探针
	// prange: 探测范围，默认全局，
	if v, ok := param["act"]; ok && v[0] == "new" {
		//TODO:新建探测器
	} else {
		//TODO:展示当前运行探测器
	}

	// We just call the normal chain handler - all error handling is done there.
	// We should expect a packet to be returned that we can send to the client.
	//ctx := context.WithValue(context.Background(), Key{}, p.Server)
	//ctx = context.WithValue(ctx, LoopKey{}, 0)
	//ctx = context.WithValue(ctx, HTTPRequestKey{}, r)
	////p.ServeDNS(ctx, dw, msg)
	//
	//// See section 4.2.1 of RFC 8484.
	//// We are using code 500 to indicate an unexpected situation when the chain
	//// handler has not provided any response message.
	//if dw.Msg == nil {
	//	http.Error(w, "No response", http.StatusInternalServerError)
	//	p.countResponse(http.StatusInternalServerError)
	//	return
	//}
	//
	//buf, _ := dw.Msg.Pack()
	//
	//mt, _ := response.Typify(dw.Msg, time.Now().UTC())
	//age := dnsutil.MinimalTTL(dw.Msg, mt)
	buf := []byte("test")
	w.Header().Set("Content-Type", doh.MimeType)
	w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
	w.WriteHeader(http.StatusOK)
	p.countResponse(http.StatusOK)

	w.Write(buf)
}

func (p *ProberHTTP) countResponse(status int) {
	vars.HTTPSResponsesCount.WithLabelValues(p.Addr, strconv.Itoa(status)).Inc()
}

// Shutdown stops the server (non gracefully).
func (p *ProberHTTP) Shutdown() error {
	if p.httpServer != nil {
		p.httpServer.Shutdown(context.Background())
	}
	return nil
}
