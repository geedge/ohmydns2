package prober

import (
	"context"
	"encoding/json"
	"fmt"
	stdlog "log"
	"net"
	"net/http"
	"ohmydns2/core/dnsserver"
	ohttp "ohmydns2/plugin/pkg/http"
	olog "ohmydns2/plugin/pkg/log"
	"ohmydns2/plugin/pkg/prober"
	"ohmydns2/plugin/pkg/reuseport"
	"ohmydns2/plugin/pkg/transport"
	"ohmydns2/plugin/prometheus/vars"
	"strconv"
	"sync"

	"github.com/coredns/caddy"
)

type ProberWriter struct {
	laddr   net.Addr
	raddr   net.Addr
	request http.Request
}

type ProberHTTP struct {
	*ProbeServer
	httpServer   *http.Server
	listenAddr   net.Addr
	validRequest func(*http.Request) bool
	proberlist   *prober.ProberList
	m            sync.Mutex
}

type ret struct {
	Code      int                   `json:"code"`
	Probernum int                   `json:"probernum"`
	M         map[int]prober.Prober `json:"proberlist"`
	Msg       string                `json:"msg"`
}

type newret struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

// loggerAdapter is a simple adapter around CoreDNS logger made to implement io.Writer in order to log errors from HTTP server
type loggerAdapter struct {
}

func (l *loggerAdapter) Write(p []byte) (n int, err error) {
	olog.Debug(string(p))
	return len(p), nil
}

// HTTPRequestKey is the context key for the current processed HTTP request (if current processed request was done over DOH)
type HTTPRequestKey struct{}

// NewProberHTTP returns a new ohmydns prober(可用HTTP调用参数) and compiles all plugins in to it.
func NewProberHTTP(addr string, conf *PBConfig) (*ProberHTTP, error) {
	s, err := NewServer(addr, conf)
	if err != nil {
		return nil, err
	}

	// Use a custom request validation func or use the standard DoH path check.
	var validator func(*http.Request) bool
	validator = conf.HTTPRequestValidateFunc

	if validator == nil {
		validator = func(r *http.Request) bool { return r.URL.Path == proberPath }
	}

	srv := &http.Server{
		ReadTimeout:  s.readTimeout,
		WriteTimeout: s.writeTimeout,
		IdleTimeout:  s.idleTimeout,
		ErrorLog:     stdlog.New(&loggerAdapter{}, "", 0),
	}

	pl := &prober.ProberList{
		Pl: make(map[int]*prober.Prober),
	}
	sh := &ProberHTTP{
		ProbeServer: s, httpServer: srv, validRequest: validator, proberlist: pl,
	}
	sh.httpServer.Handler = sh

	return sh, nil
}

// Compile-time check to ensure Server implements the caddy.GracefulServer interface
var _ caddy.GracefulServer = &dnsserver.Server{}

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
	l, err := reuseport.Listen("tcp", p.Addr[len(transport.PROBER+"://"):])
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

	out := startUpZones(transport.PROBER+"://", p.Addr)
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
	// 设置响应头部
	w.Header().Set("Content-Type", prober_contentType)

	// 解析请求
	param, _ := ohttp.ParseRequest(r)
	// 参数定义
	// act: res代表获取当前所有Prober状态，new代表新建Prober
	// ptype: 探针类型，v64代表IPv4-IPv6关联发现的探针,默认v64
	// prange: 探测范围，默认全局，

	// 检查参数
	if r, rc := prober.VaildArgs(param); rc != 0 {
		//发生错误
		w.WriteHeader(http.StatusBadRequest)
		p.countResponse(http.StatusBadRequest)
		rec := &ret{Code: http.StatusBadRequest, Msg: r}
		msg, _ := json.Marshal(rec)
		w.Write(msg)
		return
	}
	// 参数没有问题，开始处理
	if v, ok := param["act"]; ok {
		switch v[0] {
		case "new":
			ctx := context.WithValue(context.Background(), Key{}, p.ProbeServer)
			ctx = context.WithValue(ctx, LoopKey{}, 0)
			ctx = context.WithValue(ctx, HTTPRequestKey{}, r)
			err, rs := p.ServeProbe(ctx, w, r)
			if err != nil {
				//发生错误
				w.WriteHeader(http.StatusInternalServerError)
				p.countResponse(http.StatusInternalServerError)
				r := &newret{Code: http.StatusInternalServerError, Msg: rs}
				msg, _ := json.Marshal(r)
				w.Write(msg)
				return
			}
			//一切正常
			w.WriteHeader(http.StatusOK)
			p.countResponse(http.StatusOK)
			r := &newret{Code: http.StatusOK, Msg: rs}
			msg, _ := json.Marshal(r)
			w.Write(msg)
			return
		case "stop":
			if n, pok := param["pid"]; pok {
				id, _ := strconv.Atoi(n[0])
				err := p.proberlist.DeleteProberById(id)
				if err != nil {
					return
				}
				return
			}
			//TODO:	无额外参数代表停止所有探测

		}
	} else {
		// 无act参数默认列举所有探测器当前状态
		allProber, m, err := p.proberlist.ListAllProber()
		if err != nil {
			return
		}
		rt := ret{
			Code:      http.StatusOK,
			Probernum: allProber,
			M:         m,
		}
		w.WriteHeader(http.StatusOK)
		p.countResponse(http.StatusOK)
		msg, _ := json.Marshal(rt)
		w.Write(msg)
	}

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

const (
	prober_contentType = "application/json"
	proberPath         = "/prober"
	proberurl          = "localhost"
)
