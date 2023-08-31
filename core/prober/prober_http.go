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
	m            sync.Mutex
}

type proberstate struct {
	Code      int                   `json:"code"`
	Probernum int                   `json:"probernum"`
	M         map[int]prober.Prober `json:"proberlist"`
	Msg       string                `json:"msg"`
}

type codeAndMsg struct {
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
func NewProberHTTP(addr string, conf *prober.PBConfig) (*ProberHTTP, error) {
	s, err := NewServer(addr, conf)
	if err != nil {
		return nil, err
	}

	// 定义一个检查器来检查访问路径是否正确.
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

	sh := &ProberHTTP{
		ProbeServer: s, httpServer: srv, validRequest: validator,
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
func (p *ProberHTTP) ServePacket(net.PacketConn) error { return nil }

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
		err := p.httpServer.Shutdown(context.Background())
		if err != nil {
			return err
		}
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
	w.Header().Set("Content-Type", proberContenttype)

	// 解析请求
	param, _ := ohttp.ParseRequest(r)
	// 参数定义
	// act: res代表获取当前所有Prober状态，new代表新建Prober
	// ptype: 探针类型，v64代表IPv4-IPv6关联发现的探针,默认v64
	// prange: 探测范围，默认全局，

	// 检查参数
	if res, rc := prober.VaildArgs(param); rc != 0 {
		//发生错误
		w.WriteHeader(http.StatusBadRequest)
		p.countResponse(http.StatusBadRequest)
		rec := &proberstate{Code: http.StatusBadRequest, Msg: res}
		msg, _ := json.Marshal(rec)
		_, err := w.Write(msg)
		if err != nil {
			return
		}
		return
	}
	// 参数没有问题，开始处理
	if v, ok := param["act"]; ok {
		switch v[0] {

		case "new":
			ctx := context.WithValue(context.Background(), Key{}, p.ProbeServer)
			ctx = context.WithValue(ctx, LoopKey{}, 0)
			ctx = context.WithValue(ctx, HTTPRequestKey{}, r)
			serverr, rs := p.ServeProbe(ctx, w, r)
			// 服务发生错误
			if serverr != nil {
				//发生错误
				w.WriteHeader(http.StatusInternalServerError)
				p.countResponse(http.StatusInternalServerError)
				res := &codeAndMsg{Code: http.StatusInternalServerError, Msg: rs}
				msg, _ := json.Marshal(res)
				_, err := w.Write(msg)
				if err != nil {
					olog.Errorf("prober_http/ServeHTTP:  %v", err.Error())
					return
				}
				return
			}
			//一切正常
			w.WriteHeader(http.StatusOK)
			p.countResponse(http.StatusOK)
			rec := &codeAndMsg{Code: http.StatusOK, Msg: rs}
			msg, _ := json.Marshal(rec)
			_, err := w.Write(msg)
			if err != nil {
				olog.Errorf("prober_http/ServeHTTP:  %v", err.Error())
				return
			}
			return

		case "stop":
			if n, pok := param["pid"]; pok {
				id, _ := strconv.Atoi(n[0])
				err := p.proberlist.DeleteProberById(id)
				if err != nil {
					return
				}
				// 成功删除
				w.WriteHeader(http.StatusOK)
				p.countResponse(http.StatusOK)
				rec := &codeAndMsg{Code: http.StatusOK, Msg: "已停止探测器" + strconv.Itoa(id)}
				msg, _ := json.Marshal(rec)
				_, err = w.Write(msg)
				if err != nil {
					olog.Errorf("prober_http/ServeHTTP:  %v", err.Error())
					return
				}
				return
			}

			// 无参数指定则停止所有探测任务
			for pid := range p.proberlist.Pl {
				err := p.proberlist.DeleteProberById(pid)
				if err != nil {
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			p.countResponse(http.StatusOK)
			rec := &codeAndMsg{Code: http.StatusOK, Msg: "已停止所有探测器"}
			msg, _ := json.Marshal(rec)
			_, err := w.Write(msg)
			if err != nil {
				olog.Errorf("prober_http/ServeHTTP:  %v", err.Error())
				return
			}
			return
		default:
			//跳转到列举探测器状态
			break
		}
	}
	// 无act参数默认列举所有探测器当前状态
	allProber, m, err := p.proberlist.ListAllProber()
	if err != nil {
		return
	}
	rt := proberstate{
		Code:      http.StatusOK,
		Probernum: allProber,
		M:         m,
	}
	w.WriteHeader(http.StatusOK)
	p.countResponse(http.StatusOK)
	msg, _ := json.Marshal(rt)
	w.Write(msg)

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
	proberContenttype = "application/json"
	proberPath        = "/prober"
	proberurl         = "localhost"
)
