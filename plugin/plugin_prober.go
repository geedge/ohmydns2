package plugin

import (
	"context"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	"net/http"
)

type (
	// Pplugin 是一个中间层，它定义了一个用于探测的插件传递链，前一个 Handler 处理完成之后将紧接着传递到下一个 Handler。
	Pplugin func(Prober) Prober

	// Prober  except ProbeDNS may return an rcode
	// and/or error.
	//
	// If ProbeDNS writes to the request body, it should return a status
	// code. OhmyDNS2 assumes *no* reply has yet been written if the status
	// code is one of the following:
	//
	// * SERVFAIL (dns.RcodeServerFailure)
	//
	// * REFUSED (dns.RecodeRefused)
	//
	// * FORMERR (dns.RcodeFormatError)
	//
	// * NOTIMP (dns.RcodeNotImplemented)
	//
	// All other response codes signal other handlers above it that the
	// response message is already written, and that they should not write
	// to it also.
	//
	// If ServeDNS encounters an error, it should return the error value
	// so it can be logged by designated error-handling plugin.
	//
	// If writing a response after calling another ServeDNS method, the
	// returned rcode SHOULD be used when writing the response.
	//
	// If handling errors after calling another ServeDNS method, the
	// returned error value SHOULD be logged or handled accordingly.
	//
	// Otherwise, return values should be propagated down the plugin
	// chain by returning them unchanged.
	Prober interface {
		ProbeDNS(context.Context, dns.Client, *dns.Msg) (int, error)
		Name() string
	}

	// ProberFunc is a convenience type, except
	// ProbeDNS returns an rcode and an error. See Handler
	// documentation for more information.
	ProberFunc func(context.Context, dns.Client, *dns.Msg) (int, error)
)

// ServeDNS implements the Handler interface.
func (p ProberFunc) ProbeDNS(ctx context.Context, c dns.Client, msg *dns.Msg) (int, error) {
	return p(ctx, c, msg)
}

// Name implements the Handler interface.
func (p ProberFunc) Name() string { return "proberfunc" }

// PError returns err with 'plugin/name: ' prefixed to it.
func PError(name string, err error) error { return fmt.Errorf("%s/%s: %s", "prober-plugin", name, err) }

// PNextOrFailure  calls next.ProbeDNS when next is not nil, otherwise it will return, a ServerFailure and a `no next plugin found` error.
func PNextOrFailure(name string, next Prober, ctx context.Context, c dns.Client, msg *dns.Msg) (int, error) { // nolint: golint
	if next != nil {
		if span := ot.SpanFromContext(ctx); span != nil {
			child := span.Tracer().StartSpan(next.Name(), ot.ChildOf(span.Context()))
			defer child.Finish()
			ctx = ot.ContextWithSpan(ctx, child)
		}
		return next.ProbeDNS(ctx, c, msg)
	}

	return http.StatusInternalServerError, Error(name, errors.New("no next plugin found"))
}

// ClientWrite returns true if the response has been written to the client.
// Each plugin to adhere to this protocol.
//func ClientWrite(rcode int) bool {
//	switch rcode {
//	case dns.RcodeServerFailure:
//		fallthrough
//	case dns.RcodeRefused:
//		fallthrough
//	case dns.RcodeFormatError:
//		fallthrough
//	case dns.RcodeNotImplemented:
//		return false
//	}
//	return true
//}

// PErrOnce is returned when a plugin doesn't support multiple setups per server.
var PErrOnce = errors.New("this plugin can only be used once per Server Block")
