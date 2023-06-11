package trace

import ot "github.com/opentracing/opentracing-go"

type Trace interface {
	Tracer() ot.Tracer
}
