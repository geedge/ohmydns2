package prober

import (
	"context"
	"ohmydns2/plugin"
)

type Prober struct {
	Next plugin.Handler
}

func (p Prober) Probe(ctx context.Context) (int, error) {
	// 调用Prober

	return 0, nil
}

func (p Prober) Name() string {
	return name
}

const name = "v64dns-prober"
