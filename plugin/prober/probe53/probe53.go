package probe53

import (
	"context"
	"github.com/miekg/dns"
	"net"
	"ohmydns2/plugin/pkg/prober"
)

type Probe53 struct {
}

func (p Probe53) ProbeDNS(ctx context.Context, client *dns.Client, msg *dns.Msg) (int, error) {
	// ip+port作为目标
	_, _, err := client.Exchange(msg, ctx.Value(target).(net.IP).String()+":53")
	if err != nil {
		logger.Errorf("探测%v发生错误，原因为: %v", ctx.Value(target).(net.IP).String(), err.Error())
		return 1, err
	}
	return 0, nil
}

func (p Probe53) Name() string {
	return "probe53"
}

var target = prober.Target
