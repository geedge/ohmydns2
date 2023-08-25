package prober

import (
	"context"
	"crypto/tls"
	"github.com/miekg/dns"
	"github.com/panjf2000/ants/v2"
	"math"
	"net"
	"ohmydns2/core/prober"
	olog "ohmydns2/plugin/pkg/log"
	"sync"
)

type Prober struct {
	Prange           []string `json:"prange"`      // 探测范围
	Ptype            string   `json:"ptype"`       // 探针类型
	AllAddrNum       int      `json:"allAddrnum"`  // 总共需要探测的地址数
	ScanAddrNum      int      `json:"scanAddrNum"` // 已探测过的地址数
	Pid              int      `json:"pid"`         // 探测器ID
	Loop             bool     `json:"loop"`        //是否持续探测
	m                *sync.Mutex
	stop             context.CancelFunc // stop信号量
	removeFromPGList func()             //从探测器列表中删除对应记录
	c                *dns.Client
}

// 新建探测器
func NewProber(ctx context.Context) *Prober {
	p := new(Prober)

	//配置探测器
	ok := true
	if p.Prange, ok = ctx.Value(prange).([]string); !ok {
		p.Prange[0] = defaultPrange
	}
	if p.Ptype, ok = ctx.Value(ptype).(string); !ok {
		p.Ptype = defaultPtype
	}
	if p.Loop, ok = ctx.Value(ploop).(bool); !ok {
		p.Loop = defaultPloop
	}
	if p.AllAddrNum, ok = ctx.Value(PAddrNum).(int); !ok {
		p.AllAddrNum = defaultPnum
	}

	// 配置客户端
	p.c = &dns.Client{
		Timeout: pTimeout,
	}
	switch ctx.Value(pnet) {
	case "tcp":
		p.c.Net = "tcp"
	case "tcp-tls":
		p.c.Net = "tcp-tls"
		// TODO:tls配置
		p.c.TLSConfig = &tls.Config{}
	default:
		break
	}
	return p
}

//// SetArg 设定prober
//func (p *Prober) SetArg(arg map[string][]string) {
//	if v, ok := arg[prange]; ok {
//		p.Prange = v
//		p.AllAddr = len(v)
//	} else {
//		// 默认全网探测
//		p.Prange = []string{defaultPrange}
//		p.AllAddr = math.MaxInt32
//	}
//	if v, ok := arg[ptype]; ok {
//		p.Ptype = v[0]
//	} else {
//		// 默认v64 CNAME关联
//		p.Ptype = defaultPtype
//	}
//	// 是否持续探测，默认只探测一次
//	if v, ok := arg[ploop]; ok && v[0] == "1" {
//		p.Loop = true
//	} else {
//		p.Loop = defaultPloop
//	}
//	p.stop = make(chan bool)
//	p.ScannedAddr = 0
//	p.c = new(dns.Client)
//	p.c.DialTimeout = defaultMaxDial * time.Second
//	p.c.ReadTimeout = p.c.DialTimeout
//}

// Start 探测代码
func (p *Prober) Start(ctx context.Context, target chan net.IP, pool *ants.Pool) {

	var wg sync.WaitGroup

	// 探测轮数
	round := 1
	if p.Loop {
		round = math.MaxInt
	}
	for {
		// 下一轮次的数据
		for {
			if ip, ok := <-target; ok {
				select {
				case <-ctx.Done():
					// 中途取消
					return
				default:
					err := pool.Submit(p.Probe(ctx, ip, &wg))
					if err != nil {
						olog.Errorf("prober/Start:  %v", err.Error())
						return
					}
					p.addScanAddrNum()
				}
			} else {
				// 一轮扫描完成
				round -= 1
				// 探测轮数归零，退出
				if round == 0 {
					err := p.exit()
					if err != nil {
						return
					}
					return
				}
				// 未归零，开始下一轮
				break
			}
		}
	}
}

func (p *Prober) Stop() error {
	p.stop()
	return nil
}

func (p *Prober) exit() error {
	p.removeFromPGList()
	return nil
}

func (p *Prober) addScanAddrNum() {
	// 加锁防止数据错误
	p.m.Lock()
	p.ScanAddrNum += 1
	p.m.Unlock()
}

// Probe 所有探测方法的封装方法
func (p *Prober) Probe(ctx context.Context, ip net.IP, wg *sync.WaitGroup) func() {
	msg := new(dns.Msg)
	pcf := ctx.Value(Pchain).(*prober.PBConfig)
	return func() {
		// 将目标IP传入上下文
		ctx = context.WithValue(ctx, prober.Target, ip)
		_, _ = pcf.PluginChain.ProbeDNS(ctx, p.c, msg)
		wg.Done()
	}
}

func (p *Prober) Probev64(ip net.IP) error {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(p.makeProbe(ip)), dns.TypeTXT)
	// TODO:展示响应内容
	_, _, err := p.c.Exchange(msg, ip.String()+":53")
	if err != nil {
		return err
	}
	return nil
}
