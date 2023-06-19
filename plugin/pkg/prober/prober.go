package prober

import (
	"github.com/miekg/dns"
	"math"
	"net"
	olog "ohmydns2/plugin/pkg/log"
	"strconv"
	"sync"
	"time"
)

// 探测器列表
type ProberList struct {
	Pl map[int]*Prober // 探测器
}

// 获取当前正在运行的探测器数量
func (pl ProberList) GetNum() int {
	return len(pl.Pl)
}

// 增加一个探测器,并返回对应的pid
func (pl ProberList) AddProber(arg map[string][]string) (string, error) {
	//当前时间戳，作为探测器ID
	t := time.Now().Unix()
	p := NewProber()
	p.SetArg(arg)
	p.Pid = int(t)
	pl.Pl[int(t)] = p
	if p.Prange[0] != defaultPrange {
		olog.Infof("新增探测器 %v:\t探测范围\t探针类型\n\t\t\t\t%v\t%v", p.Pid, defaultPrange, p.Ptype)
	} else {
		olog.Infof("新增探测器 %v:\t探测范围\t探针类型\n\t\t\t\t%v\t%v", p.Pid, "自定义", p.Ptype)
	}
	p.Start()
	return "OK", nil
}

// 列举所有探测器信息
func (pl ProberList) ListAllProber() (int, map[int]Prober, error) {
	rm := make(map[int]Prober)
	for k, v := range pl.Pl {
		rm[k] = *v
	}

	return pl.GetNum(), rm, nil
}

func (pl ProberList) DeleteProber(pid int) error {
	err := pl.Pl[pid].Stop()
	if err != nil {
		panic("can't Stop prober " + strconv.Itoa(pid))
	}
	return nil
}

type Prober struct {
	Prange      []string `json:"prange"`      // 探测范围
	Ptype       string   `json:"ptype"`       // 探针类型
	AllAddr     int      `json:"allAddr"`     // 总共需要探测的地址数
	ScannedAddr int      `json:"scannedAddr"` // 已探测过的地址数
	Pid         int      `json:"pid"`         // 探测器ID
	m           sync.Mutex
	sigstop     chan int // stop信号管道
	c           *dns.Client
	wg          sync.WaitGroup //协程运行池
	worker      int            //最大协程数
}

func NewProber() *Prober {
	p := new(Prober)
	return p
}

// TODO:增加参数检查功能，判断参数值是否合法
// SetArg 设定prober
func (p *Prober) SetArg(arg map[string][]string) {
	if v, ok := arg[prange]; ok {
		p.Prange = v
		p.AllAddr = len(v)
	} else {
		// 默认全网探测
		p.Prange = []string{defaultPrange}
		p.AllAddr = math.MaxInt32
	}
	if v, ok := arg[ptype]; ok {
		p.Ptype = v[0]
	} else {
		// 默认v64 CNAME关联
		p.Ptype = defaultPtype
	}
	p.ScannedAddr = 0
	p.worker = defaultMaxGRout
	p.c = new(dns.Client)
	p.c.DialTimeout = defaultMaxDial * time.Second
	p.c.ReadTimeout = p.c.DialTimeout
}

// Start 探测代码
func (p *Prober) Start() error {
	if p.Prange[0] == defaultPrange {
		//	全球探测
		ipc := GenGlobIPv4()
		go func() {
			p.wg.Add(p.worker)
			count := p.worker
			for {
				ip, ok := <-ipc
				if ok {
					go func() {
						_ = p.Probe(ip)
						p.ScannedAddr += 1
						p.wg.Done()
					}()

				} else {
					break
				}
				count -= 1
				if count == 0 {
					p.wg.Wait()
					count = p.worker
					p.wg.Add(p.worker)
				}
			}

		}()
	}
	return nil
}

func (p *Prober) Stop() error {
	p.sigstop <- 1
	return nil
}

// Probe 所有探测方法的封装方法
func (p *Prober) Probe(ip net.IP) error {
	if p.Ptype == defaultPtype {
		return p.Probev64(ip)
	}
	return nil
}

func (p *Prober) Probev64(ip net.IP) error {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(p.makeProbe(ip)), dns.TypeTXT)
	// TODO:展示响应内容
	_, _, err := p.c.Exchange(msg, ip.String()+":53")
	if err != nil {
		olog.Info(err.Error())
		return err
	}
	return nil
}
