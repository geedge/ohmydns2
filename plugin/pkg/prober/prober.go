package prober

import (
	"strconv"
	"sync"
	"time"
)

// 探测器列表
type ProberList struct {
	pl map[int]*Prober // 探测器
}

// 获取当前正在运行的探测器数量
func (pl ProberList) GetNum() int {
	return len(pl.pl)
}

// 增加一个探测器,并返回对应的pid
func (pl ProberList) AddProber(arg map[string][]string) error {
	t := time.Now().Unix()
	p := NewProber()
	p.SetArg(arg)
	p.pid = int(t)
	pl.pl[int(t)] = p
	return nil
}

// 列举所有探测器信息
func (pl ProberList) ListAllProber() (int, map[int]*Prober, error) {
	return pl.GetNum(), pl.pl, nil
}

func (pl ProberList) DeleteProber(pid int) error {
	err := pl.pl[pid].Stop()
	if err != nil {
		panic("can't Stop prober " + strconv.Itoa(pid))
	}
	return nil
}

type Prober struct {
	Prange      []string // 探测范围
	Ptype       string   // 探针类型
	allAddr     int      // 总共需要探测的地址数
	scannedAddr int      // 已探测过的地址数
	pid         int      // 探测器ID
	m           sync.Mutex
	sigstop     chan int // stop信号管道
}

func NewProber() *Prober {
	p := new(Prober)
	return p
}

// TODO:设定prober
func (p *Prober) SetArg(arg map[string][]string) {
	if v, ok := arg[prange]; ok {
		p.Prange = v
	} else {
		// 默认全网探测
		p.Prange[0] = defaultPrange
	}
	if v, ok := arg[ptype]; ok {
		p.Ptype = v[0]
	} else {
		// 默认v64 CNAME关联
		p.Ptype = defaultPtype
	}
}

// 探测代码
func (p *Prober) Start() error {
	return nil
}

func (p *Prober) Stop() error {
	p.sigstop <- 1
	return nil
}
