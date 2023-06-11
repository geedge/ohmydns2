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
func (pl ProberList) AddProber(arg map[string]string) int {
	t := time.Now().Unix()
	p := NewProber()

	p.pid = int(t)
	pl.pl[int(t)] = p
	return int(t)
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
	p.Prange = arg["range"]
	p.Ptype = arg["ptype"][0]
}

// 探测代码
func (p *Prober) Start() error {

}

func (p *Prober) Stop() error {
	p.sigstop <- 1
	return nil
}
