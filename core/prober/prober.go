package prober

import (
	"github.com/miekg/dns"
	"sync"
)

type Prober struct {
	Prange      []string `json:"prange"`      // 探测范围
	Ptype       string   `json:"ptype"`       // 探针类型
	AllAddr     int      `json:"allAddr"`     // 总共需要探测的地址数
	ScannedAddr int      `json:"scannedAddr"` // 已探测过的地址数
	Pid         int      `json:"pid"`         // 探测器ID
	Loop        bool     `json:"loop"`        //是否持续探测
	m           sync.Mutex
	stop        chan bool // stop信号量
	c           *dns.Client
}
