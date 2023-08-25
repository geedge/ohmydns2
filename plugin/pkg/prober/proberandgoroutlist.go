package prober

import (
	"context"
	"errors"
	"github.com/panjf2000/ants/v2"
	"net"
	olog "ohmydns2/plugin/pkg/log"
	"strconv"
	"time"
)

// 探测器和协程状态列表
type ProberAndGoroutList struct {
	Pl     map[int]*Prober // 探测器
	GRPool *ants.Pool
}

// 获取当前正在运行的探测器数量
func (pl *ProberAndGoroutList) GetNum() int {
	return len(pl.Pl)
}

// 增加一个探测器,并返回对应的pid
func (pl *ProberAndGoroutList) AddProber(ctx context.Context, targetIP chan net.IP) string {
	//当前时间戳，作为探测器ID
	t := time.Now().Unix()
	//创建一个新的Prober对象
	p := NewProber(ctx)
	pctx, cancel := context.WithCancel(ctx)
	p.stop = cancel
	p.Pid = int(t)
	p.removeFromPGList = func() {
		err := pl.DeleteProberById(p.Pid)
		if err != nil {
			return
		}
	}
	pl.Pl[int(t)] = p

	if p.Prange[0] != defaultPrange {
		olog.Infof("新增探测器 %v:\t探测范围\t探针类型\n\t\t\t\t%v\t%v", p.Pid, defaultPrange, p.Ptype)
	} else {
		olog.Infof("新增探测器 %v:\t探测范围\t探针类型\n\t\t\t\t%v\t%v", p.Pid, "自定义", p.Ptype)
	}
	// 开始执行任务
	go p.Start(pctx, targetIP, pl.GRPool)

	return strconv.Itoa(p.Pid)
}

// 列举所有探测器信息
func (pl *ProberAndGoroutList) ListAllProber() (int, map[int]Prober, error) {
	rm := make(map[int]Prober)
	for k, v := range pl.Pl {
		rm[k] = *v
	}

	return pl.GetNum(), rm, nil
}

// DeleteProberById 根据探测器ID停止探测任务
func (pl *ProberAndGoroutList) DeleteProberById(pid int) error {
	err := pl.Pl[pid].Stop()
	delete(pl.Pl, pid)
	if err != nil {
		panic("can't Stop prober " + strconv.Itoa(pid))
	}
	return nil
}

// DeleteAllProber 删除所有的运行的探测器，底层调用了DeleteProberById
func (pl *ProberAndGoroutList) DeleteAllProber() error {
	for k, _ := range pl.Pl {
		err := pl.DeleteProberById(k)
		if err != nil {
			return err
		}
	}
	return nil
}

// DeleteProber 根据探测器对象找到对应探测ID并删除
func (pl *ProberAndGoroutList) DeleteProber(p *Prober) error {
	for k, v := range pl.Pl {
		if v == p {
			err := pl.DeleteProberById(k)
			if err != nil {
				return err
			}
			return nil
		}
	}
	olog.Error("未找到该探测器")
	return errors.New("not found this prober!!")
}
