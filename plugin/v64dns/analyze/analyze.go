package analyze

import (
	"context"
	"net"
	"ohmydns2/plugin/v64dns/analyze/pb"
	"sync"
	"sync/atomic"
	"unsafe"

	olog "ohmydns2/plugin/pkg/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Analyzer struct {
	Graphtype  string
	Graphuri   string
	GraphUser  string
	GraphPass  string
	IsA        bool
	grpcClient pb.GrpcServiceClient
}

var (
	c   unsafe.Pointer
	lck sync.Mutex
)

// GetGrpcClient 复用Grpc连接, 返回需要的client
func (a Analyzer) GetGrpcClient(target string) error {
	conn, err := a.GetConn(target)
	if err != nil {
		olog.Error("GetGrpcClient:%s", err.Error())
		return err
	}
	a.grpcClient = pb.NewGrpcServiceClient(conn)
	return nil //此处调用pb.go文件中生成的创建client的方法
}

func (a Analyzer) GetConn(target string) (*grpc.ClientConn, error) {
	if atomic.LoadPointer(&c) != nil {
		return (*grpc.ClientConn)(c), nil
	}
	lck.Lock()
	defer lck.Unlock()
	if atomic.LoadPointer(&c) != nil { //double check
		return (*grpc.ClientConn)(c), nil
	}
	cli, err := newGrpcConn(target)
	if err != nil {
		return nil, err
	}
	atomic.StorePointer(&c, unsafe.Pointer(cli))
	return cli, nil
}

// 新建grpc连接
func newGrpcConn(target string) (*grpc.ClientConn, error) {
	conn, err := grpc.Dial(
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		olog.Error("连接服务端失败: %s", err)
		return nil, err
	}
	return conn, nil
}

func (a *Analyzer) AnalyzeChain(i []net.IP) {
	if a.IsA {
		data := []string{}
		for _, ip := range i {
			data = append(data, ip.String())
		}
		a.go2py(data)
	}
}

// 远程调用Python脚本方法
func (a Analyzer) go2py(i []string) {

	// 调用服务端函数
	r, err := a.grpcClient.AnalyzeService(context.Background(), &pb.DnsChain{
		Gtype: a.Graphtype,
		Guri:  a.Graphuri,
		Guser: a.GraphUser,
		Gpass: a.GraphUser,
		Data:  i,
	})
	// 处理不成功则显示警告信息
	if r.Res != "success" {
		olog.Warning(r.Res)
	}
	if err != nil {
		olog.Error("调用解析链分析器代码失败: %s", err)
		return
	}
}
