package analyze

import (
	"context"
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
	A   Analyzer
	c   unsafe.Pointer
	lck sync.Mutex
)

func NewAnalyzer(gtype, guri, guser, gpass string) (*Analyzer, error) {
	B := Analyzer{
		Graphtype:  gtype,
		Graphuri:   guri,
		GraphUser:  guser,
		GraphPass:  gpass,
		IsA:        true,
		grpcClient: nil,
	}
	conn, err := B.GetConn("127.0.0.1:56789")
	if err != nil {
		olog.Errorf("GetGrpcClient:%s", err.Error())
		panic("error")
	}
	B.grpcClient = pb.NewGrpcServiceClient(conn)
	return &B, nil
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
		olog.Errorf("连接服务端失败: %s", err)
		return nil, err
	}
	return conn, nil
}

// 远程调用Python脚本方法
func (a Analyzer) Go2py(i []string) {
	lck.Lock()
	defer lck.Unlock()
	// 调用服务端函数
	r, err := a.grpcClient.AnalyzeService(context.Background(), &pb.DnsChain{
		Gtype: a.Graphtype,
		Guri:  a.Graphuri,
		Guser: a.GraphUser,
		Gpass: a.GraphPass,
		Data:  i,
	})
	if err != nil {
		print(r)
		olog.Errorf("调用解析链分析器代码失败: %s", err)
		return
	}
	// 处理不成功则显示警告信息
	if r.Res != "success" {
		olog.Warning(r.Res)
	}

}
