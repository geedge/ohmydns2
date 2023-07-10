package prober

const (
	prange = "range"
	ptype  = "ptype"
	ploop  = "loop"
)

const (
	defaultPrange      = "global"
	defaultPtype       = "v64"
	defaultTarget      = "n64.top"
	defaultStartsubv64 = "v4-1"
	defaultMaxGRout    = 4000 //默认协程最大运行数
	defaultMaxDial     = 5
	defaultPloop       = false
)

// 检查输入参数是否有定义，0代表一切正常，1代表有严重错误，无法创建，2代表有额外未定义参数，但仍可创建
func VaildArgs(args map[string][]string) (string, int) {
	return "OK", 0
}
