package log

import "runtime"

// 获取运行时函数
func RunFuncName() (string, int) {
	_, file, line, ok := runtime.Caller(1)
	if ok {
		return file, line
	}
	return "null", 0
}
