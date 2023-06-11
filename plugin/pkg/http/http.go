package http

import (
	"fmt"
	"net/http"
)

// ParseRequest 解析HTTP请求中的URL参数，目前仅支持GET方法
func ParseRequest(req *http.Request) (map[string][]string, error) {
	switch req.Method {
	case http.MethodGet:
		return getRequest(req)

	default:
		return nil, fmt.Errorf("method not allowed: %s", req.Method)
	}
}

func getRequest(req *http.Request) (map[string][]string, error) {
	r := make(map[string][]string)
	for k, v := range req.URL.Query() {
		r[k] = v
	}
	return r, nil
}
