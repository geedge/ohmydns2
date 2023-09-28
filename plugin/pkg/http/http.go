package http

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ParseRequest 解析HTTP请求中的URL参数，目前仅支持GET方法
func ParseRequest(req *http.Request) (map[string][]string, error) {
	switch req.Method {
	case http.MethodGet:
		return getRequest(req)
	case http.MethodPost:
		return postRequest(req)

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

// 支持json方式处理
func postRequest(req *http.Request) (map[string][]string, error) {
	r := make(map[string][]string)
	decoder := json.NewDecoder(req.Body)
	err := decoder.Decode(&r)
	if err != nil {
		return nil, err
	}
	return r, nil
}
