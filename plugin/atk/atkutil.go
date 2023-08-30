package atk

import (
	"strings"
)

func (a Atk) validRequest(qname string) int {
	//判断是否为第一阶段目标域名（放大）
	if strings.Contains(qname, a.zoneip4) {
		//需要放大
		return 0
	}
	if strings.Contains(qname, a.zoneip6) {
		//需要统计
		return 1
	}
	// 均不满足，不响应
	return 2
}
