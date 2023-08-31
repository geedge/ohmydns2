package atk

import (
	"strings"
)

func (a Atk) validRequest(qname string) int {
	//判断是否为第一阶段目标域名（放大）
	if strings.Contains(qname, a.zoneip4) {
		if len(strings.Split(qname, ".")) == 4 {
			//需要放大
			return 0
		}
		// 请求被修改，返回权威信息
		return -1
	}
	if strings.Contains(qname, a.zoneip6) {
		//需要统计
		return 1
	}
	// 均不满足，返回权威信息
	return 2
}
