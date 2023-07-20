package qname

import "strings"

// intersectionStringsList 判断字符串内是否有sublist中的元素,并返回匹配的元素
func intersectionStringsList(str string, sublist []string) (string, bool) {
	for _, item := range sublist {
		if strings.Contains(str, item) {
			return item, true
		}
	}
	return "", false
}
