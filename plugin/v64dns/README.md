## 语法格式
```
v64dns 要负责解析的域名 { 
v4ns <v4NS的子域名> <v4NS的ip地址> 
v6ns <v6NS的子域名> <v6NS的ip地址>
chain <v4-only子域名称> <v6-only子域名称>
ip-embed 是否将请求ip嵌入到响应记录中
analyze <图数据库类型（目前仅支持neo4j）> <图数据库地址:端口(不指定则采用默认)> <用户名> <密码>
} 
```
v64DNS将负责解析所给域名下的v4-only域名和v6-only域名，
最终返回结果为解析器ip链组成的TXT记录，格式为ip1 ip2 ip3 ...
需要搭配探针使用，探针格式为
`[进度标识].[随机数].[实验ID].[水印].[子域名].[实验域名]`
v64DNS默认还集成了分析脚本，添加analyze参数即可

## example

```
v64ns example.com {
v4ns ns4 1.1.1.1
v6ns ns6 1:1::1
chain v4 v6
ip-embed
analyze neo4j 1.1.1.1:7474 test test123
}

```