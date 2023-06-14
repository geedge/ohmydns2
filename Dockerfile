FROM golang:latest
LABEL authors="HDK"
WORKDIR /project/ohmydns2
COPY . .
# 配置依赖镜像源
RUN go env -w GO111MODULE=on;\
    go env -w GOPROXY=https://goproxy.io,direct;\
    sed -i s@/deb.debian.org/@/mirrors.aliyun.com/@g /etc/apt/sources.list;\
    sed -i s@/security.debian.org/@/mirrors.aliyun.com/@g /etc/apt/sources.list;\
    export DEBCONF_NONINTERACTIVE_SEEN=true \
           DEBIAN_FRONTEND=noninteractive \
           DEBIAN_PRIORITY=critical \
           TERM=linux ; \
    apt-get -qq update ; \
    apt-get -yyqq upgrade ; \
    apt-get -yyqq install ca-certificates libcap2-bin; \
    apt-get clean; \
    go build -o ./ohmydns2 ./
#  生成部署
FROM ubuntu:latest
WORKDIR /project/ohmydns2
COPY --from=0 /project/ohmydns2/ /project/ohmydns2/
EXPOSE 53/tcp
EXPOSE 2153/tcp
EXPOSE 53/udp
EXPOSE 1153/udp
EXPOSE 1153/tcp
# TODO：先启动Python服务再启动OhMydns
ENTRYPOINT ["./ohmydns2"]





