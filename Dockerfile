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
FROM python:3
WORKDIR /project/ohmydns2
COPY --from=0 /project/ohmydns2/ /project/ohmydns2/
# 2115是prober默认端口
EXPOSE 2115/tcp 53/tcp 53/udp 1153/udp 1153/tcp
# 先启动Python服务再启动OhMydns
COPY plugin/v64dns/analyze/pb/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt;\
    mkdir "config";\
    mkdir "data";\
    ln "-s plugin/v64dns/analyze/data data"
CMD [ "python", "./plugin/v64dns/analyze/pb/analyzer.py" ]
ENTRYPOINT ["./ohmydns2"]





