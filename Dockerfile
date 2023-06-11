FROM ubuntu:latest
LABEL authors="HDK"

# TODO：先启动Python服务再启动OhMydns

ENTRYPOINT ["top", "-b"]