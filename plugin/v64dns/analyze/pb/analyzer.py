# !coding=utf-8
import logging
import time
from concurrent import futures

import grpc
# from py2neo import Graph, Node, Relationship, Subgraph
# from py2neo import NodeMatcher, RelationshipMatcher
from neomodel import db, StringProperty, DateTimeFormatProperty, RelationshipTo, StructuredRel, IntegerProperty, \
    StructuredNode

import analyze_pb2
import analyze_pb2_grpc
import analyzedutil as aul

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')


class node:
    ip = ""
    AS = ""
    next = ""
    isp = ""
    cou = ""
    couCode = ""
    prov = ""
    lat = ""
    lng = ""
    FindTime = ""

    def __init__(self, ip):
        self.ip = ip
        record = aul.getrecord(ip)
        self.isp = aul.filterNull(record.get('isp', b'').decode("utf-8"))
        self.lat = aul.filterNull(record.get('latwgs', b'').decode("utf-8"))
        self.lng = aul.filterNull(record.get('lngwgs', b'').decode("utf-8"))
        self.prov = aul.filterNull(record.get('province', b'').decode("utf-8"))
        self.AS = aul.filterNull(record.get('asnumber', b'').decode("utf-8"))
        self.couCode = aul.filterNull(record.get('areacode', b'').decode("utf-8"))
        self.cou = aul.filterNull(record.get('country', b'').decode("utf-8"))
        self.FindTime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())


# 与go之间的通信

class RequestServe(analyze_pb2_grpc.GrpcServiceServicer):
    graph_conn = ""

    def AnalyzeService(self, request, context):
        '''
        具体实现AnalyzeService服务方法
        :param request:
        :param context:
        :return:
        '''
        r = request
        if r.gtype == "neo4j":
            if self.graph_conn == "":
                url = str(r.guri).split("//")[0] + "//" + r.guser + ":" + r.gpass + "@" + str(r.guri).split("//")[1]
                self.graph_conn = neo4j_connector(url)
                print("已连接到图数据库Neo4j:" + r.guri)
            result = self.graph_conn.work_with_neoj_53(r.data)
            return analyze_pb2.result(res=result)
        return analyze_pb2.result(res="not support")


working_addr = "127.0.0.1"
working_port = "56789"


def serve():
    # 启动 rpc 服务，这里可定义最大接收和发送大小(单位M)，默认只有4M
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=[
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024)])

    analyze_pb2_grpc.add_GrpcServiceServicer_to_server(RequestServe(), server)
    server.add_insecure_port(working_addr + ":" + working_port)
    server.start()
    print("Python分析模块启动，工作在 " + working_addr + ":" + working_port)
    try:
        while True:
            time.sleep(60 * 60 * 24)  # one day in seconds
    except KeyboardInterrupt:
        server.stop(0)


class RelResolver53(StructuredRel):
    w = IntegerProperty()


class NodeResolver53(StructuredNode):
    IP = StringProperty(required=True, unique_index=True)
    AS = StringProperty()
    ISP = StringProperty()
    COU = StringProperty()
    CCODE = StringProperty()
    PROV = StringProperty()
    LAT = StringProperty()
    LNG = StringProperty()
    IPType = StringProperty()
    FTIME = DateTimeFormatProperty(format="%Y-%m-%d %H:%M:%S")
    LTIME = DateTimeFormatProperty(default_now=True, format="%Y-%m-%d %H:%M:%S")
    LINK = RelationshipTo("NodeResolver53", "IP_LINK", model=RelResolver53)


class neo4j_connector:
    graph = ""

    # nodematcher = ""
    # relatmatcher = ""

    def __init__(self, url):
        # 连接neo4j
        db.set_connection(url)
        # self.graph = Graph(guri, auth=(guser, gpass), name="neo4j")
        # self.nodematcher = NodeMatcher(self.graph)
        # self.relatmatcher = RelationshipMatcher(self.graph)

    def work_with_neoj_53(self, data):
        nodes = []
        relates = []
        for d in data:
            n = node(d)
            # 查询是否存在节点
            n, exist = self.checknode_neo4j(n.ip)
            # 不存在则新建
            if not exist:
                NodeResolver53(AS=n.AS, COU=n.cou,
                               CCODE=n.couCode, LAT=n.lat, LNG=n.lng,
                               ISP=n.isp, IPtype=aul.IP46(n.ip), PROV=n.prov, FTIME=n.FindTime,
                               LTIME=n.FindTime, IP=n.ip, W=1).save()
            # 存在则只修改时间
            else:
                n.LTIME = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
                n.W += 1
                n.save()

        for i in range(len(data) - 1):
            # 查询是否存在关系
            L, l = self.checklink_neo4j(nodes[i], nodes[i + 1])
            if l == 0:
                pass
                # relates.append(
                #     Relationship(nodes[i], 'IP_link', nodes[i + 1], TIME=time.time(), LTIME=time.time(), W=1))
            else:
                L["W"] += 1
                L["LTIME"] = time.time()
                relates.append(L)
        # 提交链接
        return "success"

    def checknode_neo4j(self, ip):
        a = NodeResolver53.nodes.get_or_none(IP=ip)
        if a is not None:
            return a, True
        return None, False

    def checklink_neo4j(self, ip_from, ip_to):
        f = NodeResolver53.nodes.get_or_none(IP=ip_from)
        t = NodeResolver53.nodes.get_or_none(IP=ip_to)
        rel = f.LINK.relationship(t)
        if f is not None:
            return rel, True
        return None, False


if __name__ == '__main__':
    serve()
