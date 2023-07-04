import datetime
import logging

from py2neo import Graph, Node, Relationship, Subgraph
from py2neo import NodeMatcher, RelationshipMatcher
from concurrent import futures
import grpc
import time
import analyze_pb2
import analyze_pb2_grpc
import analyzedutil as aul


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
        self.FindTime = time.time()


# 与go之间的通信

class RequestServe(analyze_pb2_grpc.GrpcServiceServicer):
    graph_conn = ""

    def __init__(self):
        self.graph_conn = neo4j_connector()

    def AnalyzeService(self, request, context):
        '''
        具体实现AnalyzeService服务方法
        :param request:
        :param context:
        :return:
        '''
        r = request
        if r.gtype == "neo4j":
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
    logging.info("Python分析模块启动，工作在 "+working_addr + ":" + working_port)
    try:
        while True:
            time.sleep(60 * 60 * 24)  # one day in seconds
    except KeyboardInterrupt:
        server.stop(0)


class neo4j_connector:
    graph = ""
    nodematcher = ""
    relatmatcher = ""

    def __int__(self, guri, guser, gpass):
        # 连接neo4j
        self.graph = Graph(guri, auth=(guser, gpass), name="neo4j")
        self.nodematcher = NodeMatcher(self.graph)
        self.relatmatcher = RelationshipMatcher(self.graph)

    def work_with_neoj_53(self, data):
        nodes = []
        relates = []
        for d in data:
            n = node(d)
            # 查询是否存在节点
            N, l = self.checknode_neo4j(n.ip)
            if l == 0:
                nd = Node(label="ResolverFromDo53", AS=n.AS, COU=n.cou,
                          CODE=n.couCode, LAT=n.lat, LNG=n.lng,
                          ISP=n.isp, IPtype=aul.IP46(n.ip), PROVINCE=n.prov, TIME=n.FindTime, LTIME=n.FindTime, IP=n.ip,
                          W=1)
                nodes.append(nd)
            else:
                N["LTIME"] = time.time()
                N["W"] += 1
                nodes.append(N)
        if len(data) < 2:
            sub = Subgraph(nodes)
        else:
            for i in range(len(data) - 1):
                # 查询是否存在关系
                L, l = self.checklink_neo4j(nodes[i], nodes[i + 1])
                if l == 0:
                    relates.append(
                        Relationship(nodes[i], 'IP_link', nodes[i + 1], TIME=time.time(), LTIME=time.time(), W=1))
                else:
                    L["W"] += 1
                    L["LTIME"] = time.time()
                    relates.append(L)
            sub = Subgraph(nodes, relates)
        self.graph.create(subgraph=sub)
        return "success"

    def checknode_neo4j(self, ip):
        a = self.nodematcher.match("ResolverFromDo53", IP=ip).first()
        return a, len(a)

    def checklink_neo4j(self, ip_from, ip_to):
        a = self.relatmatcher.match({ip_from, ip_to}).first()
        return a, len(a)


if __name__ == '__main__':
    serve()
