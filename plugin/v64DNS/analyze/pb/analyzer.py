# TODO:与图数据库交互
import datetime

from py2neo import Graph, Node, Relationship,Subgraph
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
    FindTime=""

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
        self.FindTime=time.time()






# 与go之间的通信

class RequestServe(analyze_pb2_grpc.GrpcServiceServicer):
    def __init__(self):
        pass

    def AnalyzeService(self, request, context):
        '''
        具体实现AnalyzeService服务方法
        :param request:
        :param context:
        :return:
        '''
        r = request
        if r.gtype == "neo4j":
            result = work_with_neoj(r.guri, r.guser, r.gpass, r.data)
            return analyze_pb2.result(res=result)
        return analyze_pb2.result(res="not support")


def serve():
    # 启动 rpc 服务，这里可定义最大接收和发送大小(单位M)，默认只有4M
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=[
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
        ('grpc.max_receive_message_length', 100 * 1024 * 1024)])

    analyze_pb2_grpc.add_GrpcServiceServicer_to_server(RequestServe(), server)
    server.add_insecure_port('127.0.0.1:56789')
    server.start()
    try:
        while True:
            time.sleep(60 * 60 * 24)  # one day in seconds
    except KeyboardInterrupt:
        server.stop(0)


# TODO：接受来自go的数据，对每个节点进行建模，并填充属性
def work_with_neoj_53(guri, guser, gpass, data):
    graph = Graph(guri, username=guser, password=gpass)
    nodes = []
    relates=[]
    for d in data:
        n = node(d)
        nd = Node(label="ResolverFromDo53", AS=n.AS, COU=n.cou,
                 CODE=n.couCode,LAT=n.lat, LNG=n.lng,
                 ISP=n.isp, IPtype=aul.IP46(n.ip),PROVINCE=n.prov,TIME=n.FindTime,IP=n.ip)
        nodes.append(nd)
    if len(data)<2:
        sub = Subgraph(nodes)
    else:
        for i in range(len(data)-1):
            relates.append(Relationship(nodes[i],'IP_link',nodes[i+1]))
        sub=Subgraph(nodes,relates)
    graph.create(subgraph=sub)




# TODO：与图数据库交互


if __name__ == '__main__':
    serve()
