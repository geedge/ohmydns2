# analyzeutl 是分析器工具集合
import awdb


# 过滤所有空值
def filterNull(s):
    if s == "":
        return "UnKnown"
    return s


def IP46(IP: str):
    if ':' in IP:
        return "v6"
    if '.' in IP:
        return "v4"
    return "Unknown"


path_ip4app = "./data/IP_scene_all_cn.awdb"
path_ip6 = "./data/IP_city_single_BD09_WGS84_ipv6_en.awdb"
path_ip4qvxian = "./data/IP_basic_single_WGS84_en.awdb"


# 实例化数据读取器
def makereader(arg=0):
    # 默认加载所有离线数据
    dloader_ip4app = awdb.open_database(path_ip4app)
    dloader_ip6 = awdb.open_database(path_ip6)
    dloader_ip4qx = awdb.open_database(path_ip4qvxian)
    return dloader_ip4app, dloader_ip4qx, dloader_ip6


reader_ip4app, reader_ip4qx, reader_ip6 = makereader()


# # 传入一个ip地址，根据对象中的数据进行IP关联分析
# def make_IPinfo(ip):
#     record=getrecord(ip)
#     cou = record.get('areacode', b'').decode("utf-8")
#     multiarea = record.get('multiAreas', {})
#     if multiarea:
#         print("有多组记录")
#     else:
#         pass
#     return record

# 返回IP离线库中与ip相关的记录，记录中不包含应用场景
def getrecord(ip):
    if (IP46(ip) == "v4"):
        return IP4_info(ip)
    elif (IP46(ip) == "v6"):
        return IP6_info(ip)
    else:
        print("地址存在问题")
        print(ip)
        return 1


# 返回IPv4记录
def IP4_info(ip):
    (record, prefix_len) = reader_ip4qx.get_with_prefix_len(ip)
    return record


# 返回IPv6记录
def IP6_info(ip):
    (record, prefix_len) = reader_ip6.get_with_prefix_len(ip)
    return record
