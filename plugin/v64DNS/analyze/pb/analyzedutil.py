# analyzeutl 是分析器工具集合
def getrecord(ip):
    pass


# 过滤所有空值
def filterNull(s):
    if s == "":
        return "UnKnown"
    return s

def IP46(IP:str):
    if ':' in IP:
        return "v6"
    if '.' in IP:
        return "v4"
    return "Unknown"