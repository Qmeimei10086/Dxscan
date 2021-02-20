def load_vector(target_file):
    vectors = []
    with open( target_file, 'r', encoding="utf8") as file:
        for line in file:
            vectors.append( line.replace("\n",""))
    return vectors

def analyze_url(url):
    tmp = url.split("#")[0].split("?")
    base_url = tmp[0]
    if len(tmp) ==  2: # 正常情况下，比如有查询字符串
        query_list = tmp[1].split("&") # 获取查询字符串中的键值对
		# query_list = [ s.split("=") for s in query_string ]
    elif len(tmp) == 1: # 没有查询字符串的情况下
        query_list = []
    else:
        pass
    return base_url, query_list
	
	
def form_postdata(postdata):
    '''
    TODO: 将字典类型的postdata值转换成常规字符串类型
    输入: dict => {"key":"value","key2":"value2",...}
    输出: string => "key=value&key2=value2&..."
    '''
    r = []
    for kv in postdata.items():
        r.append( "=".join(kv) )
    return "&".join(r)
