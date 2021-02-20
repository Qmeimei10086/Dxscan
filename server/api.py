from flask import Flask, request
import json
import time
import threading
import time
import os
app = Flask(__name__)
import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)
server_api_cdn_dict = {"cdn":"no"}
server_api_whois_dict = {"whois":"None"}
server_api_fingerprint_dict = {}
server_api_os_dict = {"system":"Linux"}
server_api_port_list = []
server_api_subdomain_list = []
server_api_dir_dict = {"dir":[]}
server_api_waf_dict = {"waf":'NOwaf'}
server_api_jsparse_data = []
server_api_vuln_cms = []
server_api_vuln_system = []
server_api_sql_list = []
server_api_target_list = {}

@app.route("/cdn",methods=["POST"])
def server_api_hascdn():
    # 默认返回内容
    global server_api_cdn_dict
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    get_data = json.loads(get_data)  
    server_api_cdn = get_data.get('cdn')
    server_api_cdn_dict["cdn"] = server_api_cdn
    #print(server_api_cdn_dict)
    return json.dumps(server_api_cdn_dict, ensure_ascii=False)


@app.route("/whois",methods=["POST"])
def server_api_whois():
    # 默认返回内容
    global server_api_whois_dict
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    get_data = json.loads(get_data)  
    server_api_whois = get_data.get('whois')
    server_api_whois_dict["whois"] = server_api_whois
    #print(server_api_whois_dict)
    return json.dumps(server_api_whois_dict, ensure_ascii=False)

@app.route("/finger",methods=["POST"])
def server_api_fingerprint():
    global server_api_fingerprint_dict
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_fingerprint_dict = json.loads(get_data)  
    #print(server_api_fingerprint_dict)
    return json.dumps(server_api_fingerprint_dict, ensure_ascii=False)

@app.route("/os",methods=["POST"])
def server_api_os():
    global server_api_os_dict
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_os_dict = json.loads(get_data)  
    #print(server_api_os_dict)
    return json.dumps(server_api_os_dict, ensure_ascii=False)


@app.route("/port",methods=["POST"])
def server_api_port():
    global server_api_port_list
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_port_list.append(json.loads(get_data))
    #print(server_api_port_list)
    return json.dumps(json.loads(get_data), ensure_ascii=False)

@app.route("/dir",methods=["POST"])
def server_api_dir():
    global server_api_dir_dict
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_dir_dict = json.loads(get_data)  
    #print(server_api_dir_dict)
    return json.dumps(json.loads(get_data) , ensure_ascii=False)


@app.route("/subdomain",methods=["POST"])
def server_api_subdomain():
    global server_api_subdomain_list
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_subdomain_list.append(json.loads(get_data))
    #print(server_api_subdomain_list)
    return json.dumps(json.loads(get_data), ensure_ascii=False)


@app.route("/waf",methods=["POST"])
def server_api_waf():
    # 默认返回内容
    global server_api_waf_dict
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_waf_dict = json.loads(get_data)  
    #print(server_api_waf_dict)
    return json.dumps(server_api_waf_dict, ensure_ascii=False)


@app.route("/js",methods=["POST"])
def server_api_jsparse():
    global server_api_jsparse_data
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    if json.loads(get_data) not in server_api_jsparse_data:
        server_api_jsparse_data.append(json.loads(get_data))
    #print(server_api_jsparse_data)
    return json.dumps(json.loads(get_data), ensure_ascii=False)


@app.route("/cms",methods=["POST"])
def server_api_vuln_cms_test():
    global server_api_vuln_cms
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_vuln_cms.append(json.loads(get_data))
    #print(server_api_vuln_cms)
    return json.dumps(json.loads(get_data), ensure_ascii=False)



@app.route("/system",methods=["POST"])
def server_api_vulns_system():
    global server_api_vuln_system
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_vuln_system.append(json.loads(get_data))
    #print(server_api_vuln_system)
    return json.dumps(json.loads(get_data), ensure_ascii=False)

@app.route("/sql",methods=["POST"])
def server_api_sql_fuzz():
    global server_api_sql_list
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
    
    get_data = request.get_data()
    server_api_sql_list.append(json.loads(get_data))
    #print(server_api_sql_list)
    return json.dumps(json.loads(get_data), ensure_ascii=False)


@app.route("/report",methods=["POST"])
def server_api_report():
    return_dict = {'statusCode': '200', 'message': 'successful!', 'result': False}
    if request.get_data() is None:
        return_dict['statusCode'] = '5004'
        return_dict['message'] = '请求参数为空'
        return json.dumps(return_dict, ensure_ascii=False)
 
    get_data = request.get_data()
    server_api_target_list = json.loads(get_data)  
    
    
    text = "***********************************LOG**********************************************" +'\n'
    text += str(time.asctime(time.localtime(time.time())))
    text += "\n"
    text += "\n"
    text += "target : "+server_api_target_list["target"]
    text += "\n"
    text += "CDN情况: " + server_api_cdn_dict["cdn"] + '\n'
    text += "waf情况: "+ server_api_waf_dict["waf"] + '\n'
    text += "系统:" + server_api_os_dict["system"]
    text += "\n"
    text += "************************************whois信息**************************************"+ '\n'
    text += server_api_whois_dict["whois"]+ '\n'
    text += "**********************************************************************************"+ '\n'
    text += "\n"
    text += "*************************************指纹信息************************************"+ '\n'
    for i in server_api_fingerprint_dict.keys():
        text += str(i) + "    ==>   " + str(server_api_fingerprint_dict[i])+ '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"
    text += "************************************子域名*************************************" + '\n'
    for i in server_api_subdomain_list:
        for b in i.keys():
            text += b + "     ==>     " + i[b]+ '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"
    text += "**********************************敏感目录**************************************"+ '\n'
    for p in server_api_dir_dict["dir"]:
        text += p+ '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"
    text += "**********************************端口列表**************************************"+ '\n'
    for i in server_api_port_list:
        for b in i.keys():
            text += b + "         " + i[b]+ '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"
    text += "**********************************js敏感信息泄露********************************"+ '\n'
    for i in server_api_jsparse_data:
        for b in i.keys():
            text += i[b] + "         " + b + '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"  
    text += "**********************************sql_fuzz**************************************"+ '\n'
    for i in server_api_sql_list:
        for b in i.keys():
            text += b + "         " + i[b]+ '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"  
    text += "**********************************系统漏洞*************************************"+ '\n'
    for i in server_api_vuln_system:
        for b in i.keys():
            text += b + "         " + i[b]+ '\n'
    text += "*******************************************************************************"+ '\n'
    text += "\n"  
    text += "**********************************cms漏洞*************************************"+ '\n'
    for i in server_api_vuln_cms:
        for b in i.keys():
            text += b + "         " + i[b]+ '\n'
    
    text += "********************************************************************************"+ '\n'
    text += "\n" 
    localtimes = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()).replace(":","-")
    os.makedirs("report/"+localtimes)
    with open("report/"+localtimes+"/output.txt",'w') as f:
        f.write(text)
    
    output_json_fingerprint_dict = {}
    for i in server_api_fingerprint_dict.keys():
        output_json_fingerprint_dict[str(i)] = str(server_api_fingerprint_dict[i])
    
    output_json_subdomain_dict = {}
    for i in server_api_subdomain_list:
        for b in i.keys():
            output_json_subdomain_dict[b] = i[b]
    
    output_json_port_dict = {}
    for i in server_api_port_list:
        for b in i.keys():
            output_json_port_dict[b] = i[b]
    
    output_json_dir_list = []
    for p in server_api_dir_dict["dir"]:
        output_json_dir_list.append(p)
    
    output_json_jsparse_dict = {}
    for i in server_api_jsparse_data:
        for b in i.keys():
            output_json_jsparse_dict[i[b]] = b
    
    output_json_sqlfuzz_dict = {}
    for i in server_api_sql_list:
        for b in i.keys():
            output_json_sqlfuzz_dict[i[b]] = b
    
    output_json_systemvuln_dict = {}
    for i in server_api_vuln_system:
        for b in i.keys():
            output_json_sqlfuzz_dict[i[b]] = b
    
    output_json_cmsvuln_dict = {}
    for i in server_api_vuln_cms:
        for b in i.keys():
            output_json_cmsvuln_dict[i[b]] = b
    
    output_json = {
        'time':str(time.asctime(time.localtime(time.time()))),
        'information' : {
            'target' : server_api_target_list["target"],
            "cdn" : server_api_cdn_dict["cdn"],
            "waf" : server_api_waf_dict["waf"],
            "system" : server_api_os_dict["system"],
            "whois" : server_api_whois_dict["whois"].replace("\r\n",';'),
            'fingerprint' : output_json_fingerprint_dict,
        },
        'sensitive':{
            'subdomain' : output_json_subdomain_dict,
            'port' : output_json_port_dict,
            "dir" : output_json_dir_list,
            'jsparse' : output_json_jsparse_dict,
            'sql_fuzz' : output_json_sqlfuzz_dict,
        },
        'vuln':{
            "service_vuln" : output_json_systemvuln_dict,
            "cms_vuln" : output_json_cmsvuln_dict,
        },
    }
    
    json_str = json.dumps(output_json, indent=4)
    with open("report/"+localtimes+"/data.json", 'w') as json_file:
        json_file.write(json_str)
    
    
    print(text)
    return text

if __name__ == "__main__":
    app.run(port=8848)

