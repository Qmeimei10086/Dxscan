import requests
import zlib
import json
import time
import datetime
def whatweb(url):
    requests.packages.urllib3.disable_warnings()
    response = requests.get(url,verify=False)
    whatweb_dict = {"url":response.url,"text":response.text,"headers":dict(response.headers)}
    whatweb_dict = json.dumps(whatweb_dict)
    whatweb_dict = whatweb_dict.encode()
    whatweb_dict = zlib.compress(whatweb_dict)
    data = {"info":whatweb_dict}
    return requests.post("http://whatweb.bugscaner.com/api.go",files=data,verify=False)

def webinfo(url):
    requests.packages.urllib3.disable_warnings()
    cookies = "Hm_lvt_6809c4d9953f5afcfe906ac76fa71351=1612618624,1612668732,1612808262,1612838964; sessionid=v6crlnaibmryk6kev8zhd6j5e24y76fc; clicaptcha_text=%E5%90%93%2C%E7%A9%86; Hm_lpvt_6809c4d9953f5afcfe906ac76fa71351="+ str(int(time.time()))
    header = {
    'Accept':'application/json, text/javascript, */*; q=0.01',
    'Accept-Encoding':'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Connection':'keep-alive',
    'Content-Length':'35',
    'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
    'Cookie':cookies,
    'Host':'whatweb.bugscaner.com',
    'Origin':'http://whatweb.bugscaner.com',
    'Referer':'http://whatweb.bugscaner.com/look/',
    'User-Agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36',
    'X-Requested-With':'XMLHttpRequest'
    }
    fromdata = {
    'url': url,
    'location_capcha': 'no'
    }
    response = requests.post("http://whatweb.bugscaner.com/what.go",headers=header,data=fromdata,verify=False)
    return response


def script_fingerprint_web_fingerprint(domain):
    url = "http://" + domain
    request = whatweb(url)
    if "error" in str(request.json()):
        request = webinfo(url)
    
    requests.post('http://localhost:8848/finger', json=request.json())
    return request.json()
    

