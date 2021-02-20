#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: redis 未授权漏洞
referer: unknown
author: Lucifer
description: redis无用户名密码可直接远程操纵。
'''
import sys
import redis
import warnings
from termcolor import cprint
from urllib.parse import urlparse
import requests
class redis_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 6379
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
            r = redis.Redis(host, port=port, db=0, socket_timeout=6.0)
            if r.ping() is True:
                cprint("[+]存在redis 未授权漏洞...(高危)\tpayload: "+host+":"+str(port), "red")
                postdata = {self.url:"存在redis 未授权漏洞...(高危)\tpayload: "+host+":"+str(port)}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在redis_unauth漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = redis_unauth_BaseVerify(sys.argv[1])
    testVuln.run()
