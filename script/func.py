import os
import re
import sys
import requests
import colorama
from colorama import init,Fore,Back,Style
from printf import*
init(autoreset=True)

class fileOperation(object):

    def __init__(self):
        pass

    def exloitsFilesList(self):
        filename = os.getcwd() + '/Libs'
        fileList = os.listdir(filename)
        return filter(lambda x: (True, False)[x[-3:] == '.py' or x[0] == "."], fileList)

    def exploitScriptsList(self, filen):
        filename = "{}/Libs/{}".format(os.getcwd(), filen)
        fileList = os.listdir(filename)
        return filename, filter(lambda x: (True, False)[x[:2] == '__' or x[-3:] == 'pyc'], fileList)

    def executePlugin(self, expName, url):
        md = __import__(expName)
        try:
        # if True:
            if hasattr(md, 'Exploit'):
                exp = getattr(md, 'Exploit')()
                ret = exp.attack(url)
                if ret:
                    output = '[+] 发现漏洞 {}'.format(ret)
                    postdata = {url:ret}
                    requests.post('http://localhost:8848/cms', json=postdata)
                    printf(output,"green")
                else:
                    output = '[-]漏洞不存在'
                    printf(output,"white")
        #
        except requests.exceptions.MissingSchema as e:
            printf('[!] MissingScheme.',"red")

    def setpath(self, cmsfile):
        sys.path.append(cmsfile)

