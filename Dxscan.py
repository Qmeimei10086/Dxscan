from printf import*
banner = """
______                          
|  _  \                            
| | | |_  _____  ___ __ _ _ __  
| | | \ \/ / __|/ __/ _` | '_ \ 
| |/ / >  <\__ \ (_| (_| | | | |
|___/ /_/\_\___/\___\__,_|_| |_|
                                Dxscan {div0.1}     

"""
init(autoreset=True)
printf(banner,"yellow")
import re
from script.script_osscan import*
from script.script_whois import*
from script.script_findsubdomain import*
from script.script_portscan import*
from script.script_fingerprint import*
from script.script_dir_scan import*
from script.script_jsparse import*
from script.script_cdn import*
from script.script_check_waf import*
from sql_fuzz.class_fuzzer import Fuzzer
from script_cms_scan import*
from script_cms_scan_all import*
from script_system_scan import*
from script_postdata import postdata_sql
import argparse
import socket
import colorama
from colorama import init,Fore,Back,Style
import platform
from bs4 import BeautifulSoup
import threading
import requests
import os
import sys
import time
from automatic import*
js_list_main = []

def start_js(url):
    global js_list_main
    try:
        jsparse = JsParse(url).jsparse()
        for js in jsparse:
            text = "[jsparse] " + str(js)
            
            js_list_main.append(text + " -- " + url) 
    except Exception as e:
        print(e)
def re_find_url(html,url,target):
    tag = re.findall(r'<a href="([a-zA-z]+://[^\s]*)"', str(html))
    url_lists = []
    lists = []
    urls = []
    returns = []
    #url_list = []
    num = 0
    for i in tag:
        if i[:4] != 'http' and target in i:
            i = "http:"+i
        if i[0] == '/'  and "http" not in i and target not in i:
            i = "http://" + target +i
        if i not in url_lists:
            if url in i:
                url_lists.append(i)

    soup = BeautifulSoup(html,'html.parser')
    for a in soup.find_all('a',href=True):   
        href = a['href']
        if href[:4] != 'http' and target in href:
            href = "http:"+href
        if href[0] == '/'  and "http" not in href and target not in href:
            href = "http://" + target +href
        lists.append(href)

    for i in lists:
        if i not in url_lists:
            if target in i:
                url_lists.append(i)
    url_lists = list(set(url_lists))
    for i in url_lists:
        if target in i:
            urls.append(i)

    for i in urls:
        returns.append(i)
        if num > 101:
            break
        num +=1
    return returns
def judge_legal_ip(ip):
    compile_ip=re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$') 
    if compile_ip.match(ip): 
        return True
    else: 
        return False
def isIP(target):
    try:
        if judge_legal_ip(target):
            pass
        if ":" in target:
            host = target.split(':')[0]
            port = target.split(':')[1]
            if judge_legal_ip(host) and int(port):
                pass
            else:
                host = target.split(':')[0]
                port = target.split(':')[1]
                int(port)
                socket.gethostbyname(host)
        else:
            socket.gethostbyname(target)
        return True
    
    except:
        text = '[-]'+target+" 不是域名或IP"
        printf(text,"red")
        return False
threading.Thread(target=os.system, args=(sys.executable+" server\\api.py",)).start()
time.sleep(3)
#--------------------------------------------------
def main_os_scan(target):
    methods = input('是否使用nmap进行扫描操作系统(需要安装nmap)[y/n]')
    if methods == "y" or methods == "":
        if judge_legal_ip(target):
            os_name = script_osscan_nmap_scan(target)
        else:
            try:
                rhost =socket.gethostbyname(target)
                text = "[+]"+target+" ==> "+rhost
                printf(text,"green")
                os_name = script_osscan_nmap_scan(rhost)
            except:
                text = '[-]'+target+" 不是域名或者IP"
                printf(text,"red")
        output = "[OS-SCAN] "+ target + " ==> " +str(os_name)
        printf(output,"yellow")  
        
    elif methods == "n":
        if judge_legal_ip(target):
            os_name = script_osscan_ttl_scan(target)
        else:
            try:
                rhost =socket.gethostbyname(target)
                text = "[+]"+target+" ==> "+rhost
                printf(text,"green")
                os_name = script_osscan_ttl_scan(rhost)
                output = "[OS-SCAN] "+ target + " ==> " +str(os_name)
                printf(output,"yellow") 
            except:
                text = '[-]'+target+" 不是域名或者IP"
                printf(text,"red")
    else:
        text = "[-]没有"+"' "+methods+" '"+'这个选项'
        printf(text,"red")
#--------------------------------------------------
def main_whois(target):
    if isIP(target):
        try:     
            whoispresa = script_whois_whois(target)
            printf("+---------------------------------------whois信息----------------------------------------","white")
            printf(whoispresa,"yellow")
            printf("+---------------------------------------whois信息-----------------------------------------","white")
        except:
            text = '[-]'+target+" 连接失败"
            printf(text,"red")
#-------------------------------------------------
def main_findsubdomain(target):
    if isIP(target):
        subdomain = script_findsubdomain_findsubdomain(target)
        printf("+--------------------------------子域名列表-----------------------------","white")
        for i in subdomain:
            printf(i,'yellow')
        printf("+------------------------------------------------------------------","white")
        choose = input("是否将子域名解析为IP[y/n]")
        
        if choose == "y" or choose == "":
            printf("+--------------------------------解析结果-----------------------------","white")
            for i in subdomain:
                rhost =socket.gethostbyname(i)
                text = i+" ==> " + rhost
                printf(text,"pink")
                subdomain_data = {i:rhost}
                requests.post('http://localhost:8848/subdomain', json=subdomain_data)

            printf("+-----------------------------------------------------------------","white")
        
        elif choose == "n":
            for i in subdomain:
                subdomain_data = {i:"None"}
                requests.post('http://localhost:8848/subdomain', json=subdomain_data)
        else:
            text = "[-]没有"+"' "+choose+" '"+'这个选项'
            printf(text,"red")
#-------------------------------------------------
def main_portscan(target):
    if isIP(target):
        if ":" in target:
            host = target.split(":")[0]
            port  = target.split(":")[1]
            if judge_legal_ip and type(int(port)) == int:
                port_list = scrpit_portscan_port_scan(host)
            else:
                rhost =socket.gethostbyname(host)
                text = "[+]"+target+" ==> "+rhost
                printf(text,"yellow")
                port_list = scrpit_portscan_port_scan(rhost)
        if judge_legal_ip(target):
            port_list = scrpit_portscan_port_scan(target)
        else:
            rhost =socket.gethostbyname(target)
            text = "[+]"+target+" ==> "+rhost
            printf(text,"yellow")
            port_list = scrpit_portscan_port_scan(rhost)
    printf("+--------------------------------端口列表-----------------------------","white")
    for p in port_list:
        if str(p) in service:
            text = str(p)+"       " + service[str(p)]
            post_dict = {str(p):service[str(p)]}
            printf(text,"yellow")
            requests.post('http://localhost:8848/port', json=post_dict)
            
        else:
            text = str(p)+"       " + "UNKNOW"
            post_dict = {str(p):"UNKNOW"}
            printf(text,"yellow")
            requests.post('http://localhost:8848/port', json=post_dict)
    printf("+-----------------------------------------------------------------","white")
#-------------------------------------------------
def main_fingerprint(target):
    if isIP(target):
        printf("+--------------------------------指纹识别-----------------------------","white")
        url = target
        data = script_fingerprint_web_fingerprint(url)
        if 'Web Frameworks' in data.keys():
            text = "[fingerprint] "+"网站框架 ==> "+str(data['Web Frameworks'])
            printf(text,"yellow")
        if 'Web Servers' in data.keys():
            text = "[fingerprint] "+"网站中间件 ==> "+str(data['Web Servers'])
            printf(text,"yellow")
        if 'JavaScript Frameworks' in data.keys():
            text = "[fingerprint] "+"JS框架 ==> "+str(data['JavaScript Frameworks'])
            printf(text,"yellow")
        if 'CMS' in data.keys():
            text = "[fingerprint] "+"CMS框架 ==> "+str(data['CMS'])
            printf(text,"yellow")
        if 'Programming Languages' in data.keys():
            text = "[fingerprint] "+"网站语言 ==> "+str(data['Programming Languages'])
            printf(text,"yellow")
        if 'Waf' in data.keys(): 
            text = "[fingerprint] "+"网站WAF ==> "+str(data['Waf'])
            printf(text,"yellow")
        if 'Operating Systems' in data.keys():
            text = "[fingerprint] "+"服务器系统 ==> "+str(data['Operating Systems'])
            printf(text,"yellow")
        printf("+------------------------------------------------------------------","white")
        printf("感谢http://whatweb.bugscaner.com/ 提供的数据","white")
#-------------------------------------------------
def main_dir_scan(target):
    if isIP(target):
        printf("+--------------------------------目录爆破-----------------------------","white")
        url = "http://"+target
        printf("1.php敏感目录  2.asp敏感目录  3.aspx敏感目录  4.jsp敏感目录  5.网站备份  6.网站后台  7.常用敏感目录",'white')
        types = int(input("请选择扫描类型(数字):"))
        if types == 1:
            types = 'php'
        elif types == 2:
            types = "asp"
        elif types == 3:
            types = 'aspx'
        elif types == 4:
            types = 'jsp'
        elif types == 5:
            types = "beifeng"
        elif types == 6:
            types = 'admin'
        elif types == 7:
            types = 'often'
        else:
            text = "[-]没有"+"' "+str(types)+" '"+'这个选项'
            printf(text,"red")
            #sys.exit(0)
        other = input("请输入网站响应中存在哪段文字为错误(没有请回车):")
        if other == "":
            other = "UHEWIUDHJSQUIDHWJ@*&@Y^&YQHJ*(D!IO)(E@XKJU@IND@*YDGHUIQJkjd(K"
        script_dir_scan_dir_scan(url,other,types)
        printf("+------------------------------------------------------------------","white")
#-------------------------------------------------
def main_jsparse(target):
    threads_1 = []
    header = {'User-Agent':'Mozilla/5.0'}
    if isIP(target):
        urls_1 = []
        printf("+--------------------------------js敏感信息泄露-----------------------------","white")
        url = "http://"+target
        url_list.append(url)
        while True:
            tlurl = input("请添加除主站外的其他路径,例如/p/index.html,没有请输入'n'或直接回车:")
            if tlurl == 'n' or tlurl == '':
                break
            tes = url+tlurl
            urls_1.append(tes)
        if urls_1 != []:
            for i in urls_1:
                html = requests.get(url,headers=header).text
                url_lists = re_find_url(html,url,target)
                for i in list(set(url_lists)):
                    url_list.append(i)
                
        html = requests.get(url,headers=header).text
        url_lists = re_find_url(html,url,target)
        url_list = list(set(url_lists))
        for i in url_list:
            t = threading.Thread(target=start_js, args=(i,))
            threads_1.append(t)
        for i in range(len(threads_1)):
            threads_1[i].start()
        for i in range(len(threads_1)):
            threads_1[i].join()
        for i in js_list_main:
            if "127.0.0.1" not in i and target != "127.0.0.1":
                output = i
                js_data = output[10:].split(" -- ")
                js_dict = {js_data[0]:js_data[1]}
                requests.post('http://localhost:8848/js', json=js_dict)
                printf(output,"yellow")

        printf("+------------------------------------------------------------------","white")
#-------------------------------------------------
def main_cms_scan(target):
    if isIP(target):
        printf("+--------------------------------cms漏洞扫描-----------------------------","white")
        url = "http://"+target
        script_cms_scan_run(url)
        script_cms_scan_all_find_cms(url)
        printf("+------------------------------------------------------------------","white")
        printf("感谢https://github.com/1oid/cms_poc_exp提供的poc","white")
#-------------------------------------------------
def main_check_cdn(target):
    if isIP(target):
        script_cdn_iscdn(target)
#-------------------------------------------------
def main_sql_fuzz(target):
    if isIP(target):
        header = {'User-Agent':'Mozilla/5.0'}
        printf("+--------------------------------sql注入模糊测试-----------------------------","white")
        printf("[!]这是模糊测试,别想着什么一键getshell",'red')
        url = "http://"+target+"/?id=1"
        url_list = []
        if postdata_sql == {}:
            while True:
                tlurl = input("请添加除了主站外带参数的URL,例如http://explamp.com/pwd=123,没有请输入'n'或直接回车:")
                if tlurl == 'n' or tlurl == '':
                    break
                url_list.append(tlurl)
                url_list.append(url)
            for url in url_list:
                output = "[sql_fuzz] [INFO]测试url ==> "+url
                printf(output,"blue")
                Fuzzer(url=url,headers=header).fuzz_sql(method='g',threshold=20)
        else:
            printf("检测到postdata_sql中有内容,是否进行post注入测试[y/n]","white")
            bools = input('请选择>')
            if bools == "y" or bools == "":
                printf("[INFO]进行post注入",'blue')
                url = input("请输入要测试的url:")
                output = "[INFO] [sql_fuzz] URL ==> "+url
                printf(output,'yellow')
                Fuzzer(url=url,headers=header).fuzz_sql(method='p',postdata=postdata_sql,threshold=20)
            elif bools == "n":
                while True:
                    tlurl = input("请添加除了主站外带参数的URL,例如http://explamp.com/pwd=123,没有请输入'n'或直接回车:")
                    if tlurl == 'n' or tlurl == '':
                        break
                    url_list.append(tlurl)
                for url in url_list:
                    output = "[sql_fuzz] [INFO]测试url ==> "+url
                    printf(output,"blue")
                    Fuzzer(url=url,headers=header).fuzz_sql(method='g',threshold=20)
            else:
                text = "[-]没有"+"' "+bools+" '"+'这个选项'
                printf(text,"red")
        printf("+--------------------------------sql注入模糊测试-----------------------------","white")
        printf("感谢https://github.com/ser4wang/Ares-Fuzzer/提供的脚本","white")
#-------------------------------------------------
def main_check_waf(target):
    if isIP(target):
        url = "http://"+target
        waf = script_check_waf_checkwaf(url)
        if waf == "NoWAF" or waf == None:
            output = "[check_waf]这个网站可能没有WAF" 
            waf_data = {"waf":"NOwaf"}
            printf(output,"green")
        else:
            output = "[check_waf]这个网站使用了waf "  +url +" ==> "+waf
            waf_data = {"waf":waf}
            printf(output,"yellow")
        requests.post('http://localhost:8848/waf', json=waf_data)
        printf("参考脚本https://github.com/al0ne/Vxscan",'white')
#-------------------------------------------------
def main_system_scan(target):
    if isIP(target):
        printf("+--------------------------------系统漏洞扫描-----------------------------","white")
        url = "http://"+target
        script_system_scan_system(url)
        printf("+------------------------------------------------------------------","white")
        printf("感谢https://github.com/Lucifer1993/AngelSword/提供的poc","white")
#-------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Dxscan {#div v0.1}")
    parser.add_argument('-O','--osscan', action='store_true')
    parser.add_argument('-t','--target',required=True)
    parser.add_argument('-whois', action='store_true')
    parser.add_argument('-F',"--findsubdomain",action='store_true')
    parser.add_argument('-P','--portscan', action='store_true')
    parser.add_argument('-V','--server', action='store_true')
    parser.add_argument('-D','--dirscan', action='store_true')
    parser.add_argument('-J','--jsparse', action='store_true')
    parser.add_argument('-C','--cmsscan', action='store_true')
    parser.add_argument('-S','--systemscan', action='store_true')
    parser.add_argument('-I','--iscdn', action='store_true')
    parser.add_argument('-Q','--sql_injection', action='store_true')
    parser.add_argument('-A','--check_waf', action='store_true')
    parser.add_argument('-W','--automatic', action='store_true')
    args = parser.parse_args()
    target = args.target
    action_val_os = args.osscan
    action_val_whois = args.whois
    action_val_findsubdomain = args.findsubdomain
    action_val_portscan = args.portscan
    action_val_fingerprint = args.server
    action_val_dirscan = args.dirscan
    action_val_jsparse = args.jsparse
    action_val_cmsscan = args.cmsscan
    action_val_systemscan = args.systemscan
    action_val_iscdn = args.iscdn
    action_val_sql_injection = args.sql_injection
    action_val_check_waf = args.check_waf
    action_val_automatic = args.automatic
    
    if action_val_os:
        main_os_scan(target)
    if action_val_whois:
        main_whois(target)
    if action_val_findsubdomain:
        main_findsubdomain(target)
    if action_val_portscan:
        main_portscan(target)
    if action_val_fingerprint:
        main_fingerprint(target)
    if action_val_dirscan:
        main_dir_scan(target)
    if action_val_jsparse:
        main_jsparse(target)
    if action_val_cmsscan:
        main_cms_scan(target)
    if action_val_systemscan:
        main_system_scan(target)
    if action_val_iscdn:
        main_check_cdn(target)
    if action_val_sql_injection:
        main_sql_fuzz(target)
    if action_val_check_waf:
        main_check_waf(target)
    if action_val_automatic:
        try:
            start_automatic(target)
        except Exception as e:
            print(e)
        
    os._exit()
if __name__ == "__main__":
    main()
    