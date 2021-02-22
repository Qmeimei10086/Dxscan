try:
    from printf import*
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
except Exception as e:
    print(e)
init(autoreset=True)
js_list_main = []
def automatic_start_js(url):
    global js_list_main
    try:
        jsparse = JsParse(url).jsparse()
        for js in jsparse:
            text = "[jsparse] " + str(js)
            
            js_list_main.append(text + " -- " + url) 
    except Exception as e:
        print(e)
def automatic_re_find_url(html,url,target):
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
    #print(returns)
    return returns
def automatic_judge_legal_ip(ip):
    compile_ip=re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$') 
    if compile_ip.match(ip): 
        return True
    else: 
        return False
def automatic_isIP(target):
    try:
        if automatic_judge_legal_ip(target):
            pass
        if ":" in target:
            host = target.split(':')[0]
            port = target.split(':')[1]
            if automatic_judge_legal_ip(host) and int(port):
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
def automatic_os_scan(target,methods):
    if methods == "y" or methods == "":
        if automatic_judge_legal_ip(target):
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
        if automatic_judge_legal_ip(target):
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
def automatic_whois(target):
    try:     
        whoispresa = script_whois_whois(target)
        printf("+---------------------------------------whois信息----------------------------------------","white")
        printf(whoispresa,"yellow")
        printf("+---------------------------------------whois信息-----------------------------------------","white")
    except:
        text = '[-]'+target+" 连接失败"
        printf(text,"red")
def automatic_findsubdomain(target,choose):
    subdomain = script_findsubdomain_findsubdomain(target)
    printf("+--------------------------------子域名列表-----------------------------","white")
    for i in subdomain:
        printf(i,'yellow')
    printf("+------------------------------------------------------------------","white")
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
def automatic_portscan(target):
    if ":" in target:
        host = target.split(":")[0]
        port  = target.split(":")[1]
        if automatic_judge_legal_ip and type(int(port)) == int:
            port_list = scrpit_portscan_port_scan(host)
        else:
            rhost =socket.gethostbyname(host)
            text = "[+]"+target+" ==> "+rhost
            printf(text,"yellow")
            port_list = scrpit_portscan_port_scan(rhost)
    if automatic_judge_legal_ip(target):
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
def automatic_fingerprint(target):
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
def automatic_dir_scan(target,types,other):
    printf("+--------------------------------目录爆破-----------------------------","white")
    url = "http://"+target
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
    if other == "":
        other = "UHEWIUDHJSQUIDHWJ@*&@Y^&YQHJ*(D!IO)(E@XKJU@IND@*YDGHUIQJkjd(K"
    script_dir_scan_dir_scan(url,other,types)
    printf("+------------------------------------------------------------------","white")
def automatic_jsparse(target,urls_1):
    threads_1 = []
    url_list = []
    header = {'User-Agent':'Mozilla/5.0'}
    printf("+--------------------------------js敏感信息泄露-----------------------------","white")
    url = "http://"+target
    url_list.append(url)
    if urls_1 != []:
        for i in urls_1:
            html = requests.get(url,headers=header).text
            url_lists = automatic_re_find_url(html,url,target)
            for i in list(set(url_lists)):
                url_list.append(i)
            
    html = requests.get(url,headers=header).text
    url_lists = automatic_re_find_url(html,url,target)
    url_list = list(set(url_lists))
    for i in url_list:
        t = threading.Thread(target=automatic_start_js, args=(i,))
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
def automatic_cms_scan(target):
    printf("+--------------------------------cms漏洞扫描-----------------------------","white")
    url = "http://"+target
    script_cms_scan_run(url)
    script_cms_scan_all_find_cms(url)
    printf("+------------------------------------------------------------------","white")
    printf("感谢https://github.com/1oid/cms_poc_exp提供的poc","white")
def automatic_check_cdn(target):
    script_cdn_iscdn(target)
def automatic_sql_fuzz(target,url_list,bools):
    header = {'User-Agent':'Mozilla/5.0'}
    printf("+--------------------------------sql注入模糊测试-----------------------------","white")
    printf("[!]这是模糊测试,别想着什么一键getshell",'red')
    url = "http://"+target+"/?id=1"
    
    if postdata_sql == {}:
        for url in url_list:
            output = "[sql_fuzz] [INFO]测试url ==> "+url
            printf(output,"blue")
            Fuzzer(url=url,headers=header).fuzz_sql(method='g',threshold=20)
    else:
        printf("检测到postdata_sql中有内容,是否进行post注入测试[y/n]","white")
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
def automatic_check_waf(target):
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

def start_automatic(target):
    if automatic_isIP(target):
        url_list_1 = []
        urls_1 = []
        bools = "n"
        output = "[automatic] 已启用自动化模式,请回答下列问题才可开始"
        printf(output,"yellow")
        methods = input('问题来自系统扫描 -- 是否使用nmap进行扫描操作系统(需要安装nmap)[y/n]')
        if methods != "y" and methods != "" and methods != "n":
            text = "[-]没有"+"' "+methods+" '"+'这个选项'
            printf(text,"red")
        choose = input("问题来自子域名爆破 -- 是否将子域名解析为IP[y/n]")
        if choose != "y" and choose != "" and choose != "n":
            text = "[-]没有"+"' "+methods+" '"+'这个选项'
            printf(text,"red")
        printf("1.php敏感目录  2.asp敏感目录  3.aspx敏感目录  4.jsp敏感目录  5.网站备份  6.网站后台  7.常用敏感目录",'white')
        types = int(input("问题来自目录爆破 -- 请选择扫描类型(数字):"))
        if types != 1 and types != 2 and types != 3 and types != 4 and types != 5 and types != 6 and types != 7:
            text = "[-]没有"+"' "+str(types)+" '"+'这个选项'
            printf(text,"red")
        other = input("问题来自目录爆破 -- 请输入网站响应中存在哪段文字为错误(没有请回车):")
        url = "http://"+target
        while True:
            tlurl = input("问题来自js敏感信息泄露 -- 请添加除主站外的其他路径,例如/p/index.html,没有请输入'n'或直接回车:")
            if tlurl == 'n' or tlurl == '':
                break
            tes = url+tlurl
            urls_1.append(tes)
        if postdata_sql == {}:
            #url = "http://"+target+"/?id=1"
            while True:
                tlurl = input("问题来自sql模糊测试 -- 请添加除了主站外带参数的URL,例如http://explamp.com/pwd=123,没有请输入'n'或直接回车:")
                if tlurl == 'n' or tlurl == '':
                    break
                url_list_1.append(tlurl)
            url_list_1.append("http://"+target+"/?id=1")
                
        else:
            printf("问题来自sql模糊测试 -- 检测到postdata中有内容,是否进行post注入测试[y/n]","white")
            bools = input('请选择>')
            if bools != "y" and choose != "" and choose != "n":
                text = "[-]没有"+"' "+methods+" '"+'这个选项'
                printf(text,"red")
        printf("[automatic] [+]问题回答完毕,开始扫描",'blue')
        printf("[automatic] [INFO]开始扫描系统版本",'blue')
        automatic_os_scan(target,methods)
        printf("[automatic] [INFO]开始扫描网站指纹信息",'blue')
        automatic_fingerprint(target)
        printf("[automatic] [INFO]开始收集网站子域名目录",'blue')
        automatic_findsubdomain(target,choose)
        printf("[automatic] [INFO]开始收集whois信息",'blue')
        automatic_whois(target)
        printf("[automatic] [INFO]开始扫描网站端口",'blue')
        automatic_portscan(target)
        printf("[automatic] [INFO]开始扫描网站CDN情况",'blue')
        automatic_check_cdn(target)
        printf("[automatic] [INFO]开始扫描网站WAF(网站防火墙)",'blue')
        automatic_check_waf(target)
        printf("[automatic] [INFO]开始寻找网站js敏感信息泄露",'blue')
        automatic_jsparse(target,urls_1)
        printf("[automatic] [INFO]开始扫描网站爆破网站目录",'blue')
        automatic_dir_scan(target,types,other)
        printf("[automatic] [+]信息收集完毕,开始大规模漏洞扫描!",'blue')
        printf("[automatic] [INFO]开始测试sql注入漏洞",'blue')
        automatic_sql_fuzz(target=target,url_list=url_list_1,bools=bools)
        printf("[automatic] [INFO]开始扫描cms漏洞",'blue')
        automatic_cms_scan(target)
        printf("[automatic] [+]扫描完毕,开始生成报告",'blue')
        poastdatas = {"target":target}
        requests.post('http://localhost:8848/report', json=poastdatas)
    else:
        text = '[-]'+target+" 不是域名或者IP"
        printf(text,"red")
