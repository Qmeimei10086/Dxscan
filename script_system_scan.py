from system.systemmain import *
import colorama
from colorama import init,Fore,Back,Style
from printf import*

init(autoreset=True)

def script_system_scan_system(url):
    systempocdict = {
    "libssh身份绕过漏洞(CVE-2018-10933)":libssh_bypass_auth_BaseVerify(url),
    "ElasticSearch未授权漏洞":elasticsearch_unauth_BaseVerify(url),
    "CouchDB 未授权漏洞":couchdb_unauth_BaseVerify(url),
    "zookeeper 未授权漏洞":zookeeper_unauth_BaseVerify(url),
    "GoAhead LD_PRELOAD远程代码执行(CVE-2017-17562)":goahead_LD_PRELOAD_rce_BaseVerify(url),
    "天融信Topsec change_lan.php本地文件包含":topsec_change_lan_filedownload_BaseVerify(url),
    "Tomcat代码执行漏洞(CVE-2017-12616)":tomcat_put_exec_BaseVerify(url),
    "Tomcat 弱口令漏洞":tomcat_weak_pass_BaseVerify(url),
    "redis 未授权漏洞":redis_unauth_BaseVerify(url),
    "KingGate防火墙默认配置不当可被远控":kinggate_zebra_conf_BaseVerify(url),
    "nginx Multi-FastCGI Code Execution":multi_fastcgi_code_exec_BaseVerify(url),
    "TurboMail设计缺陷以及默认配置漏洞":turbomail_conf_BaseVerify(url),
    "TurboGate邮件网关XXE漏洞":turbogate_services_xxe_BaseVerify(url),
    "weblogic blind XXE漏洞(CVE-2018-3246)":weblogic_ws_utc_xxe_BaseVerify(url),
    "weblogic 弱口令漏洞":weblogic_weak_pass_BaseVerify(url),
    "weblogic SSRF漏洞(CVE-2014-4210)":weblogic_ssrf_BaseVerify(url),
    "weblogic XMLdecoder反序列化漏洞(CVE-2017-10271)":weblogic_xmldecoder_exec_BaseVerify(url),
    "weblogic 接口泄露":weblogic_interface_disclosure_BaseVerify(url),
    "实易DNS管理系统文件包含至远程代码执行":forease_fileinclude_code_exec_BaseVerify(url),
    "hudson源代码泄露漏洞":hudson_ws_disclosure_BaseVerify(url),
    "N点虚拟主机管理系统V1.9.6版数据库下载漏洞":npoint_mdb_download_BaseVerify(url),
    "宏杰Zkeys虚拟主机默认数据库漏洞":zkeys_database_conf_BaseVerify(url),
    "江南科友堡垒机信息泄露":hac_gateway_info_disclosure_BaseVerify(url),
    "Moxa OnCell 未授权访问":moxa_oncell_telnet_BaseVerify(url),
    "glassfish 任意文件读取":glassfish_fileread_BaseVerify(url),
    "zabbix jsrpc.php SQL注入":zabbix_jsrpc_profileIdx2_sqli_BaseVerify(url),
    "php fastcgi任意文件读取漏洞":php_fastcgi_read_BaseVerify(url),
    "php expose_php模块开启":php_expose_disclosure_BaseVerify(url),
    "hfs rejetto 远程代码执行":hfs_rejetto_search_rce_BaseVerify(url),
    "shellshock漏洞":shellshock_BaseVerify(url),
    "dorado默认口令漏洞":dorado_default_passwd_BaseVerify(url),
    "ms15_034 http.sys远程代码执行(CVE-2015-1635)":iis_ms15034_httpsys_rce_BaseVerify(url),
    "IIS 6.0 webdav远程代码执行漏洞(CVE-2017-7269)":iis_webdav_rce_BaseVerify(url),
    "深澜软件srun3000计费系统任意文件下载漏洞":srun_index_file_filedownload_BaseVerify(url),
    "深澜软件srun3000计费系统rad_online.php命令执行bypass":srun_rad_online_bypass_rce_BaseVerify(url),
    "深澜软件srun3000计费系统rad_online.php参数username命令执行":srun_rad_online_username_rce_BaseVerify(url),
    "深澜软件srun3000计费系统download.php任意文件下载":srun_download_file_filedownload_BaseVerify(url),
    "深澜软件srun3000计费系统user_info.php命令执行":srun_user_info_uid_rce_BaseVerify(url),
    "intel AMT web系统绕过登录(CVE-2017-5689)":intel_amt_crypt_bypass_BaseVerify(url),
    "smtp starttls明文命令注入(CVE-2011-0411)":smtp_starttls_plaintext_inj_BaseVerify(url),
    "resin viewfile 任意文件读取":resin_viewfile_fileread_BaseVerify(url),
    "mongodb 未授权漏洞":mongodb_unauth_BaseVerify(url),
    "深信服 AD4.5版本下命令执行漏洞":sangfor_ad_script_command_exec_BaseVerify(url),
    }
    
    
    for key in systempocdict:
        text = "[INFO]测试系统/中间件漏洞  ==> " + key
        printf(text,"yellow")
        systempocdict[key].run()
    




