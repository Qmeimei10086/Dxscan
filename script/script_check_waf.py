import logging
import re
import requests
from urllib import parse
WAF_RULE = (
    'WAF|headers|Server|WAF', r'360|headers|X-Powered-By-360wzb|wangzhan\.360\.cn', '360|headers|X-Powered-By|360',
    '360wzws|headers|Server|360wzws', '360 AN YU|content|content|Sorry! your access has been intercepted by AnYu',
    '360 AN YU|content|content|AnYu- the green channel', 'Anquanbao|headers|X-Powered-By-Anquanbao|MISS',
    'Armor|headers|Server|armor', 'BaiduYunjiasu|headers|Server|yunjiasu-nginx',
    'BinarySEC|headers|x-binarysec-cache|miss', r'BinarySEC|headers|x-binarysec-via|binarysec\.com',
    'BinarySEC|headers|Server|BinarySec', r'BlockDoS|headers|Server|BlockDos\.net',
    'CloudFlare CDN|headers|Server|cloudflare-nginx', 'CloudFlare CDN|headers|Server|cloudflare',
    'cloudflare CDN|headers|CF-RAY|.+', 'Cloudfront CDN|headers|Server|cloudfront',
    'Cloudfront CDN|headers|X-Cache|cloudfront', r'Cloudfront CDN|headers|X-Cache|Error\sfrom\scloudfront',
    'mod_security|headers|Server|mod_security', 'Barracuda NG|headers|Server|Barracuda',
    'mod_security|headers|Server|Mod_Security', 'F5 BIG-IP APM|headers|Server|BigIP',
    'F5 BIG-IP APM|headers|Server|BIG-IP', 'F5 BIG-IP ASM|headers|X-WA-Info|.+',
    'F5 BIG-IP ASM|headers|X-Cnection|close', 'F5-TrafficShield|headers|Server|F5-TrafficShield',
    'GoDaddy|headers|X-Powered-By|GoDaddy', 'Bluedon IST|headers|Server|BDWAF',
    'Comodo|headers|Server|Protected by COMODO', 'Airee CDN|headers|Server|Airee', 'Beluga CDN|headers|Server|Beluga',
    'Fastly CDN|headers|X-Fastly-Request-ID|\w+', 'limelight CDN|headers|Set-Cookie|limelight',
    'CacheFly CDN|headers|BestCDN|CacheFly', 'maxcdn CDN|headers|X-CDN|maxcdn',
    'DenyAll|headers|Set-Cookie|\Asessioncookie=', 'AdNovum|headers|Set-Cookie|^Navajo.*?$',
    'dotDefender|headers|X-dotDefender-denied|1', 'Incapsula CDN|headers|X-CDN|Incapsula',
    'Jiasule|headers|Set-Cookie|jsluid=', 'KONA|headers|Server|AkamaiGHost', 'ModSecurity|headers|Server|NYOB',
    'ModSecurity|headers|Server|NOYB', 'ModSecurity|headers|Server|.*mod_security',
    'NetContinuum|headers|Cneonction|\Aclose', 'NetContinuum|headers|nnCoection|\Aclose',
    'NetContinuum|headers|Set-Cookie|citrix_ns_id', 'Newdefend|headers|Server|newdefend',
    'NSFOCUS|headers|Server|NSFocus', 'Safe3|headers|X-Powered-By|Safe3WAF', 'Safe3|headers|Server|Safe3 Web Firewall',
    'Safedog|headers|X-Powered-By|WAF/2\.0', 'Safedog|headers|Server|Safedog', 'Safedog|headers|Set-Cookie|Safedog',
    'Safedog|content|content|404.safedog.cn/images/safedogsite/broswer_logo.jpg', 'SonicWALL|headers|Server|SonicWALL',
    'ZenEdge Firewall|headers|Server|ZENEDGE', 'WatchGuard|headers|Server|WatchGuard',
    'Stingray|headers|Set-Cookie|\AX-Mapping-', 'Art of Defence HyperGuard|headers|Set-Cookie|WODSESSION=',
    'Sucuri|headers|Server|Sucuri/Cloudproxy', 'Usp-Sec|headers|Server|Secure Entry Server',
    'Varnish|headers|X-Varnish|.+', 'Varnish|headers|Server|varnish', 'Wallarm|headers|Server|nginx-wallarm',
    'WebKnight|headers|Server|WebKnight', 'Yundun|headers|Server|YUNDUN', 'Teros WAF|headers|Set-Cookie|st8id=',
    'Imperva SecureSphere|headers|X-Iinfo|.+', 'NetContinuum WAF|headers|Set-Cookie|NCI__SessionId=',
    'Yundun|headers|X-Cache|YUNDUN', 'Yunsuo|headers|Set-Cookie|yunsuo', 'Immunify360|headers|Server|imunify360',
    'ISAServer|headers|Via|.+ISASERVER', 'Qiniu CDN|headers|X-Qiniu-Zone|0', 'azion CDN|headers|Server|azion',
    'HyperGuard Firewall|headers|Set-cookie|ODSESSION=', 'ArvanCloud|headers|Server|ArvanCloud',
    'GreyWizard Firewall|headers|Server|greywizard.*', 'FortiWeb Firewall|headers|Set-Cookie|cookiesession1',
    'Beluga CDN|headers|Server|Beluga', 'DoSArrest Internet Security|headers|X-DIS-Request-ID|.+',
    'ChinaCache CDN|headers|Powered-By-ChinaCache|\w+', 'ChinaCache CDN|headers|Server|ChinaCache',
    'HuaweiCloudWAF|headers|Server|HuaweiCloudWAF', 'HuaweiCloudWAF|headers|Set-Cookie|HWWAFSESID',
    'KeyCDN|headers|Server|KeyCDN', 'Reblaze Firewall|headers|Set-cookie|rbzid=\w+',
    'Distil Firewall|headers|X-Distil-CS|.+', 'SDWAF|headers|X-Powered-By|SDWAF',
    'NGENIX CDN|headers|X-NGENIX-Cache|HIT', 'FortiWeb|headers|Server|FortiWeb.*',
    'Naxsi|headers|X-Data-Origin|naxsi-waf', 'IBM DataPower|headers|X-Backside-Transport|\w+',
    'Cisco ACE XML Gateway|headers|Server|ACE\sXML\sGateway', 'AWS WAF|headers|Server|awselb.*',
    'PowerCDN|headers|Server|PowerCDN', 'Profense|headers|Server|profense', 'CompState|headers|X-SL-CompState|.+',
    'West263CDN|headers|X-Cache|.+WT263CDN-.+', 'DenyALL WAF|content|content|Condition Intercepted',
    'yunsuo|content|content|<img\sclass="yunsuologo"', 'yunsuo|headers|Set-Cookie|yunsuo_session_verify',
    'aesecure|content|content|aesecure_denied.png', 'aesecure|content|content|aesecure_denied.png',
    'aliyun|content|content|errors.aliyun.com', 'aliyun|content|content|cdn.aliyuncs.com',
    'aliyun|headers|Set-Cookie|aliyungf_tc=',
    'Palo Alto Firewall|content|content|has been blocked in accordance with company policy',
    'PerimeterX Firewall|content|content|https://www.perimeterx.com/whywasiblocked',
    'Neusoft SEnginx|content|content|SENGINX-ROBOT-MITIGATION',
    'SiteLock TrueShield|content|content|sitelock-site-verification', 'SonicWall|content|content|nsa_banner',
    'SonicWall|content|content|Web Site Blocked', 'Sophos UTM Firewall|content|content|Powered by UTM Web Protection',
    'd盾|content|content|D盾_拦截提示', 'Alert Logic|content|content|<title>Requested URL cannot be found</title>',
    'Alert Logic|content|content|We are sorry, but the page you are looking for cannot be found',
    'Alert Logic|content|content|Reference ID:', 'Approach|content|content|Approach</b> Web Application Firewall',
    'Approach|content|content|Approach</i> infrastructure team',
    'Topsec-Waf|content|content|Topsec Network Security Technology Co.,Ltd', '七牛CDN|content|content|glb.clouddn.com',
    '七牛CDN|content|content|glb.qiniucdn.com', '七牛CDN|content|content|cdn.staticfile.org',
    '网宿CDN|headers|Server|Cdn Cache Server', '网宿CDN|headers|Server|WS CDN Server',
    '网宿CDN|headers|X-Via|Cdn Cache Server', 'DnP Firewall|content|content|Powered by DnP Firewall',
    'DnP Firewall|content|content|dnp_firewall_redirect', '华为防火墙|headers|Server|Eudemon.+',
    'Incapsula-WAF|headers|set-cookie|incap_ses_', 'Incapsula-WAF|headers|set-cookie|incap_visid_83_',
    'RackCorp-CDN|headers|server|^[\s]*rackcorpcdn', 'RackCorp-CDN|headers|server|^[\s]*rackcorpcdn\/([\d\.]{3,6})')
def parse_host(url):
    if (not parse.urlparse(url).path) and (parse.urlparse(url).path != '/'):
        host = url.replace('http://', '').replace('https://', '').rstrip('/')
    else:
        host = url.replace('http://', '').replace('https://', '').rstrip('/')
        host = re.sub(r'/\w+', '', host)
    if ':' in host:
        host = re.sub(r':\d+', '', host)
    return host


def verify(headers, content):
    for i in WAF_RULE:
        name, method, position, regex = i.split('|')
        if method == 'headers':
            if headers.get(position) is not None:
                if re.search(regex, str(headers.get(position))) is not None:
                    return name
        else:
            if re.search(regex, str(content)):
                return name
    return 'NoWAF'


def script_check_waf_checkwaf(url):
    payload = (
    "/index.php?id=1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(XSS)</script>',table_name FROM information_schema.tables WHERE 2>1--/**/",
    "/../../../etc/passwd", "/.git/", "/phpinfo.php")
    result = 'NoWAF'
    host = parse_host(url)
    header = {'User-Agent':'Mozilla/5.0'}
    try:
        r = requests.get(url,headers=header)
        result = verify(r.headers, r.text)
        if result == 'NoWAF':
            for i in payload:
                r = requests.get(url + i,headers=header)
                result = verify(r.headers, r.text)
                if result != 'NoWAF' and result != None:
                    return result
        elif result == None:
            return 'NoWAF'
        else:
            return result
    except (UnboundLocalError, AttributeError):
        pass
    except Exception as e:
        logging.exception(e)


