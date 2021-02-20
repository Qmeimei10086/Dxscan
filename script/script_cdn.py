import socket
from threading import Thread, Semaphore
from printf import*
import colorama
from colorama import init,Fore,Back,Style
import requests
init(autoreset=True)
timeouts = 5.0
socket.setdefaulttimeout(timeouts)


class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs=None, *, daemon=None):
        Thread.__init__(self, group, target, name, args, kwargs, daemon=daemon)
        self._return = None

    def run(self):
        if self._target is not None:
                self._return = self._target(*self._args,**self._kwargs)

    def join(self):
        Thread.join(self)
        return self._return


def get_ip_list(domain): 
    dict = {}
    sm = Semaphore(20)
    with sm:
        try:
            addrs = socket.getaddrinfo(domain, None)
            for item in addrs:
                if item[4][0] in dict:
                    dict.get(domain).append(str(item[4][0]))
                else:
                    dict.setdefault(domain, []).append(str(item[4][0]))
            
        except Exception as e:
            print('[-] Error: {} info: {}'.format(domain, e))
            pass
        except socket.timeout as e:
            print('[-] {} time out'.format(domain))
            pass
    return dict


def open_url_txt(filename):
    url_list = []
    with open(filename, 'r') as f:
        for l in f:
            url_list.append(l.strip())
    return url_list



def script_cdn_iscdn(url):
    t = ThreadWithReturnValue(target=get_ip_list, args=(url,))
    t.start()
    ip = t.join()
    if ip:
        for key in ip:
            if len(ip[key]) > 1:
                output = '[CDN] [-] Url: {} 可能有CDN'.format(key)
                postdata = {"cdn": "YES"}
                requests.post('http://localhost:8848/cdn', json=postdata)
                printf(output,"red")
                return True
            else:
                output = '[CDN] [+] Url:{} 没有CDN! IP:{}'.format(key, ip[key][0])
                postdata = {"cdn": "NO"}
                requests.post('http://localhost:8848/cdn', json=postdata)
                printf(output,"yellow")
                return False
                
