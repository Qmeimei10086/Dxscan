import requests
import queue
import threading
import sys
import time
from printf import*
from colorama import init,Fore,Back,Style
dir_data = []
init(autoreset=True)


def make_thread(url,threadNum,text,file):
    pathQueue = getPath(url,file)
    threads = []
    for i in range(threadNum):
        t = threading.Thread(target=blastingUrl, args=(pathQueue,text))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
 
def blastingUrl(pathQueue,text):
    num = 1
    nums = 0
    global dir_data
    #global postdata
    while not pathQueue.empty():
        try:
            url = pathQueue.get()
            header = {'User-Agent':'Mozilla/5.0'}
            res = requests.get(url,headers=header)

            if res.status_code == 200 and text not in res.text:
                echo = "[dir_scan]"+str(res.status_code) +" ==> "+url
                printf(echo,"yellow")
                dir_data.append(url)
            if res.status_code == 302 and text not in res.text:
                echo = "[dir_scan]"+str(res.status_code) +" ==> "+url
                printf(echo,"red")
                dir_data.append(url+" s    --code:302")
        except Exception as e:
            print(e)
            
    #postdata = {"dir": dir_data}
    


 
def getPath(url,file):
    pathQueue = queue.Queue()
    f = open(file,"r",encoding='utf-8')
    for i in f.readlines():
        path = url + i.strip()
        pathQueue.put(path)
    f.close()
    return pathQueue
 
def script_dir_scan_dir_scan(url,text,types):
    threadNum = 25
    postdata = {}
    sTime = time.time()
    file = ""
    if types == "php":
        file = "data/php.txt"
    if types == "asp":
        file = "data/asp.txt"
    if types == "aspx":
        file = "data/aspx.txt"
    if types == "jsp":
        file = "data/jsp.txt"
    if types == "beifeng":
        file = "data/beifen.txt"
    if types == 'admin':
        file = "data/admin.txt"
    if types == 'often':
        file = "data/dir.txt"
    make_thread(url,int(threadNum),text,file)
    eTime = time.time()
    postdata = {"dir": dir_data}
    requests.post('http://localhost:8848/dir', json=postdata)
    print("[INFO]共耗时%.2f s" % (eTime - sTime))






