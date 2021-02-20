from scapy.all import*
import nmap
from random import randint
import requests
def script_osscan_ttl_scan(ip):
    print("[INFO]use the TTL scan")
    id_ip = randint(1, 65535)
    id_ping = randint(1, 65535)
    seq_ping = randint(1, 65535)
    print("[INFO]Constructing packet.......")
    packet = IP(dst=ip,ttl=128,id=id_ip)/ICMP(id=id_ping, seq=seq_ping)
    print("[INFO]sending packet.........")
    result = sr1(packet,timeout=1,verbose=0)
    if result is None:
        pass
    elif int(result[IP].ttl) <= 64:
        postdata = {"system":"Linux/Uinx"}
        requests.post('http://localhost:8848/os', json=postdata)
        return "Linux/Uinx"
    else:
        postdata = {"system":"Windows"}
        requests.post('http://localhost:8848/os', json=postdata)
        return "Windows"
        
        
def script_osscan_nmap_scan(ip):
    print("[INFO]use the nmap scan")
    nm = nmap.PortScanner()    
    try:
        print("[INFO]Using nmap to scan....")
        result = nm.scan(hosts=ip,arguments='-O')
        os_name = result["scan"][ip]['osmatch'][0]['name']
        time.sleep(0.1)
        postdata = {"system":os}
        requests.post('http://localhost:8848/os', json=postdata)
        return os_name
    
    except:
        pass



