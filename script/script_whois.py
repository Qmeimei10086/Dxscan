import requests
from bs4 import BeautifulSoup

def script_whois_whois(domain):
    whoisheaders = {'User-Agent': 'Mozilla/5.0'}
    print("[INFO]send requests ==> http://whois.chinaz.com/"+domain)
    whoisr = requests.get('http://whois.chinaz.com/'+domain,headers=whoisheaders)
    whoisres = whoisr.text
    whoissoup = BeautifulSoup(whoisres,'html.parser')
    whoisa = whoissoup.find_all('p',class_="MoreInfo")
    whoisresa = str(whoisa[0])
    whoispresa = whoisresa.replace('<br/>',"\n")
    postdata = {"whois":whoispresa}
    requests.post('http://localhost:8848/whois', json=postdata)
    return whoispresa



