import requests
from lxml import etree

def script_findsubdomain_findsubdomain(domain):
    subdomain = []
    header = {'User-Agent': 'Mozilla/5.0'}
    print("[INFO]send requests ==> http://mtool.chinaz.com/Tool/SubDomain/?host="+domain)
    url = "http://mtool.chinaz.com/Tool/SubDomain/?host="+domain
    text = requests.get(url,headers=header).text
    html = etree.HTML(text)
    site = html.xpath('//tr/td[@name="subhost"]')
    for i in site:
        subdomain.append(i.text)
    return subdomain






