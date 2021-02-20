# Dxscan  
一款多功能全自动漏洞扫描,信息收集工具 
# 安装:  
1.   pip install -r requirements.txt    
2.   安装nmap   
  
需要的库:  
paramiko==2.4.2  
pymongo==3.7.2  
PyMySQL==0.9.2  
pexpect==4.6.0  
termcolor==1.1.0  
requests==2.20.0  
beautifulsoup4==4.6.3  
elasticsearch==6.3.1  
redis==2.10.6  
colorama  
BeautifulSoup  
scapy  
python-nmap  
flask  
  
# 作用:  
全自动web扫描器  
支持端口扫描,whois查询，cdn确认，指纹识别，系统扫描，js敏感信息泄露，目录爆破，sql模糊尝试,子域名扫描  
  
# 亮点:  
400+cms的poc  
100+系统，服务中间件漏洞  
400+指纹信息  
自动生成json和txt报告  
  
# 使用  
-t + 域名  
-O ：扫描系统  
-whois ：获取whois信息  
-F ：子域名扫描  
-P ：端口扫描  
-V ：获取指纹，中间件，语言等  
-D ：目录爆破  
-J ：js敏感信息收集  
-C ：cms漏洞扫描  
-S ：系统扫描  
-I ：cdn判断  
-Q ：sql模糊测试  
-A ：waf识别  
-W ：全自动化扫描  
  
如果你啥也不会直接: python Dxscan.py -W -t explamp.com(域名)  

