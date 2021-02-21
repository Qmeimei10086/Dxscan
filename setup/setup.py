import os
python_path = "python"
pip_path = "pip"
print("[+]开始更新apt/pkg")
os.system("pkg update -y")
os.system("apt update -y")
print("[+]开始安装nmap")
os.system("pkg install nmap -y")
print("[+]开始安装unzip")
os.system("pkg install unzip -y")
print("[+]开始解压配置文件")
os.system("unzip libxslt.zip")
os.system("unzip libxml2.zip")
print("[+]开始验证python版本")
python_V = (os.popen("python -V").readlines())[0]
if "3." in = python_V[:9]:
	print("[+]python默认版本为3.x")
	pass
else:
	python_V = (os.popen("python3 -V").readlines())[0]
	if "3." in = python_V[:9]:
		python_path = "python3"
	else:
		print("[-]电脑里没有python(可能)")


python_V = (os.popen("pip -V").readlines())[0]
if "3." in = python_V[:9]:
	print("[+]pip默认版本为3.x")
	pass
else:
	python_V = (os.popen("pip3 -V").readlines())[0]
	if "3." in = python_V[:9]:
		python_path = "pip3"
	else:
		print("[-]电脑里没有pip(可能)")
print("开始更新pip")
os.system(pip_path + " install --upgrade pip")

print("[+]开始安装flask")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com flask")
print("[+]开始安装paramiko")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com paramiko")
print("[+]开始安装pymongo")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com pymongo")
print("[+]开始安装pymongo")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com PyMySQL")
print("[+]开始安装pexpect")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com pexpect")
print("[+]开始安装termcolor")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com termcolor")
print("[+]开始安装requests")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com requests")
print("[+]开始安装beautifulsoup4")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com beautifulsoup4")
print("[+]开始安装elasticsearch")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com elasticsearch")
print("[+]开始安装redis")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com redis")
print("[+]开始安装colorama")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com colorama")
print("[+]开始安装scapy")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com scapy")
print("[+]开始安装python-nmap")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com python-nmap")

print("[*]基本库安装完成!")

print("[+]开始安装lxml支持库(这个最麻烦= = )")
os.system("apt install clang -y")
os.system("apt install libxml2 -y")
os.system("apt install libxslt -y")
os.system("apt install libiconv -y")
os.system("apt install libxml2-utils -y")
os.system("apt install libxml2-dev -y")
os.system("apt install libxslt-dev -y")
os.system("apt install libiconv-dev -y")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com cython")
print("[+]开始安装lxml支持库,注意下面要回答问题的awa")
os.system(pip_path + " install -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com lxml")
choose = input("安装lxml是否出现错误(默认为n)?[y/n]")
if choose == "y":
	print("多半是libxml和libxslt的问题= =")
	os.system("cd libxml2 && ./configure && make && make install")
	os.system("cd libxslt && ./configure && make && make install")
	print("[+]安装完成(大概)")
	print("命令放这里了,爱折腾的自己整 --> https://blog.csdn.net/u013992330/article/details/106933992")
	install_cmd = """
	--------------------------------
	libxml:
	
	wget ftp://xmlsoft.org/libxml2/libxml2-2.9.3.tar.gz
	tar -xvf libxml2-2.9.3.tar.gz
	cd libxml2-2.9.3
	./configure
	make
	sudo make install
	---------------------------------
	libxslt:


	wget ftp://xmlsoft.org/libxml2/libxslt-1.1.28.tar.gz
	tar -xvf libxslt-1.1.28.tar.gz
	cd libxslt-1.1.28
	./configure --build=arm-pc-linux  # x86架构的build一般为i686-pc-linux
	make 
	sudo make install
	"""
	print(install_cmd)

if choose == "n" or choose == "":
	print("[*]安装完成")




