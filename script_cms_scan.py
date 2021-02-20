from optparse import OptionParser
from script.func import *
from printf import*
from optparse import OptionParser
import colorama
from colorama import init,Fore,Back,Style

init(autoreset=True)
ini = fileOperation()
expFolders = list(ini.exloitsFilesList())


def script_cms_scan_scan(cms, url):
    if cms in expFolders:
        filename, plugins = ini.exploitScriptsList(cms)
        ini.setpath(filename)
        for plugin in plugins:
            output = '[INFO] 载入插件 {}'.format(plugin)
            printf(output,"yellow")
            ini.executePlugin(plugin[:-3], url)

def script_cms_scan_run(url):
    for expfolder in expFolders:
        try:
            script_cms_scan_scan(expfolder, url)
        except Exception as e:
            print(e)





