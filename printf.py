import colorama
from colorama import init,Fore,Back,Style
import platform

def print_linux(text,color):
    if color == "black":
        print('\033[30m'+text)
    if color == "red":
        print('\033[31m'+text)
    if color == "green":
        print('\033[32m'+text)
    if color == "yellow":
        print('\033[33m'+text)
    if color == "blue":
        print('\033[34m'+text)
    if color == "pink":
        print('\033[35m'+text)
    if color == "white":
        print('\033[37m'+text)

def print_windows(text,color):
    init(autoreset=True)
    if color == "black":
        print('\033[1;31;30m'+text)
    if color == "red":
        print('\033[1;31;31m'+text)
    if color == "green":
        print('\033[1;31;32m'+text)
    if color == "yellow":
        print('\033[1;31;33m'+text)
    if color == "blue":
        print('\033[1;31;34m'+text)
    if color == "pink":
        print('\033[1;31;35m'+text)
    if color == "white":
        print('\033[1;31;37m'+text)

def printf(text,color):
    if platform.system().lower() == 'windows':
        print_linux(text,color)
    elif platform.system().lower() == 'linux':
        print_windows(text,color)


