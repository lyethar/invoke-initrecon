#!/bin/python3 

import sys
from colorama import Fore, Back, Style 
import subprocess 
import os 
import argparse
import stat


def printBanner():
    print (Fore.YELLOW + """ _______        .__  .__    _________             .__   ._.
 \      \  __ __|  | |  |  /   _____/ ____   _____|  |__| |
 /   |   \|  |  \  | |  |  \_____  \_/ __ \ /  ___/  |  \ |
/    |    \  |  /  |_|  |__/        \  ___/ \___ \|   Y  \|
\____|__  /____/|____/____/_______  /\___  >____  >___|  /_
        \/                        \/     \/     \/     \/\/\n\n\n """)
    print(Style.RESET_ALL)


def smb_enum(targets_smb):
    os.system("apt install smbmap")
    targets = targets_smb
    print(Fore.GREEN + "\nEnumerating NULL SMB sessions!" )
    print(Style.RESET_ALL)
    print(Fore.YELLOW)
    os.system("""crackmapexec smb """ + targets + """ -u 'a' -p '' --shares""" )
    print(Style.RESET_ALL)

def ldap_enum(targets_ldap):
    print("Executing null session enumeration against LDAP, RPC, and SMB!")
    print("Installing ldap-utils!")
    os.system("apt install ldap-utils")
    print("Done!✅")
    with open(targets_ldap) as file_in:
        lines = []
        for line in file_in:
            lines.append(line)
	
    for l in lines:
        print(Fore.GREEN + "\nEnumerating " + l)
        print(Style.RESET_ALL)
        print(Fore.YELLOW)
        os.system("""ldapsearch -H ldap://""" + l + """:389/ -x -b '' -W 'objectclass=*'""")
        print(Style.RESET_ALL)


def rpc_enum(targets_rpc):
    os.chdir('tools')
    os.chdir('rpcenum')
    os.chmod('rpcenum', stat.S_IXOTH)
    with open(targets_rpc) as file_in:
        lines = []
        for line in file_in:
            lines.append(line)
	
    for l in lines:
        print(Fore.GREEN + "\nEnumerating " + l)
        print(Style.RESET_ALL)
        print(Fore.YELLOW)
        result = subprocess.check_output(["./rpcenum", "-i", l, "-e", "All"], text=True)
        print(result)
        print(Style.RESET_ALL)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--smb-targets", type=str,
                        help="The file containing targets running SMB")
    parser.add_argument("-l", "--ldap-targets", type=str,
                        help="The file containing targets running LDAP")
    parser.add_argument("-r", "--rpc-targets", type=str,
                        help="The file containing targets running RPC")
    return parser.parse_args()

def main():
    args = parse_args()
    targets_smb = args.targets_smb
    targets_ldap = args.targets_ldap
    targets_rpc = args.targets_rpc
    printBanner()
    smb_enum(targets_smb)
    ldap_enum(targets_ldap)
    rpc_enum(targets_rpc)

	
if __name__ == '__main__':
    main()
