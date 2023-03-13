#!/bin/python3 

import sys
from colorama import Fore, Back, Style 
import subprocess 
import os 
import argparse

# Define Banner
def printBanner():
	print (Fore.YELLOW + """   ________  ________  ________  ________  ____ ___  ________   ________  ________   ________  ________   _______  ________  ________  ________  ________ 
  /        \/    /   \/    /   \/        \/    /   \/        \ /        \/    /   \ /        \/        \//       \/        \/        \/        \/    /   \
 _/       //         /         /         /         /         /_/       //         /_/       //        _//        /         /         /         /         /
/         /         /\        /         /        _/        _//         /         //         //       //        _/        _/       --/         /         / 
\\_______/\__/_____/  \______/\________/\____/___/\________/ \\_______/\__/_____/ \________/ \______/ \____/___/\________/\________/\________/\__/_____/  \n\n\n """)
print(Style.RESET_ALL)


def makedir():	
	directories = ["enumeration","exploitation","post-exploitation","tools"]
	for x in directories: 
		os.system('mkdir ' + x)
	print ("Done setting up the workflow ✅")

def parseoutput(commands):
	for y in commands:
		os.system(y)
	print ("Parsing output ✅")


def invokescan(scope):
	print("Executing Round 1 scans")
	os.system("nmap -sS -Pn --top-ports 20 -iL " + scope + """ | awk '/^Nmap scan report/{ip=$NF} /open/{print ip >> "open_ports.txt"}'""")
	print ("Done with Round 1 ✅")
	print("Executing Round 2 scans")
	os.system("sort open_ports.txt | uniq > output_file")
	os.system("nmap -sS -sV -Pn -T3 -vv -oA outputFile -iL output_file")
	print ("Done with Round 2 ✅")
		
	
	
def parse_args():
	parser = argparse.ArgumentParser()

	parser.add_argument("-s", "--scope", type=str,
			help="The scope.txt file.")
			
	return parser.parse_args()


def main():
	args = parse_args()
	scope = args.scope
	commands = ["""cat outputFile.gnmap | grep "445/open" | cut -d" " -f 2 > targets_smb.txt""","""cat outputFile.gnmap | grep "21/open" | cut -d" " -f 2 > targets_ftp.txt""","""cat outputFile.gnmap | grep "22/open" | cut -d" " -f 2 > targets_ssh.txt""","""cat outputFile.gnmap | grep "23/open" | cut -d" " -f 2 > targets_telnet.txt""","""cat outputFile.gnmap | grep "3389/open" | cut -d" " -f 2 > targets_rdp.txt""","""cat outputFile.gnmap | grep "5900/open" | cut -d" " -f 2 > targets_vnc.txt""","""cat outputFile.gnmap | grep "1433/open" | cut -d" " -f 2 > targets_sqlserver.txt""","""cat outputFile.gnmap | grep "3306/open" | cut -d" " -f 2 > targets_mysql.txt""","""cat outputFile.gnmap | grep "5432/open" | cut -d" " -f 2 > targets_postgresql.txt""","""cat outputFile.gnmap | grep "623/open" | cut -d" " -f 2 > targets_ipmi.txt""","""cat outputFile.gnmap | grep "4786/open" | cut -d" " -f 2 > targets_ciscosmartinstall.txt""","""cat outputFile.gnmap | grep "113/open" | cut -d" " -f 2 > targets_ident.txt""","""cat outputFile.gnmap | grep "873/open" | cut -d" " -f 2 > targets_rsync.txt""", """cat outputFile.gnmap | grep "2049/open" | cut -d" " -f 2 > targets_nfs.txt""",""" cat outputFile.gnmap | grep "6379/open" | cut -d" " -f 2 > targets_redis.txt"""]
	printBanner()
	makedir()
	invokescan(scope)
	parseoutput(commands)
		
	
if __name__ == '__main__':
	main()
