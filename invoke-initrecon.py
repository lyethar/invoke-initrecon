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

def downloadtooling(tools):
	print ("Downloading tools for future use!")
	print ("Updating system!")
	os.system('sudo apt update')
	os.chdir('tools')
	os.system("wget https://raw.githubusercontent.com/lyethar/invoke-initrecon/main/better_default.rc")
	os.system("wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.2/nuclei_3.3.2_linux_amd64.zip")
	os.system("unzip nuclei_3.3.2_linux_amd64.zip")
	os.system("wget https://github.com/sensepost/gowitness/releases/download/2.5.1/gowitness-2.5.1-linux-amd64")
	for z in tools:
		os.system('git clone ' + z)
	os.chdir('..')
	print ("Done! ✅")
	
def invokescan(scope, exclude):
	os.chdir('enumeration')
	print("Executing Round 1 scans")
	output_file = "open_ports.txt"
	scope_file = scope
	exclusion = exclude
	if os.path.exists(output_file):
		os.remove(output_file)
	with open(scope_file, "r") as file:
		subnets = [line.strip() for line in file if line.strip()]
	
	for subnet in subnets:
		print(f"Scanning subnet {subnet}...")
		result = subprocess.check_output(["nmap", "-n", "-Pn", "-sS", "--top-ports", "20", "--exclude", exclusion, "--open", subnet], text=True)
		
		if "open" in result:
			print(f"Open ports found in subnet {subnet}:")
			ips_with_open_ports = [line.split()[4] for line in result.splitlines() if "Nmap scan report for" in line]
			with open(output_file, "a") as file:
				for ip in ips_with_open_ports:
					print(f"IP: {ip}")
					file.write(ip + "\n")
			print(f"Saved to {output_file}")
		else:
			print(f"No open ports found in subnet {subnet}")
	print("Done with Round 1 scans")
			        
	#os.system("nmap -sS -Pn --top-ports 20 -iL " + scope + """ | awk '/^Nmap scan report/{ip=$NF} /open/{print ip >> "open_ports.txt"}'""")
	print ("Done with Round 1 ✅")
	print("Executing Round 2 scans")
	os.system("sort open_ports.txt | uniq > output_file")
	os.system("nmap -n -sS -sV -Pn -T3 -vv -oA outputFile -iL output_file")
	print ("Done with Round 2 ✅")
	os.system('cd ..')	
	

def parse_args():
	parser = argparse.ArgumentParser()

	parser.add_argument("-s", "--scope", type=str,
			help="The scope.txt file.")
	parser.add_argument("-e", "--exclude", type=str,
			   help="Exclude your own IP to avoid messing things up while relaying on internal networks!")
	return parser.parse_args()


def main():
	args = parse_args()
	scope = args.scope
	exclude = args.exclude
	commands = ["""cat outputFile.gnmap | grep "445/open" | cut -d" " -f 2 > targets_smb.txt""","""cat outputFile.gnmap | grep "21/open" | cut -d" " -f 2 > targets_ftp.txt""","""cat outputFile.gnmap | grep "22/open" | cut -d" " -f 2 > targets_ssh.txt""","""cat outputFile.gnmap | grep "23/open" | cut -d" " -f 2 > targets_telnet.txt""","""cat outputFile.gnmap | grep "3389/open" | cut -d" " -f 2 > targets_rdp.txt""","""cat outputFile.gnmap | grep "5900/open" | cut -d" " -f 2 > targets_vnc.txt""","""cat outputFile.gnmap | grep "1433/open" | cut -d" " -f 2 > targets_sqlserver.txt""","""cat outputFile.gnmap | grep "3306/open" | cut -d" " -f 2 > targets_mysql.txt""","""cat outputFile.gnmap | grep "5432/open" | cut -d" " -f 2 > targets_postgresql.txt""","""cat outputFile.gnmap | grep "623/open" | cut -d" " -f 2 > targets_ipmi.txt""","""cat outputFile.gnmap | grep "4786/open" | cut -d" " -f 2 > targets_ciscosmartinstall.txt""","""cat outputFile.gnmap | grep "113/open" | cut -d" " -f 2 > targets_ident.txt""","""cat outputFile.gnmap | grep "873/open" | cut -d" " -f 2 > targets_rsync.txt""", """cat outputFile.gnmap | grep "2049/open" | cut -d" " -f 2 > targets_nfs.txt""",""" cat outputFile.gnmap | grep "6379/open" | cut -d" " -f 2 > targets_redis.txt""", """cat outputFile.gnmap | grep "389/open" | cut -d" " -f 2 > targets_ldap.txt"""]
	linwinpwn = "https://github.com/lefayjey/linWinPwn"
	sshaudit = "https://github.com/jtesta/ssh-audit"
	rpcenum = "https://github.com/s4vitar/rpcenum"
	kerbspray = "https://github.com/lyethar/KerbSpray"
	responder = "https://github.com/lgandx/Responder"
	masscan = "https://github.com/robertdavidgraham/masscan"
	sshaudit = "https://github.com/jtesta/ssh-audit"
	ultimate_nmap_parser = "https://github.com/shifty0g/ultimate-nmap-parser"
	tools = [linwinpwn,sshaudit,kerbspray,rpcenum,responder,masscan,sshaudit,ultimate_nmap_parser]
	printBanner()
	makedir()
	downloadtooling(tools)
	invokescan(scope, exclude)
	parseoutput(commands)

	
if __name__ == '__main__':
	main()
