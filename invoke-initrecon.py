#!/bin/python3 

import sys
from colorama import Fore, Back, Style 
import subprocess 
import os 
import argparse
import re

# Define base directories
BASE_DIR = "/opt/initrecon"
TOOLS_DIR = f"{BASE_DIR}/tools"
ENUM_DIR = f"{BASE_DIR}/enumeration"
EXPLOIT_DIR = f"{BASE_DIR}/exploitation"
POST_DIR = f"{BASE_DIR}/post-exploitation"

# Define color scheme for output messages
INFO = Fore.BLUE      # Information messages
SUCCESS = Fore.GREEN  # Success messages
ERROR = Fore.RED      # Error messages
WARNING = Fore.YELLOW # Warning messages
RESET = Style.RESET_ALL

# Helper function for formatted output
def print_status(message, status_type=INFO, symbol="[*]"):
	print(f"{status_type}{symbol} {message}{RESET}")

def print_success(message):
	print_status(message, SUCCESS, "[+]")

def print_error(message):
	print_status(message, ERROR, "[-]")

def print_info(message):
	print_status(message, INFO, "[*]")

def print_warning(message):
	print_status(message, WARNING, "[!]")

# Define standardized scan parameters
NMAP_STANDARD_OPTS = "-n -Pn"  # No DNS resolution, treat all hosts as online
NMAP_TIMING = "-T3"  # Default timing template
NMAP_RATE = "--max-rate 1000"  # Standard packet rate
NMAP_RETRIES = "--max-retries 1"  # Minimize retries for faster scanning
NMAP_HOST_TIMEOUT = "--host-timeout 2m"  # Standard host timeout
NMAP_EXTRA = "--defeat-rst-ratelimit"  # Help with rate limiting
NMAP_OUTPUT = "-vv"  # Verbosity level

# Combine standard options
NMAP_COMMON = f"{NMAP_STANDARD_OPTS} {NMAP_TIMING} {NMAP_RATE} {NMAP_RETRIES} {NMAP_HOST_TIMEOUT} {NMAP_EXTRA} {NMAP_OUTPUT}"

# Define Banner
def printBanner():
	print (Fore.YELLOW + """   ________  ________  ________  ________  ____ ___  ________   ________  ________   ________  ________   _______  ________  ________  ________  ________ 
  /        \/    /   \/    /   \/        \/    /   \/        \ /        \/    /   \ /        \/        \//       \/        \/        \/        \/    /   \
 _/       //         /         /         /         /         /_/       //         /_/       //        _//        /         /         /         /         /
/         /         /\        /         /        _/        _//         /         //         //       //        _/        _/       --/         /         / 
\\_______/\__/_____/  \______/\________/\____/___/\________/ \\_______/\__/_____/ \________/ \______/ \____/___/\________/\________/\________/\__/_____/  \n\n\n """)
print(Style.RESET_ALL)

def makedir():	
	# Create base directories with absolute paths
	directories = [BASE_DIR, TOOLS_DIR, ENUM_DIR, EXPLOIT_DIR, POST_DIR]
	for x in directories: 
		os.system(f'sudo mkdir -p {x}')
		os.system(f'sudo chmod 777 {x}')  # Ensure we have write permissions
	print_success("Base directories created ✅")

def downloadtooling(tools):
	print_info("Downloading and setting up enumeration tools...")
	
	# System updates
	print_info("Updating system...")
	os.system('sudo apt update && sudo apt install -y enum4linux nbtscan onesixtyone snmp-mibs-downloader seclists')
	
	# Create tool categories in /opt/initrecon/tools/
	os.chdir(TOOLS_DIR)
	categories = ['smb', 'ldap', 'ftp', 'general', 'web']
	for category in categories:
		if not os.path.exists(f"{TOOLS_DIR}/{category}"):
			os.makedirs(f"{TOOLS_DIR}/{category}")
	
	# Download and organize tools
	print_info("Downloading tools...")
	
	# General tools
	os.system(f"wget https://raw.githubusercontent.com/lyethar/invoke-initrecon/main/better_default.rc -O {TOOLS_DIR}/better_default.rc")
	os.system(f"wget https://github.com/projectdiscovery/nuclei/releases/download/v3.4.4/nuclei_3.4.4_linux_amd64.zip -O {TOOLS_DIR}/nuclei.zip")
	os.system(f"cd {TOOLS_DIR} && unzip nuclei.zip && rm nuclei.zip")
	os.system(f"wget https://github.com/sensepost/gowitness/releases/download/3.0.5/gowitness-3.0.5-linux-amd64 -O {TOOLS_DIR}/gowitness")
	os.system(f"chmod +x {TOOLS_DIR}/gowitness")
	os.system(f"chmod +x {TOOLS_DIR}/nuclei")
	
	# Protocol-specific tools
	tool_mapping = {
		'smb': [
			'https://github.com/lefayjey/linWinPwn',
			'https://github.com/lgandx/Responder',
			'https://github.com/Pennyw0rth/NetExec',
			'https://github.com/dirkjanm/mitm6'
		],
		'ldap': [
			'https://github.com/lyethar/KerbSpray',
			'https://github.com/ropnop/windapsearch',
			'https://github.com/dirkjanm/ldapdomaindump'
		],
		'ftp': [
			'https://github.com/danielmiessler/SecLists'
		],
		'general': [
			'https://github.com/robertdavidgraham/masscan',
			'https://github.com/shifty0g/ultimate-nmap-parser',
			'https://github.com/s4vitar/rpcenum',
			'https://github.com/jtesta/ssh-audit'
		]
	}
	
	# Clone and set up tools with absolute paths
	for category, repo_list in tool_mapping.items():
		category_path = f"{TOOLS_DIR}/{category}"
		for repo in repo_list:
			repo_name = repo.split('/')[-1]
			os.system(f"cd {category_path} && git clone {repo}")
	
	#print("[+] Installing Python requirements for tools...")
	#os.system('pip3 install impacket ldap3 pyasn1 pycryptodomex')
	
	print_success("Tool setup complete! ✅")

def invokescan(scope, exclude):
	os.chdir(ENUM_DIR)
	print_info("Starting network enumeration...")
	
	# Initial host discovery and quick port scan
	print_info("Phase 1: Quick host discovery...")
	output_file = f"{ENUM_DIR}/open_ports.txt"
	
	if os.path.exists(output_file):
		os.remove(output_file)
		
	with open(scope, "r") as file:
		subnets = [line.strip() for line in file if line.strip()]
	
	for subnet in subnets:
		print_info(f"Scanning subnet {subnet}...")
		# Quick SYN scan with standardized parameters
		quick_scan_cmd = ["nmap"] + NMAP_COMMON.split() + ["-sS", "--top-ports", "20", "--open", "--exclude", exclude, subnet]
		result = subprocess.check_output(quick_scan_cmd, text=True)
		
		if "open" in result:
			print_success(f"Open ports found in subnet {subnet}")
			ips_with_open_ports = [line.split()[4] for line in result.splitlines() 
								 if "Nmap scan report for" in line]
			with open(output_file, "a") as file:
				for ip in ips_with_open_ports:
					file.write(ip + "\n")
	
	print_success(f"Phase 1 complete - Quick discovery finished - Check live hosts in {ENUM_DIR}/open_ports.txt")

	# Comprehensive port scan
	print_info("Phase 2: Detailed port scanning...")
	os.system(f"sort {output_file} | uniq > {ENUM_DIR}/output_file")
	
	print_info("Scanning hosts utilizing 88, 135, 389, 445 ...")
	domain_ports = [88, 135, 389, 445]
 
	for port in domain_ports:
		print_info(f"Scanning port {port}...")
		os.system(f"nmap {NMAP_COMMON} -sS --open -p {port} -oA {ENUM_DIR}/scan_{port} -iL {ENUM_DIR}/output_file")
	# Parse scan results for domain ports and output to service files
	for port in domain_ports:
		print_info(f"Parsing scan results for port {port}...")
		os.system(f"""grep "{port}/open" {ENUM_DIR}/scan_{port}.gnmap | cut -d" " -f2 > {ENUM_DIR}/targets_port_{port}.txt""")
		
		# Map ports to services
		if port == 88:
			os.system(f"cp {ENUM_DIR}/targets_port_88.txt {ENUM_DIR}/targets_kerberos.txt")
		elif port == 135:
			os.system(f"cp {ENUM_DIR}/targets_port_135.txt {ENUM_DIR}/targets_rpc.txt")
		elif port == 389:
			os.system(f"cp {ENUM_DIR}/targets_port_389.txt {ENUM_DIR}/targets_ldap.txt") 
		elif port == 445:
			os.system(f"cp {ENUM_DIR}/targets_port_445.txt {ENUM_DIR}/targets_smb.txt")

	# Retrieve domain controllers from results
	# Compare Kerberos and LDAP hosts to identify domain controllers
	print_info("Identifying domain controllers...")
	dc_output = f"{ENUM_DIR}/targets_domain_controllers.txt"
	
	# Read hosts with Kerberos (88) and LDAP (389)
	with open(f"{ENUM_DIR}/targets_kerberos.txt", "r") as f:
		kerberos_hosts = set(line.strip() for line in f)
	
	with open(f"{ENUM_DIR}/targets_ldap.txt", "r") as f:
		ldap_hosts = set(line.strip() for line in f)
	
	# Find hosts that have both ports open
	domain_controllers = kerberos_hosts.intersection(ldap_hosts)
	
	# Write domain controllers to file
	with open(dc_output, "w") as f:
		for dc in domain_controllers:
			f.write(f"{dc}\n")
	
	print_success(f"Domain controllers identified and saved to {dc_output}")
	# Retrieve domain name from domain controllers using nmap NSE scripts
	print_info("Retrieving domain name from domain controllers...")
	domain_name_cmd = f"nmap {NMAP_COMMON} -p 389 --script ldap-rootdse -oA {ENUM_DIR}/domain_name_scan -iL {ENUM_DIR}/targets_domain_controllers.txt"
	os.system(domain_name_cmd)
 
	# Parse the domain name from the scan results
	domain_output = f"{ENUM_DIR}/domain_name.txt"
	domain_name = ""
 
	try:
		with open(f"{ENUM_DIR}/domain_name_scan.nmap", "r") as f:
			for line in f:
				if "defaultNamingContext:" in line:
					# Extract domain name from DN format (e.g., DC=domain,DC=local)
					domain_parts = line.split("DC=")[1:]  # Split on DC= and skip first empty part
					domain_name = ".".join([part.split(",")[0] for part in domain_parts])
					break
		
		if domain_name:
			with open(domain_output, "w") as f:
				f.write(domain_name + "\n")
			print_success(f"Domain name identified: {domain_name}")
			print_success(f"Domain name saved to {domain_output}")
		else:
			print_error("Could not determine domain name")
 
	except FileNotFoundError:
		print_error("Domain name scan results not found")
	except Exception as e:
		print_error(f"Error retrieving domain name: {str(e)}")
 
	# Check for SMB signing on identified SMB hosts
	print_info("Checking for SMB signing...")
	smb_signing_cmd = f"nmap {NMAP_COMMON} -p445 --script smb2-security-mode -oA {ENUM_DIR}/smb_signing_scan -iL {ENUM_DIR}/targets_smb.txt"
	os.system(smb_signing_cmd)

	# Parse results and extract hosts without SMB signing
	unsigned_ips = []
	try:
		with open(f"{ENUM_DIR}/smb_signing_scan.nmap", "r") as f:
			current_ip = None
			for line in f:
				if "Nmap scan report for" in line:
					current_ip = line.split()[-1].strip("()")
				elif "Message signing enabled but not required" in line:
					unsigned_ips.append(current_ip)

		# Save IPs to file
		with open(f"{ENUM_DIR}/targets_smb_unsigned.txt", "w") as f:
			for ip in unsigned_ips:
				f.write(f"{ip}\n")

		# Get DNS names for unsigned hosts
		dns_cmd = f"nmap {NMAP_COMMON} -sL -iL {ENUM_DIR}/targets_smb_unsigned.txt -oA {ENUM_DIR}/smb_unsigned_dns"
		os.system(dns_cmd)

		# Parse and save results with DNS names
		with open(f"{ENUM_DIR}/smb_unsigned_dns.nmap", "r") as f, \
			 open(f"{ENUM_DIR}/targets_smb_unsigned_dns.txt", "w") as out:
			for line in f:
				if "Nmap scan report for" in line:
					parts = line.split()
					if len(parts) > 5:  # Has DNS name
						dns = parts[4]
						ip = parts[5].strip("()")
						out.write(f"{ip} - {dns}\n")
					else:  # IP only
						ip = parts[4]
						out.write(f"{ip}\n")

		print_success(f"Hosts without SMB signing saved to {ENUM_DIR}/targets_smb_unsigned.txt")
		print_success(f"Hosts without SMB signing (with DNS) saved to {ENUM_DIR}/targets_smb_unsigned_dns.txt")

	except FileNotFoundError:
		print_error("SMB signing scan results not found")
	except Exception as e:
		print_error(f"Error processing SMB signing results: {str(e)}")
  
  
	# Null Session Enumeration Against SMB & RPC 	
	print_info("Performing null session enumeration against SMB and RPC...")
	smb_null_hosts = []
	rpc_null_hosts = []

	try:
		# Try netexec first for SMB
		subprocess.run(["netexec", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		result = subprocess.run(f"netexec {ENUM_DIR}/targets_smb.txt -u 'a' -p '' --shares", shell=True, capture_output=True, text=True)
		with open(f"{ENUM_DIR}/smb_null_sessions.txt", "w") as f:
			f.write(result.stdout)
			# Extract successful null sessions
			for line in result.stdout.splitlines():
				if "[+]" in line:  # netexec shows [+] for successful auth
					ip = line.split()[0]
					smb_null_hosts.append(ip)
	except FileNotFoundError:
		try:
			# Try crackmapexec if netexec not found
			subprocess.run(["crackmapexec", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			result = subprocess.run(f"crackmapexec smb {ENUM_DIR}/targets_smb.txt -u 'a' -p '' --shares", shell=True, capture_output=True, text=True)
			with open(f"{ENUM_DIR}/smb_null_sessions.txt", "w") as f:
				f.write(result.stdout)
				# Extract successful null sessions
				for line in result.stdout.splitlines():
					if "[+]" in line:  # crackmapexec shows [+] for successful auth
						ip = line.split()[1]
						smb_null_hosts.append(ip)
		except FileNotFoundError:
			# Fall back to smbmap if neither is found
			result = subprocess.run(f"smbmap -H {ENUM_DIR}/targets_smb.txt -u 'a' -p ''", shell=True, capture_output=True, text=True)
			with open(f"{ENUM_DIR}/smb_null_sessions.txt", "w") as f:
				f.write(result.stdout)
				# Extract successful null sessions
				for line in result.stdout.splitlines():
					if "OK" in line:  # smbmap shows OK for successful auth
						ip = line.split()[0]
						smb_null_hosts.append(ip)

	try:
		# Try netexec first for RPC
		subprocess.run(["netexec", "smb", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		result = subprocess.run(f"netexec smb {ENUM_DIR}/targets_rpc.txt -u '' -p '' --users", shell=True, capture_output=True, text=True)
		with open(f"{ENUM_DIR}/rpc_enum.txt", "w") as f:
			f.write(result.stdout)
			# Extract successful null sessions
			for line in result.stdout.splitlines():
				if "[+]" in line:  # netexec shows [+] for successful auth
					ip = line.split()[0]
					rpc_null_hosts.append(ip)
	except FileNotFoundError:
		try:
			# Try crackmapexec if netexec not found
			subprocess.run(["crackmapexec", "smb", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			result = subprocess.run(f"crackmapexec smb {ENUM_DIR}/targets_rpc.txt -u '' -p '' --users", shell=True, capture_output=True, text=True)
			with open(f"{ENUM_DIR}/rpc_enum.txt", "w") as f:
				f.write(result.stdout)
				# Extract successful null sessions
				for line in result.stdout.splitlines():
					if "[+]" in line:  # crackmapexec shows [+] for successful auth
						ip = line.split()[1]
						rpc_null_hosts.append(ip)
		except FileNotFoundError:
			try:
				# Try rpcenum if crackmapexec not found
				with open(f"{ENUM_DIR}/targets_rpc.txt", "r") as f:
					for ip in f:
						ip = ip.strip()
						if ip:  # Skip empty lines
							result = subprocess.run(f"{TOOLS_DIR}/general/rpcenum/rpcenum -e All -i {ip}", shell=True, capture_output=True, text=True)
							with open(f"{ENUM_DIR}/rpc_enum.txt", "a") as out:
								out.write(result.stdout)
							if "successful" in result.stdout.lower():  # rpcenum shows "successful" for working null sessions
								rpc_null_hosts.append(ip)
			except:
				# Fall back to rpcclient if all else fails
				with open(f"{ENUM_DIR}/targets_rpc.txt", "r") as f:
					for ip in f:
						ip = ip.strip()
						if ip:  # Skip empty lines
							result = subprocess.run(f"rpcclient -U '' -N {ip} -c 'enumdomusers'", shell=True, capture_output=True, text=True)
							with open(f"{ENUM_DIR}/rpc_enum.txt", "a") as out:
								out.write(result.stdout)
							if result.returncode == 0:  # rpcclient returns 0 on successful auth
								rpc_null_hosts.append(ip)

	# Output vulnerable hosts
	with open(f"{ENUM_DIR}/smb_null_hosts.txt", "w") as f:
		for host in smb_null_hosts:
			f.write(f"{host}\n")
	if smb_null_hosts:
		print_warning("The following hosts allow SMB null sessions:")
		for host in smb_null_hosts:
			print_info(f"  {host}")
		print_info(f"Results saved to {ENUM_DIR}/smb_null_hosts.txt")
	
	with open(f"{ENUM_DIR}/rpc_null_hosts.txt", "w") as f:
		for host in rpc_null_hosts:
			f.write(f"{host}\n")
	if rpc_null_hosts:
		print_warning("The following hosts allow RPC null sessions:")
		for host in rpc_null_hosts:
			print_info(f"  {host}")
		print_info(f"Results saved to {ENUM_DIR}/rpc_null_hosts.txt")
  
  
	# LDAP null enumeration
	print_info("Checking for LDAP null binds...")
	ldap_null_hosts = []

	try:
		with open(f"{ENUM_DIR}/targets_ldap.txt", "r") as f:
			for ip in f:
				ip = ip.strip()
				if ip:  # Skip empty lines
					print_info(f"Attempting LDAP null bind on {ip}")
					
					# Try both standard LDAP and LDAPS
					protocols = [
						("ldap", "389"),
						("ldaps", "636")
					]
					
					for protocol, port in protocols:
						# Basic anonymous bind check
						result = subprocess.run(
							f"ldapsearch -x -H {protocol}://{ip}:{port} -s base '(objectClass=*)'",
							shell=True, capture_output=True, text=True
						)
						
						# If successful, try to enumerate more information
						if result.returncode == 0:
							ldap_null_hosts.append(f"{ip}:{port}")
							print_success(f"Successful null bind on {protocol}://{ip}:{port}")
							
							# Save initial results
							with open(f"{ENUM_DIR}/ldap_enum_{ip}.txt", "w") as out:
								out.write(f"=== {protocol}://{ip}:{port} Anonymous Bind Results ===\n")
								out.write(result.stdout)
							
							# Try to enumerate naming contexts
							naming_result = subprocess.run(
								f"ldapsearch -x -H {protocol}://{ip}:{port} -s base -b '' '(objectClass=*)' namingContexts",
								shell=True, capture_output=True, text=True
							)
							
							if naming_result.returncode == 0 and "namingContexts:" in naming_result.stdout:
								contexts = []
								for line in naming_result.stdout.splitlines():
									if "namingContexts:" in line:
										context = line.split("namingContexts:", 1)[1].strip()
										contexts.append(context)
										
								# For each naming context, try to enumerate objects
								for context in contexts:
									enum_result = subprocess.run(
										f"ldapsearch -x -H {protocol}://{ip}:{port} -b '{context}' '(objectClass=*)'",
										shell=True, capture_output=True, text=True
									)
									
									with open(f"{ENUM_DIR}/ldap_enum_{ip}.txt", "a") as out:
										out.write(f"\n=== Enumeration of {context} ===\n")
										out.write(enum_result.stdout)
						else:
							print_info(f"No null bind available on {protocol}://{ip}:{port}")

	except FileNotFoundError:
		print_warning("No LDAP targets found")
	except Exception as e:
		print_error(f"Error during LDAP enumeration: {str(e)}")

	# Output vulnerable hosts
	with open(f"{ENUM_DIR}/ldap_null_hosts.txt", "w") as f:
		for host in ldap_null_hosts:
			f.write(f"{host}\n")
	if ldap_null_hosts:
		print_warning("The following hosts allow LDAP null binds:")
		for host in ldap_null_hosts:
			print_info(f"  {host}")
		print_info(f"Results saved to {ENUM_DIR}/ldap_null_hosts.txt")

	print_success("LDAP null bind enumeration complete!")
 
	# Top 1000 TCP scan without service detection
	print_info("Running top 1000 TCP scan...")
	tcp_scan_cmd = f"nmap {NMAP_COMMON} -sS --open -oA {ENUM_DIR}/top_1000_tcp_scan -iL {ENUM_DIR}/output_file"
	os.system(tcp_scan_cmd)
	print_success("Top 1000 TCP scan complete!")
	
	# Scanning common web ports 80,443,8000-8002,8080-8089,8443,3000-3001,5000-5001,9000-9001,81,88,8008,8081,8888,9443,7443,7080,7081,8889,8983,9999,4000,4567,6060,6066,6068,9090,9292,7000-7001,4848,5985,10000
	print_info("Scanning common web ports...")
	web_ports = "80,443,8000-8002,8080-8089,8443,3000-3001,5000-5001,9000-9001,81,88,8008,8081,8888,9443,7443,7080,7081,8889,8983,9999,4000,4567,6060,6066,6068,9090,9292,7000-7001,4848,5985,10000"
	web_scan_cmd = f"nmap {NMAP_COMMON} -sS --open -p {web_ports} -oA {ENUM_DIR}/web_scan -iL {ENUM_DIR}/output_file"
	os.system(web_scan_cmd)
	print_success("Common web ports scan complete!")
 
	# Parse all Nmap scan results utilizing ultimate-nmap-parser
	print_info("Parsing all Nmap scan results utilizing ultimate-nmap-parser...")

	# Create parser output directory
	parser_output_dir = f"{ENUM_DIR}/nmap_parsed"
	os.makedirs(parser_output_dir, exist_ok=True)

	# Use absolute paths for both the parser and the scan results
	parser_path = f"{TOOLS_DIR}/general/ultimate-nmap-parser/ultimate-nmap-parser.sh"
	os.chmod(parser_path, 0o755)  # Make executable with rwxr-xr-x permissions
	scan_results = f"{ENUM_DIR}/*.gnmap"

	# Execute parser from ENUM_DIR with absolute paths
	os.chdir(f"{ENUM_DIR}/nmap_parsed")
	os.system(f"{parser_path} {scan_results} --all")

	print_success(f"All Nmap scan results parsed and saved to {parser_output_dir}!")
 
 
	# # UDP scan for common ports
	# print_info("Running UDP scan for common ports...")
	# udp_ports = "53,69,111,123,137,138,161,162,500,514,520,623,1434,1900,5353"
	# udp_scan_cmd = f"nmap {NMAP_COMMON} -sU -sV --version-intensity 5 --open -p {udp_ports} -oA {ENUM_DIR}/udp_scan -iL {ENUM_DIR}/output_file"
	# os.system(udp_scan_cmd)
	
	print_success("Phase 2 complete - Port scanning finished 🔍 - TOP 1000 TCP, WEB PORTS, AND NULL BINDS (RPC, LDAP, SMB) scan complete! 🔍")

def parse_args():
	parser = argparse.ArgumentParser()

	parser.add_argument("-s", "--scope", type=str,
			help="The scope.txt file.")
	parser.add_argument("-e", "--exclude", type=str,
			   help="Exclude your own IP to avoid messing things up while relaying on internal networks!")
	return parser.parse_args()

def enumerate_services():
	print_info("Starting service-specific enumeration...")
	os.chdir(ENUM_DIR)

	# FTP Enumeration with standardized Nmap parameters
	if os.path.exists(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_21-ftp.txt") and os.path.getsize(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_21-ftp.txt") > 0:
		print_info("Enumerating FTP targets...")
		# Create FTP scan resource script
		ftp_resource = f"{ENUM_DIR}/ftp_scan.rc"
		with open(ftp_resource, "w") as f:
			f.write(f"""
use auxiliary/scanner/ftp/anonymous
set RHOSTS file:{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_21-ftp.txt
set THREADS 10
set VERBOSE true
spool {ENUM_DIR}/ftp_anonymous_scan.txt
run
spool off
exit
""")
		
		# Run Metasploit FTP scan
		print_info("Running Metasploit FTP anonymous scan...")
		os.system(f"msfconsole -q -r {ftp_resource}")
	# VNC Enumeration
	if os.path.exists(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_5900-vnc.txt") and os.path.getsize(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_5900-vnc.txt") > 0:
		print_info("Enumerating VNC targets...")
		# Create VNC scan resource script
		vnc_resource = f"{ENUM_DIR}/vnc_scan.rc"
		with open(vnc_resource, "w") as f:
			f.write(f"""
use auxiliary/scanner/vnc/vnc_none_auth
set RHOSTS file:{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_5900-vnc.txt
set THREADS 10
set VERBOSE true
spool {ENUM_DIR}/vnc_noauth_scan.txt
run
spool off
exit
""")
		
		# Run Metasploit VNC scan
		print_info("Running Metasploit VNC no auth scan...")
		os.system(f"msfconsole -q -r {vnc_resource}")


	# NFS Enumeration
	if os.path.exists(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_2049-nfs.txt") and os.path.getsize(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_2049-nfs.txt") > 0:
		print_info("Enumerating NFS targets...")
		with open(f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_2049-nfs.txt", "r") as f:
			nfs_hosts = [line.strip() for line in f]
		
		with open(f"{ENUM_DIR}/nfs_shares.txt", "w") as outfile:
			for host in nfs_hosts:
				print_info(f"Checking NFS mounts on {host}...")
				try:
					result = subprocess.run(["showmount", "-e", host], capture_output=True, text=True, timeout=30)
					outfile.write(f"\nNFS Shares on {host}:\n")
					outfile.write(result.stdout)
				except subprocess.TimeoutExpired:
					print_warning(f"Timeout while checking NFS on {host}")
				except Exception as e:
					print_error(f"Error checking NFS on {host}: {str(e)}")


	# SNMP Enumeration
	if os.path.exists(f"{ENUM_DIR}/targets_snmp.txt") and os.path.getsize(f"{ENUM_DIR}/targets_snmp.txt") > 0:
		print_info("Enumerating SNMP targets...")
		os.system(f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-community-strings.txt -i {ENUM_DIR}/targets_snmp.txt > {ENUM_DIR}/snmp_communities.txt")
		os.system(f"snmpwalk -v1 -c public $(head -n 1 {ENUM_DIR}/targets_snmp.txt) > {ENUM_DIR}/snmp_walk.txt")

	# Web Enumeration with Nuclei
	web_urls_file = f"{ENUM_DIR}/nmap_parsed/parse/web-urls.txt"
	if os.path.exists(web_urls_file) and os.path.getsize(web_urls_file) > 0:
		print_info("Running Nuclei web scans...")
		
		# Create output directory for Nuclei results
		nuclei_output_dir = f"{ENUM_DIR}/nuclei_results"
		os.makedirs(nuclei_output_dir, exist_ok=True)
		
		# Run Nuclei with common templates
		nuclei_cmd = f"{TOOLS_DIR}/nuclei -l {web_urls_file} -o {nuclei_output_dir}/nuclei_scan.txt"
		print_info("Running Nuclei vulnerability scan...")
		os.system(nuclei_cmd)
		
		# Check if any results were found
		if os.path.exists(f"{nuclei_output_dir}/nuclei_scan.txt"):
			print_success("Nuclei scan completed - Check results in nuclei_results/nuclei_scan.txt")
		else:
			print_warning("No Nuclei findings")
	print_success("Service enumeration complete! Check the enumeration directory for results.")

def create_msf_resource_script(target_file, output_dir):
    """Create a Metasploit resource script for SMB scanning"""
    resource_script = f"{output_dir}/smb_scan.rc"
    
    # Create module-specific output directory
    msf_output_dir = f"{output_dir}/msf_module_output"
    os.makedirs(msf_output_dir, exist_ok=True)
    
    with open(resource_script, "w") as f:
        f.write(f"""
# Set global options
setg THREADS 10
setg VERBOSE true

# SMB Version Detection
use auxiliary/scanner/smb/smb_version
set RHOSTS file:{target_file}
set VERBOSE true
spool {msf_output_dir}/smb_version.txt
run
spool off

# SMB Login Scan
use auxiliary/scanner/smb/smb_login
set RHOSTS file:{target_file}
set SMBUser ''
set SMBPass ''
set VERBOSE true
spool {msf_output_dir}/smb_login.txt
run
spool off

# SMB MS17-010 Scanner
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS file:{target_file}
set VERBOSE true
spool {msf_output_dir}/smb_ms17_010.txt
run
spool off

# SMB Pipe Auditor
use auxiliary/scanner/smb/pipe_auditor
set RHOSTS file:{target_file}
set VERBOSE true
spool {msf_output_dir}/smb_pipe_audit.txt
run
spool off

# SMB Share Enumeration
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS file:{target_file}
set ShowFiles true
set SpiderShares false
set VERBOSE true
spool {msf_output_dir}/smb_shares.txt
run
spool off

# BlueKeep Scanner (CVE-2019-0708)
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS file:{target_file}
set RDP_CLIENT_IP 192.168.1.1
set VERBOSE true
spool {msf_output_dir}/bluekeep_scan.txt
run
spool off

# DoublePulsar SMB Scanner
use auxiliary/scanner/smb/smb_ms17_010_scan
set RHOSTS file:{target_file}
set CHECK_ARCH true
set CHECK_DOPU true
set VERBOSE true
spool {msf_output_dir}/doublepulsar_scan.txt
run
spool off

# SMBGhost Scanner (CVE-2020-0796)
use auxiliary/scanner/smb/smb_ghostcat
set RHOSTS file:{target_file}
set VERBOSE true
spool {msf_output_dir}/smbghost_scan.txt
run
spool off

# MS12-020 RDP Scanner
use auxiliary/scanner/rdp/ms12_020_check
set RHOSTS file:{target_file}
set VERBOSE true
spool {msf_output_dir}/ms12_020_scan.txt
run
spool off

exit
""")
    return resource_script, msf_output_dir

def run_msf_scan(target_file, output_dir):
    """Run Metasploit SMB scans using resource script"""
    print_info("Starting Metasploit SMB and RDP vulnerability scans...")
    
    # Create resource script and get output directory
    resource_script, msf_output_dir = create_msf_resource_script(target_file, output_dir)
    
    # Run Metasploit with resource script
    msf_output = f"{output_dir}/msf_vulnerability_scan.txt"
    msf_cmd = f"msfconsole -q -r {resource_script} | tee {msf_output}"
    
    try:
        # Check if msfconsole is available
        subprocess.run(["msfconsole", "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print_info("Running Metasploit scans (this may take a while)...")
        os.system(msf_cmd)
        print_success("Metasploit vulnerability scans completed!")
        
        # Create a consolidated report from individual module outputs
        try:
            with open(f"{output_dir}/msf_consolidated_report.txt", "w") as report:
                report.write("Metasploit Scan Consolidated Report\n")
                report.write("================================\n\n")
                
                # List of all module output files and their descriptions
                modules = {
                    "smb_version.txt": "SMB Version Detection",
                    "smb_login.txt": "SMB Null Session Check",
                    "smb_ms17_010.txt": "EternalBlue (MS17-010) Check",
                    "smb_pipe_audit.txt": "SMB Pipe Audit",
                    "smb_shares.txt": "SMB Share Enumeration",
                    "bluekeep_scan.txt": "BlueKeep Vulnerability Check",
                    "doublepulsar_scan.txt": "DoublePulsar Backdoor Check",
                    "smbghost_scan.txt": "SMBGhost Vulnerability Check",
                    "ms12_020_scan.txt": "MS12-020 RDP Vulnerability Check"
                }
                
                # Process each module's output
                for filename, description in modules.items():
                    module_file = f"{msf_output_dir}/{filename}"
                    if os.path.exists(module_file):
                        report.write(f"\n{description}\n")
                        report.write("=" * len(description) + "\n")
                        
                        with open(module_file, "r") as f:
                            content = f.read().strip()
                            if content:
                                report.write(content + "\n")
                            else:
                                report.write("No findings\n")
                
                print_success(f"Consolidated report saved to {output_dir}/msf_consolidated_report.txt")
                
            # Parse results for specific vulnerabilities
            vulnerabilities = {
                "BlueKeep": "VULNERABLE - CVE-2019-0708",
                "DoublePulsar": "VULNERABLE - DOUBLEPULSAR",
                "SMBGhost": "VULNERABLE - CVE-2020-0796",
                "MS12-020": "VULNERABLE - MS12-020",
                "EternalBlue": "VULNERABLE - MS17-010"
            }
            
            with open(f"{output_dir}/critical_vulnerabilities.txt", "w") as vuln_f:
                vuln_f.write("Critical Vulnerabilities Found\n")
                vuln_f.write("===========================\n\n")
                
                for module_file in os.listdir(msf_output_dir):
                    with open(f"{msf_output_dir}/{module_file}", "r") as f:
                        content = f.read()
                        for vuln_name, vuln_string in vulnerabilities.items():
                            if vuln_string in content:
                                print_error(f"Found {vuln_name} vulnerable hosts!")
                                vuln_f.write(f"\n{vuln_name} Vulnerable Hosts:\n")
                                for line in content.splitlines():
                                    if vuln_string in line:
                                        ip = line.split()[0]
                                        vuln_f.write(f"  - {ip}\n")
                                        print_warning(f"Host vulnerable to {vuln_name}: {ip}")
                
        except Exception as e:
            print_error(f"Error processing module outputs: {str(e)}")
        
        return True, msf_output_dir
    except FileNotFoundError:
        print_warning("Metasploit not found - skipping Metasploit vulnerability scans")
        return False, None

def scan_smb_vulnerabilities():
    print_info("Starting targeted SMB vulnerability scans...")
    
    # Use parsed Nmap output for SMB targets
    smb_targets = f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_445-microsoft-ds.txt"
    if not os.path.exists(smb_targets) or os.path.getsize(smb_targets) == 0:
        print_warning("No SMB targets found to scan")
        return

    # Create directory for SMB vulnerability scan results
    smb_vuln_dir = f"{ENUM_DIR}/smb_vulnerabilities"
    os.makedirs(smb_vuln_dir, exist_ok=True)

    # NSE script categories for SMB vulnerability scanning
    smb_scripts = [
        # Version detection and basic info
        "smb-protocols,smb-security-mode,smb2-capabilities,smb2-security-mode",
        # Security issues and vulnerabilities
        "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103",
        # Configuration and security checks
        "smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups,smb-enum-services",
        # Additional checks
        "smb-double-pulsar-backdoor,smb-os-discovery"
    ]

    # Run each script category separately for better organization
    for scripts in smb_scripts:
        script_name = scripts.split(',')[0]  # Use first script name for file naming
        print_info(f"Running {script_name} and related checks...")
        
        try:
            scan_cmd = f"nmap {NMAP_COMMON} -p445 --open --script={scripts} -oA {smb_vuln_dir}/smb_vuln_{script_name} -iL {smb_targets}"
            subprocess.run(scan_cmd, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            print_error(f"Error running {script_name} scan: {str(e)}")
            continue

    # Run Metasploit scans if available
    msf_success, msf_output_dir = run_msf_scan(smb_targets, smb_vuln_dir)

    # Parse results for vulnerable hosts
    print_info("Analyzing scan results...")
    
    try:
        # Create summary report
        with open(f"{smb_vuln_dir}/smb_vulnerability_summary.txt", "w") as summary:
            summary.write("SMB Vulnerability Scan Summary\n")
            summary.write("============================\n\n")
            
            # Process NSE script results
            for scripts in smb_scripts:
                script_name = scripts.split(',')[0]
                nmap_file = f"{smb_vuln_dir}/smb_vuln_{script_name}.nmap"
                
                if os.path.exists(nmap_file):
                    with open(nmap_file, "r") as f:
                        content = f.read()
                        summary.write(f"\n{script_name} Results:\n")
                        summary.write("=" * (len(script_name) + 9) + "\n")
                        
                        # Extract relevant findings
                        for line in content.splitlines():
                            if any(x in line.lower() for x in ["vulnerable", "warning", "critical", "exposed"]):
                                summary.write(f"{line}\n")
            
            # Add Metasploit results if available
            if msf_success and msf_output_dir:
                summary.write("\nMetasploit Scan Results\n")
                summary.write("=====================\n")
                
                # Process each module's output
                for module_file in os.listdir(msf_output_dir):
                    if module_file.endswith(".txt"):
                        with open(f"{msf_output_dir}/{module_file}", "r") as f:
                            content = f.read().strip()
                            if content:
                                summary.write(f"\n{module_file} Results:\n")
                                summary.write(content + "\n")

        print_success(f"Vulnerability summary saved to {smb_vuln_dir}/smb_vulnerability_summary.txt")
        
        # Create critical vulnerabilities report
        with open(f"{smb_vuln_dir}/critical_vulnerabilities.txt", "w") as vuln_f:
            vuln_f.write("Critical SMB Vulnerabilities Found\n")
            vuln_f.write("==============================\n\n")
            
            vulnerabilities = {
                "MS17-010": "VULNERABLE - MS17-010",
                "DoublePulsar": "VULNERABLE - DOUBLEPULSAR",
                "SMBv1": "SMBv1 Protocol enabled",
                "Unsigned SMB": "Message signing disabled",
                "Anonymous Access": "Anonymous access allowed"
            }
            
            for vuln_name, vuln_string in vulnerabilities.items():
                found_hosts = set()
                
                # Check both NSE and Metasploit results
                for root, _, files in os.walk(smb_vuln_dir):
                    for file in files:
                        if file.endswith((".nmap", ".txt")):
                            try:
                                with open(os.path.join(root, file), "r") as f:
                                    content = f.read()
                                    if vuln_string.lower() in content.lower():
                                        for line in content.splitlines():
                                            if vuln_string.lower() in line.lower():
                                                # Extract IP address using regex
                                                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                                                if ip_match:
                                                    found_hosts.add(ip_match.group())
                            except Exception as e:
                                print_error(f"Error processing {file}: {str(e)}")
                                continue
                
                if found_hosts:
                    vuln_f.write(f"\n{vuln_name} Vulnerable Hosts:\n")
                    for host in sorted(found_hosts):
                        vuln_f.write(f"  - {host}\n")
                        print_warning(f"Host {host} vulnerable to {vuln_name}")

        print_success("SMB vulnerability scanning complete! 🎯")
        
    except Exception as e:
        print_error(f"Error creating vulnerability reports: {str(e)}")
        return False

    return True

def main():
	args = parse_args()
	scope = args.scope
	exclude = args.exclude
	
	printBanner()
	makedir()
	downloadtooling([])
	invokescan(scope, exclude)
	enumerate_services()
	scan_smb_vulnerabilities()
	print_success("All tasks completed successfully! ✅")

if __name__ == '__main__':
	main()
