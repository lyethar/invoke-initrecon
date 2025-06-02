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

def is_subnet(ip_string):
    """Check if the string represents a subnet (CIDR notation or with wildcards)"""
    return '/' in ip_string or '*' in ip_string

def analyze_scope_file(scope_file):
    """Analyze scope file to determine if it contains subnets or individual IPs"""
    subnets = []
    individual_ips = []
    
    with open(scope_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line:  # Skip empty lines
                continue
            if is_subnet(line):
                subnets.append(line)
            else:
                individual_ips.append(line)
    
    return subnets, individual_ips

def invokescan(scope, exclude):
    os.chdir(ENUM_DIR)
    print_info("Starting network enumeration...")
    
    # Analyze scope file
    subnets, individual_ips = analyze_scope_file(scope)
    
    # Create output file for discovered hosts
    output_file = f"{ENUM_DIR}/open_ports.txt"
    if os.path.exists(output_file):
        os.remove(output_file)

    if subnets:
        print_info("Subnet ranges detected - Starting with quick discovery scan...")
        # Initial host discovery and quick port scan for subnets
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
        
        print_success("Quick discovery finished - Check live hosts in open_ports.txt")
        
        # Combine discovered IPs with individual IPs from scope
        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                discovered_ips = set(line.strip() for line in f)
            individual_ips.extend(discovered_ips)
    
    # Remove duplicates and write final IP list
    individual_ips = list(set(individual_ips))
    with open(output_file, "w") as f:
        for ip in individual_ips:
            f.write(ip + "\n")
    
    if not individual_ips:
        print_error("No live hosts found to scan!")
        return
    
    print_info(f"Starting detailed scans against {len(individual_ips)} hosts...")
    
    # Domain service ports scan (88, 135, 389, 445)
    domain_ports = [88, 135, 389, 445]
    print_info("Scanning domain service ports (88, 135, 389, 445)...")
    domain_ports_str = ",".join(map(str, domain_ports))
    domain_scan_cmd = f"nmap {NMAP_COMMON} -sS --open -p {domain_ports_str} -oA {ENUM_DIR}/domain_services -iL {output_file}"
    os.system(domain_scan_cmd)
    
    # Parse results for each port
    for port in domain_ports:
        print_info(f"Extracting hosts with port {port} open...")
        os.system(f"""grep "{port}/open" {ENUM_DIR}/domain_services.gnmap | cut -d" " -f2 > {ENUM_DIR}/targets_port_{port}.txt""")
        
        # Map ports to services
        if port == 88:
            os.system(f"cp {ENUM_DIR}/targets_port_88.txt {ENUM_DIR}/targets_kerberos.txt")
        elif port == 135:
            os.system(f"cp {ENUM_DIR}/targets_port_135.txt {ENUM_DIR}/targets_rpc.txt")
        elif port == 389:
            os.system(f"cp {ENUM_DIR}/targets_port_389.txt {ENUM_DIR}/targets_ldap.txt") 
        elif port == 445:
            os.system(f"cp {ENUM_DIR}/targets_port_445.txt {ENUM_DIR}/targets_smb.txt")
    
    # Identify domain controllers
    print_info("Identifying domain controllers...")
    try:
        with open(f"{ENUM_DIR}/targets_port_88.txt", "r") as f:
            kerberos_hosts = set(line.strip() for line in f)
        with open(f"{ENUM_DIR}/targets_port_389.txt", "r") as f:
            ldap_hosts = set(line.strip() for line in f)
        
        domain_controllers = kerberos_hosts.intersection(ldap_hosts)
        if domain_controllers:
            with open(f"{ENUM_DIR}/targets_domain_controllers.txt", "w") as f:
                for dc in domain_controllers:
                    f.write(f"{dc}\n")
            print_success(f"Found {len(domain_controllers)} domain controllers")
    except FileNotFoundError:
        print_warning("Could not identify domain controllers - required service ports not found")
    
    # Top 1000 TCP scan
    print_info("Running top 1000 TCP port scan...")
    tcp_scan_cmd = f"nmap {NMAP_COMMON} -sS --open -oA {ENUM_DIR}/top_1000_tcp_scan -iL {output_file}"
    os.system(tcp_scan_cmd)
    
    # Web ports scan
    print_info("Scanning common web ports...")
    web_ports = "80,443,8000-8002,8080-8089,8443,3000-3001,5000-5001,9000-9001,81,88,8008,8081,8888,9443,7443,7080,7081,8889,8983,9999,4000,4567,6060,6066,6068,9090,9292,7000-7001,4848,5985,10000"
    web_scan_cmd = f"nmap {NMAP_COMMON} -sS --open -p {web_ports} -oA {ENUM_DIR}/web_scan -iL {output_file}"
    os.system(web_scan_cmd)
    
    # Parse all Nmap scan results
    print_info("Parsing all Nmap scan results...")
    parser_output_dir = f"{ENUM_DIR}/nmap_parsed"
    os.makedirs(parser_output_dir, exist_ok=True)
    parser_path = f"{TOOLS_DIR}/general/ultimate-nmap-parser/ultimate-nmap-parser.sh"
    os.chmod(parser_path, 0o755)
    scan_results = f"{ENUM_DIR}/*.gnmap"
    os.chdir(f"{ENUM_DIR}/nmap_parsed")
    os.system(f"{parser_path} {scan_results} --all")
    
    scan_summary = f"""
Scan Summary:
============
Total Hosts: {len(individual_ips)}
Domain Controllers: {len(domain_controllers) if 'domain_controllers' in locals() else 0}
Scan Results: {parser_output_dir}
"""
    print_info(scan_summary)
    
    with open(f"{ENUM_DIR}/scan_summary.txt", "w") as f:
        f.write(scan_summary)
    
    print_success("Phase 2 complete - Port scanning finished 🔍 - TOP 1000 TCP, WEB PORTS, AND NULL BINDS (RPC, LDAP, SMB) scan complete! 🔍")

def parse_args():
    parser = argparse.ArgumentParser(description="Network reconnaissance tool supporting both subnet ranges and IP lists")
    parser.add_argument("-s", "--scope", type=str, required=True,
                    help="Scope file containing either subnet ranges (CIDR notation) or individual IP addresses")
    parser.add_argument("-e", "--exclude", type=str, required=True,
                    help="IP address to exclude from scans (e.g., your attacking machine)")
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
    smb_targets = f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_445-smb.txt"
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
