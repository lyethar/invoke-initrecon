#!/bin/python3

import sys
import shutil
import subprocess
import os
import argparse
import re
from colorama import Fore, Style

BASE_DIR = "/opt/initrecon"
TOOLS_DIR = f"{BASE_DIR}/tools"
ENUM_DIR = f"{BASE_DIR}/enumeration"
EXPLOIT_DIR = f"{BASE_DIR}/exploitation"
POST_DIR = f"{BASE_DIR}/post-exploitation"

INFO = Fore.BLUE
SUCCESS = Fore.GREEN
ERROR = Fore.RED
WARNING = Fore.YELLOW
RESET = Style.RESET_ALL

NMAP_STANDARD_OPTS = "-n -Pn"
NMAP_TIMING = "-T3"
NMAP_RATE = "--max-rate 1000"
NMAP_RETRIES = "--max-retries 1"
NMAP_HOST_TIMEOUT = "--host-timeout 2m"
NMAP_EXTRA = "--defeat-rst-ratelimit"
NMAP_OUTPUT = "-vv"

NMAP_COMMON = f"{NMAP_STANDARD_OPTS} {NMAP_TIMING} {NMAP_RATE} {NMAP_RETRIES} {NMAP_HOST_TIMEOUT} {NMAP_EXTRA} {NMAP_OUTPUT}"


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


def printBanner():
    print(Fore.YELLOW + """   ________  ________  ________  ________  ____ ___  ________   ________  ________   ________  ________   _______  ________  ________  ________  ________
  /        \/    /   \/    /   \/        \/    /   \/        \ /        \/    /   \ /        \/        \//       \/        \/        \/        \/    /   \
 _/       //         /         /         /         /         /_/       //         /_/       //        _//        /         /         /         /         /
/         /         /\        /         /        _/        _//         /         //         //       //        _/        _/       --/         /         /
\\_______/\__/_____/  \______/\________/\____/___/\________/ \\_______/\__/_____/ \________/ \______/ \____/___/\________/\________/\________/\__/_____/  \n\n\n """)
    print(Style.RESET_ALL)


def makedir():
    directories = [BASE_DIR, TOOLS_DIR, ENUM_DIR, EXPLOIT_DIR, POST_DIR]
    for path in directories:
        subprocess.run(["sudo", "mkdir", "-p", path], check=True)
        subprocess.run(["sudo", "chmod", "755", path], check=True)
    print_success("Base directories created")


def downloadtooling():
    print_info("Downloading and setting up enumeration tools...")
    print_info("Updating system...")
    os.system("sudo apt update && sudo apt install -y enum4linux nbtscan onesixtyone snmp-mibs-downloader seclists")

    categories = ["smb", "ldap", "ftp", "general", "web"]
    for category in categories:
        os.makedirs(f"{TOOLS_DIR}/{category}", exist_ok=True)

    print_info("Downloading tools...")
    os.system(f"wget -q https://raw.githubusercontent.com/lyethar/invoke-initrecon/main/better_default.rc -O {TOOLS_DIR}/better_default.rc")
    os.system(f"wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.4.4/nuclei_3.4.4_linux_amd64.zip -O {TOOLS_DIR}/nuclei.zip && cd {TOOLS_DIR} && unzip -q nuclei.zip && rm nuclei.zip")
    os.system(f"wget -q https://github.com/sensepost/gowitness/releases/download/3.0.5/gowitness-3.0.5-linux-amd64 -O {TOOLS_DIR}/gowitness")
    os.system(f"chmod +x {TOOLS_DIR}/gowitness {TOOLS_DIR}/nuclei")

    tool_mapping = {
        "smb": [
            "https://github.com/lefayjey/linWinPwn",
            "https://github.com/lgandx/Responder",
            "https://github.com/Pennyw0rth/NetExec",
            "https://github.com/dirkjanm/mitm6",
        ],
        "ldap": [
            "https://github.com/lyethar/KerbSpray",
            "https://github.com/ropnop/windapsearch",
            "https://github.com/dirkjanm/ldapdomaindump",
        ],
        "ftp": [
            "https://github.com/danielmiessler/SecLists",
        ],
        "general": [
            "https://github.com/robertdavidgraham/masscan",
            "https://github.com/shifty0g/ultimate-nmap-parser",
            "https://github.com/s4vitar/rpcenum",
            "https://github.com/jtesta/ssh-audit",
        ],
    }

    for category, repos in tool_mapping.items():
        category_path = f"{TOOLS_DIR}/{category}"
        for repo in repos:
            repo_name = repo.split("/")[-1]
            dest = f"{category_path}/{repo_name}"
            if not os.path.exists(dest):
                subprocess.run(["git", "clone", "--quiet", repo, dest])

    print_success("Tool setup complete!")


def is_subnet(ip_string):
    return "/" in ip_string or "*" in ip_string


def analyze_scope_file(scope_file):
    if not os.path.isfile(scope_file):
        print_error(f"Scope file not found: {scope_file}")
        sys.exit(1)

    subnets = []
    individual_ips = []
    with open(scope_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if is_subnet(line):
                subnets.append(line)
            else:
                individual_ips.append(line)
    return subnets, individual_ips


def _run_nmap(args, label="nmap"):
    """Run nmap with the given argument list; log errors without crashing."""
    cmd = ["nmap"] + args
    try:
        return subprocess.run(cmd, capture_output=False, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print_error(f"{label} failed (exit {e.returncode})")
        return None
    except FileNotFoundError:
        print_error("nmap not found — install it and retry")
        sys.exit(1)


def invokescan(scope, exclude):
    os.makedirs(ENUM_DIR, exist_ok=True)

    exclude_flag = "--excludefile" if os.path.isfile(exclude) else "--exclude"
    print_info(f"Using {exclude_flag}: {exclude}")

    subnets, individual_ips = analyze_scope_file(scope)
    output_file = f"{ENUM_DIR}/open_ports.txt"

    if os.path.exists(output_file):
        os.remove(output_file)

    if subnets:
        print_info("Subnet ranges detected — starting quick discovery scan...")
        for subnet in subnets:
            print_info(f"Scanning subnet {subnet}...")
            result = subprocess.run(
                ["nmap"] + NMAP_COMMON.split() + [
                    "-sS", "--top-ports", "20", "--open",
                    exclude_flag, exclude, "--", subnet,
                ],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print_warning(f"Quick scan of {subnet} returned non-zero exit code")

            discovered = [
                line.split()[4]
                for line in result.stdout.splitlines()
                if "Nmap scan report for" in line
            ]
            if discovered:
                print_success(f"Found {len(discovered)} live host(s) in {subnet}")
                with open(output_file, "a") as f:
                    f.write("\n".join(discovered) + "\n")

        if os.path.exists(output_file):
            with open(output_file) as f:
                individual_ips.extend(line.strip() for line in f if line.strip())

    individual_ips = sorted(set(individual_ips))
    with open(output_file, "w") as f:
        f.write("\n".join(individual_ips) + "\n")

    if not individual_ips:
        print_error("No live hosts found — aborting detailed scans")
        return

    print_info(f"Starting detailed scans against {len(individual_ips)} host(s)...")

    # Domain services (Kerberos, RPC, LDAP, SMB, IPMI)
    domain_ports = [88, 135, 389, 445, 623]
    domain_ports_str = ",".join(map(str, domain_ports))
    print_info(f"Scanning domain service ports ({domain_ports_str})...")
    os.system(
        f"nmap {NMAP_COMMON} -sS --open -p {domain_ports_str} "
        f"-oA {ENUM_DIR}/domain_services -iL {output_file}"
    )

    port_aliases = {88: "kerberos", 135: "rpc", 389: "ldap", 445: "smb", 623: "ipmi"}
    for port in domain_ports:
        out = f"{ENUM_DIR}/targets_port_{port}.txt"
        os.system(f'grep "{port}/open" {ENUM_DIR}/domain_services.gnmap | cut -d" " -f2 > {out}')
        alias = port_aliases.get(port)
        if alias:
            os.system(f"cp {out} {ENUM_DIR}/targets_{alias}.txt")

    # Identify domain controllers (port 88 + 389)
    domain_controllers: set[str] = set()
    try:
        with open(f"{ENUM_DIR}/targets_port_88.txt") as f:
            kerberos_hosts = {line.strip() for line in f if line.strip()}
        with open(f"{ENUM_DIR}/targets_port_389.txt") as f:
            ldap_hosts = {line.strip() for line in f if line.strip()}
        domain_controllers = kerberos_hosts & ldap_hosts
        if domain_controllers:
            with open(f"{ENUM_DIR}/targets_domain_controllers.txt", "w") as f:
                f.write("\n".join(sorted(domain_controllers)) + "\n")
            print_success(f"Found {len(domain_controllers)} domain controller(s)")
    except FileNotFoundError:
        print_warning("Could not identify domain controllers — required port files missing")

    # Top 1000 TCP scan
    print_info("Running top-1000 TCP port scan...")
    os.system(f"nmap {NMAP_COMMON} -sS --open -oA {ENUM_DIR}/top_1000_tcp_scan -iL {output_file}")

    # Web ports scan
    web_ports = (
        "80,443,8000-8002,8080-8089,8443,3000-3001,5000-5001,"
        "9000-9001,81,88,8008,8081,8888,9443,7443,7080,7081,"
        "8889,8983,9999,4000,4567,6060,6066,6068,9090,9292,"
        "7000-7001,4848,5985,10000"
    )
    print_info("Scanning common web ports...")
    os.system(
        f"nmap {NMAP_COMMON} -sS --open -p {web_ports} "
        f"-oA {ENUM_DIR}/web_scan -iL {output_file}"
    )

    # Parse all nmap results
    print_info("Parsing nmap scan results...")
    parser_output_dir = f"{ENUM_DIR}/nmap_parsed"
    os.makedirs(parser_output_dir, exist_ok=True)
    parser_path = f"{TOOLS_DIR}/general/ultimate-nmap-parser/ultimate-nmap-parser.sh"
    if os.path.exists(parser_path):
        os.chmod(parser_path, 0o755)
        subprocess.run(
            [parser_path, f"{ENUM_DIR}/*.gnmap", "--all"],
            cwd=parser_output_dir,
        )
    else:
        print_warning(f"ultimate-nmap-parser not found at {parser_path} — skipping parse step")

    scan_summary = (
        f"\nScan Summary:\n{'=' * 13}\n"
        f"Total Hosts:        {len(individual_ips)}\n"
        f"Domain Controllers: {len(domain_controllers)}\n"
        f"Scan Results:       {parser_output_dir}\n"
    )
    print_info(scan_summary)
    with open(f"{ENUM_DIR}/scan_summary.txt", "w") as f:
        f.write(scan_summary)

    print_success("Phase 2 complete — TOP 1000 TCP, WEB PORTS, and DOMAIN SERVICES scan done!")


def enumerate_services():
    print_info("Starting service-specific enumeration...")

    def _host_file(rel_path):
        full = f"{ENUM_DIR}/nmap_parsed/parse/hosts/{rel_path}"
        return full if os.path.exists(full) and os.path.getsize(full) > 0 else None

    # FTP — anonymous access
    ftp_file = _host_file("tcp_21-ftp.txt")
    if ftp_file:
        print_info("Enumerating FTP targets...")
        ftp_resource = f"{ENUM_DIR}/ftp_scan.rc"
        with open(ftp_resource, "w") as f:
            f.write(
                f"use auxiliary/scanner/ftp/anonymous\n"
                f"set RHOSTS file:{ftp_file}\n"
                f"set THREADS 10\n"
                f"set VERBOSE true\n"
                f"spool {ENUM_DIR}/ftp_anonymous_scan.txt\n"
                f"run\nspool off\nexit\n"
            )
        os.system(f"msfconsole -q -r {ftp_resource}")

    # VNC — no-auth check
    vnc_file = _host_file("tcp_5900-vnc.txt")
    if vnc_file:
        print_info("Enumerating VNC targets...")
        vnc_resource = f"{ENUM_DIR}/vnc_scan.rc"
        with open(vnc_resource, "w") as f:
            f.write(
                f"use auxiliary/scanner/vnc/vnc_none_auth\n"
                f"set RHOSTS file:{vnc_file}\n"
                f"set THREADS 10\n"
                f"set VERBOSE true\n"
                f"spool {ENUM_DIR}/vnc_noauth_scan.txt\n"
                f"run\nspool off\nexit\n"
            )
        os.system(f"msfconsole -q -r {vnc_resource}")

    # NFS — showmount
    nfs_file = _host_file("tcp_2049-nfs.txt")
    if nfs_file:
        print_info("Enumerating NFS targets...")
        with open(nfs_file) as f:
            nfs_hosts = [line.strip() for line in f if line.strip()]
        with open(f"{ENUM_DIR}/nfs_shares.txt", "w") as outfile:
            for host in nfs_hosts:
                print_info(f"Checking NFS mounts on {host}...")
                try:
                    result = subprocess.run(
                        ["showmount", "-e", "--", host],
                        capture_output=True, text=True, timeout=30,
                    )
                    outfile.write(f"\nNFS Shares on {host}:\n{result.stdout}")
                except subprocess.TimeoutExpired:
                    print_warning(f"Timeout checking NFS on {host}")
                except Exception as exc:
                    print_error(f"Error checking NFS on {host}: {exc}")

    # SNMP — community string brute-force
    snmp_file = _host_file("tcp_161-snmp.txt")
    if snmp_file:
        print_info("Enumerating SNMP targets...")
        snmp_wordlist = "/usr/share/seclists/Discovery/SNMP/snmp-community-strings.txt"
        os.system(f"onesixtyone -c {snmp_wordlist} -i {snmp_file} > {ENUM_DIR}/snmp_communities.txt")
        os.system(f"snmpwalk -v1 -c public $(head -n 1 {snmp_file}) > {ENUM_DIR}/snmp_walk.txt")

    # IPMI
    ipmi_targets = f"{ENUM_DIR}/targets_ipmi.txt"
    if os.path.exists(ipmi_targets) and os.path.getsize(ipmi_targets) > 0:
        print_info("Enumerating IPMI targets...")
        ipmi_resource = f"{ENUM_DIR}/ipmi_scan.rc"
        with open(ipmi_resource, "w") as f:
            f.write(
                f"use auxiliary/scanner/ipmi/ipmi_cipher_zero\n"
                f"set RHOSTS file:{ipmi_targets}\n"
                f"set THREADS 20\n"
                f"spool {ENUM_DIR}/ipmi_cipher_zero.txt\n"
                f"run\nspool off\n\n"
                f"use auxiliary/scanner/ipmi/ipmi_dumphashes\n"
                f"set RHOSTS file:{ipmi_targets}\n"
                f"set THREADS 20\n"
                f"spool {ENUM_DIR}/ipmi_dumphashes.txt\n"
                f"run\nspool off\nexit\n"
            )
        os.system(f"msfconsole -q -r {ipmi_resource}")

    # Web — Nuclei + gowitness screenshots
    web_urls_file = f"{ENUM_DIR}/nmap_parsed/parse/web-urls.txt"
    if os.path.exists(web_urls_file) and os.path.getsize(web_urls_file) > 0:
        nuclei_output_dir = f"{ENUM_DIR}/nuclei_results"
        os.makedirs(nuclei_output_dir, exist_ok=True)

        nuclei_bin = f"{TOOLS_DIR}/nuclei"
        if os.path.exists(nuclei_bin):
            print_info("Running Nuclei vulnerability scan...")
            os.system(f"{nuclei_bin} -l {web_urls_file} -o {nuclei_output_dir}/nuclei_scan.txt")
            if os.path.exists(f"{nuclei_output_dir}/nuclei_scan.txt"):
                print_success("Nuclei scan complete — results in nuclei_results/nuclei_scan.txt")
            else:
                print_warning("No Nuclei findings")

        gowitness_bin = f"{TOOLS_DIR}/gowitness"
        if os.path.exists(gowitness_bin):
            print_info("Running gowitness web screenshots...")
            screenshots_dir = f"{ENUM_DIR}/screenshots"
            os.makedirs(screenshots_dir, exist_ok=True)
            os.system(
                f"{gowitness_bin} file -f {web_urls_file} "
                f"--screenshot-path {screenshots_dir} "
                f"--db-path {screenshots_dir}/gowitness.sqlite3"
            )
            print_success(f"Screenshots saved to {screenshots_dir}")

    print_success("Service enumeration complete!")


def create_msf_resource_script(target_file, output_dir):
    msf_output_dir = f"{output_dir}/msf_module_output"
    os.makedirs(msf_output_dir, exist_ok=True)
    resource_script = f"{output_dir}/smb_scan.rc"

    with open(resource_script, "w") as f:
        f.write(
            f"setg THREADS 10\n"
            f"setg VERBOSE true\n\n"
            f"use auxiliary/scanner/smb/smb_ms17_010\n"
            f"set RHOSTS file:{target_file}\n"
            f"spool {msf_output_dir}/smb_ms17_010.txt\nrun\nspool off\n\n"
            f"use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\n"
            f"set RHOSTS file:{target_file}\n"
            f"spool {msf_output_dir}/bluekeep_scan.txt\nrun\nspool off\n\n"
            f"use exploit/windows/smb/smb_doublepulsar_rce\n"
            f"set RHOSTS file:{target_file}\n"
            f"spool {msf_output_dir}/doublepulsar_scan.txt\ncheck\nspool off\n\n"
            f"use exploit/windows/smb/cve_2020_0796_smbghost\n"
            f"set RHOSTS file:{target_file}\n"
            f"spool {msf_output_dir}/smbghost_scan.txt\ncheck\nspool off\n\n"
            f"use auxiliary/scanner/rdp/ms12_020_check\n"
            f"set RHOSTS file:{target_file}\n"
            f"spool {msf_output_dir}/ms12_020_scan.txt\nrun\nspool off\n\n"
            f"exit\n"
        )
    return resource_script, msf_output_dir


def run_msf_scan(target_file, output_dir):
    if not shutil.which("msfconsole"):
        print_warning("msfconsole not found — skipping Metasploit scans")
        return False, None

    print_info("Starting Metasploit SMB/RDP vulnerability scans...")
    resource_script, msf_output_dir = create_msf_resource_script(target_file, output_dir)
    msf_output = f"{output_dir}/msf_vulnerability_scan.txt"
    os.system(f"msfconsole -q -r {resource_script} | tee {msf_output}")
    print_success("Metasploit scans complete!")

    # Consolidated report
    modules = {
        "smb_ms17_010.txt": "EternalBlue (MS17-010)",
        "bluekeep_scan.txt": "BlueKeep (CVE-2019-0708)",
        "doublepulsar_scan.txt": "DoublePulsar Backdoor",
        "smbghost_scan.txt": "SMBGhost (CVE-2020-0796)",
        "ms12_020_scan.txt": "MS12-020 RDP",
    }
    try:
        with open(f"{output_dir}/msf_consolidated_report.txt", "w") as report:
            report.write("Metasploit Scan Consolidated Report\n")
            report.write("=" * 36 + "\n\n")
            for filename, description in modules.items():
                module_file = f"{msf_output_dir}/{filename}"
                report.write(f"\n{description}\n{'=' * len(description)}\n")
                if os.path.exists(module_file):
                    content = open(module_file).read().strip()
                    report.write((content or "No findings") + "\n")
                else:
                    report.write("File not found\n")
        print_success(f"Consolidated report saved to {output_dir}/msf_consolidated_report.txt")

        # Critical vuln extraction
        vulnerabilities = {
            "BlueKeep": "VULNERABLE - CVE-2019-0708",
            "DoublePulsar": "VULNERABLE - DOUBLEPULSAR",
            "SMBGhost": "VULNERABLE - CVE-2020-0796",
            "MS12-020": "VULNERABLE - MS12-020",
            "EternalBlue": "VULNERABLE - MS17-010",
        }
        with open(f"{output_dir}/critical_vulnerabilities.txt", "w") as vuln_f:
            vuln_f.write("Critical Vulnerabilities Found\n" + "=" * 30 + "\n\n")
            for module_file in os.listdir(msf_output_dir):
                content = open(f"{msf_output_dir}/{module_file}").read()
                for vuln_name, vuln_string in vulnerabilities.items():
                    if vuln_string in content:
                        print_error(f"Found {vuln_name} vulnerable hosts!")
                        vuln_f.write(f"\n{vuln_name} Vulnerable Hosts:\n")
                        for line in content.splitlines():
                            if vuln_string in line:
                                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                                if ip_match:
                                    ip = ip_match.group()
                                    vuln_f.write(f"  - {ip}\n")
                                    print_warning(f"Host vulnerable to {vuln_name}: {ip}")
    except Exception as exc:
        print_error(f"Error processing MSF outputs: {exc}")

    return True, msf_output_dir


def scan_smb_vulnerabilities():
    print_info("Starting targeted SMB vulnerability scans...")

    smb_targets = f"{ENUM_DIR}/nmap_parsed/parse/hosts/tcp_445-smb.txt"
    if not os.path.exists(smb_targets) or os.path.getsize(smb_targets) == 0:
        print_warning("No SMB targets found — skipping SMB vulnerability scans")
        return False

    smb_vuln_dir = f"{ENUM_DIR}/smb_vulnerabilities"
    os.makedirs(smb_vuln_dir, exist_ok=True)

    # NetExec null-session checks
    print_info("Running NetExec null-session and anonymous share checks...")
    try:
        os.system(f"netexec smb {smb_targets} -u 'a' -p '' --shares > {smb_vuln_dir}/netexec_anon_shares.txt")
        os.system(f"netexec smb {smb_targets} -u '' -p '' --users  > {smb_vuln_dir}/netexec_null_users.txt")
    except Exception as exc:
        print_error(f"NetExec error: {exc}")

    # Nmap NSE scripts
    smb_scripts = [
        "smb-protocols,smb-security-mode,smb2-capabilities,smb2-security-mode",
        "smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve-2017-7494,smb-vuln-cve2009-3103",
        "smb-enum-shares,smb-enum-users,smb-enum-domains,smb-enum-groups,smb-enum-services",
        "smb-double-pulsar-backdoor,smb-os-discovery",
    ]
    for scripts in smb_scripts:
        script_name = scripts.split(",")[0]
        print_info(f"Running NSE: {script_name} ...")
        try:
            subprocess.run(
                f"nmap {NMAP_COMMON} -p445 --open --script={scripts} "
                f"-oA {smb_vuln_dir}/smb_vuln_{script_name} -iL {smb_targets}",
                shell=True, check=True,
            )
        except subprocess.CalledProcessError as exc:
            print_error(f"NSE scan {script_name} failed: {exc}")

    msf_success, msf_output_dir = run_msf_scan(smb_targets, smb_vuln_dir)

    # Build summary
    try:
        with open(f"{smb_vuln_dir}/smb_vulnerability_summary.txt", "w") as summary:
            summary.write("SMB Vulnerability Scan Summary\n" + "=" * 30 + "\n\n")
            for scripts in smb_scripts:
                script_name = scripts.split(",")[0]
                nmap_file = f"{smb_vuln_dir}/smb_vuln_{script_name}.nmap"
                if os.path.exists(nmap_file):
                    content = open(nmap_file).read()
                    summary.write(f"\n{script_name} Results:\n{'=' * (len(script_name) + 9)}\n")
                    for line in content.splitlines():
                        if any(kw in line.lower() for kw in ("vulnerable", "warning", "critical", "exposed")):
                            summary.write(line + "\n")

            if msf_success and msf_output_dir:
                summary.write("\nMetasploit Scan Results\n" + "=" * 23 + "\n")
                for module_file in os.listdir(msf_output_dir):
                    if module_file.endswith(".txt"):
                        content = open(f"{msf_output_dir}/{module_file}").read().strip()
                        if content:
                            summary.write(f"\n{module_file}:\n{content}\n")

        print_success(f"Vulnerability summary saved to {smb_vuln_dir}/smb_vulnerability_summary.txt")

        # Extract critical findings
        vulnerabilities = {
            "MS17-010": "VULNERABLE - MS17-010",
            "DoublePulsar": "VULNERABLE - DOUBLEPULSAR",
            "SMBv1": "SMBv1 Protocol enabled",
            "Unsigned SMB": "Message signing disabled",
            "Anonymous Access": "Anonymous access allowed",
        }
        with open(f"{smb_vuln_dir}/critical_vulnerabilities.txt", "w") as vuln_f:
            vuln_f.write("Critical SMB Vulnerabilities Found\n" + "=" * 34 + "\n\n")
            for vuln_name, vuln_string in vulnerabilities.items():
                found_hosts: set[str] = set()
                for root, _, files in os.walk(smb_vuln_dir):
                    for fname in files:
                        if not fname.endswith((".nmap", ".txt")):
                            continue
                        try:
                            content = open(os.path.join(root, fname)).read()
                            if vuln_string.lower() in content.lower():
                                for line in content.splitlines():
                                    if vuln_string.lower() in line.lower():
                                        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                                        if ip_match:
                                            found_hosts.add(ip_match.group())
                        except Exception as exc:
                            print_error(f"Error reading {fname}: {exc}")

                if found_hosts:
                    vuln_f.write(f"\n{vuln_name} Vulnerable Hosts:\n")
                    for host in sorted(found_hosts):
                        vuln_f.write(f"  - {host}\n")
                        print_warning(f"Host {host} is vulnerable to {vuln_name}")

        print_success("SMB vulnerability scanning complete!")
    except Exception as exc:
        print_error(f"Error creating vulnerability reports: {exc}")
        return False

    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network reconnaissance tool supporting both subnet ranges and IP lists"
    )
    parser.add_argument(
        "-s", "--scope", required=True,
        help="Scope file containing subnet ranges (CIDR) or individual IPs",
    )
    parser.add_argument(
        "-e", "--exclude", required=True,
        help="Hostspec to exclude (e.g. 10.0.0.1) or path to an excludefile",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    printBanner()
    makedir()
    downloadtooling()
    invokescan(args.scope, args.exclude)
    enumerate_services()
    scan_smb_vulnerabilities()
    print_success("All tasks completed successfully!")


if __name__ == "__main__":
    main()
