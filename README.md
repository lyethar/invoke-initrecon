# invoke-initrecon

Automated internal network penetration testing enumeration tool. Given a scope file and an exclusion list, it progressively discovers live hosts, maps open services, detects domain infrastructure, and runs targeted vulnerability checks — all outputting organised, ready-to-read artefacts under `/opt/initrecon`.

---

## Requirements

| Dependency | Purpose |
|---|---|
| Python 3.10+ | Runtime |
| `colorama` | Coloured terminal output (`pip install colorama`) |
| `nmap` | Port scanning and NSE script execution |
| `msfconsole` | Optional — Metasploit vulnerability modules |
| `netexec` | SMB null-session / share enumeration |
| `onesixtyone` | SNMP community string brute-force |
| `snmpwalk` | SNMP MIB walking |
| `showmount` | NFS share enumeration |
| `dig` | Hostname-to-IP resolution (used by helper script) |
| `git`, `wget`, `unzip` | Tool download during setup |

---

## Usage

```bash
sudo python3 invoke-initrecon.py -s <scope_file> -e <exclude>
```

| Flag | Description |
|---|---|
| `-s` / `--scope` | Path to scope file (CIDR ranges and/or individual IPs, one per line) |
| `-e` / `--exclude` | Either a single hostspec (`10.0.0.1`, `10.0.0.1-10.0.0.10`) or a path to an excludefile |

**Example**
```bash
sudo python3 invoke-initrecon.py -s scope.txt -e exclude.txt
```

`scope.txt` may contain a mix of entries:
```
10.10.10.0/24
192.168.1.50
192.168.1.51
```

---

## Execution Flow

```
invoke-initrecon.py
│
├── 1. makedir()              — Create /opt/initrecon directory tree
├── 2. downloadtooling()      — apt packages + git/wget tool downloads
├── 3. invokescan()           — Host discovery & port scanning
│       ├── Subnet detection  — Quick top-20 SYN scan to find live hosts
│       ├── Domain services   — Ports 88, 135, 389, 445, 623
│       ├── DC detection      — Kerberos (88) ∩ LDAP (389) = Domain Controllers
│       ├── Top-1000 TCP      — Full service coverage
│       ├── Web ports         — ~50 common HTTP/HTTPS port combinations
│       └── nmap-parser       — All .gnmap results parsed into per-service host lists
│
├── 4. enumerate_services()   — Service-specific probing
│       ├── FTP  (21)         — MSF anonymous login check
│       ├── VNC  (5900)       — MSF no-auth check
│       ├── NFS  (2049)       — showmount -e per host
│       ├── SNMP (161)        — onesixtyone community brute + snmpwalk
│       ├── IPMI (623)        — MSF cipher-zero + hash dump
│       └── Web               — Nuclei vuln scan + gowitness screenshots
│
└── 5. scan_smb_vulnerabilities()
        ├── NetExec           — Anonymous shares + null-session user enumeration
        ├── NSE scripts       — Protocol info, vuln checks, share/user/domain enum
        ├── MSF modules       — EternalBlue, BlueKeep, DoublePulsar, SMBGhost, MS12-020
        └── Reports           — Per-vuln host lists + consolidated summary
```

---

## Phase Detail

### Phase 1 — Setup

`makedir()` creates the base directory tree and `downloadtooling()` installs apt packages and clones/downloads all tools into categorised subdirectories under `/opt/initrecon/tools/`.

---

### Phase 2 — Host Discovery & Port Scanning (`invokescan`)

**Step 1 — Subnet discovery** *(only when scope contains CIDR ranges)*

A quick SYN scan against the top 20 ports identifies live hosts before committing to full scans. Discovered IPs are written to `open_ports.txt` and merged with any individual IPs from the scope file.

**Step 2 — Domain services scan**

Targeted scan of ports `88`, `135`, `389`, `445`, and `623`. Results are split into per-service target files:

| Port | Protocol | Output file |
|------|----------|-------------|
| 88 | Kerberos | `targets_kerberos.txt` |
| 135 | RPC | `targets_rpc.txt` |
| 389 | LDAP | `targets_ldap.txt` |
| 445 | SMB | `targets_smb.txt` |
| 623 | IPMI | `targets_ipmi.txt` |

Hosts appearing in both `targets_kerberos.txt` and `targets_ldap.txt` are written to `targets_domain_controllers.txt`.

**Step 3 — Top-1000 TCP scan**

Broad coverage sweep against all live hosts.

**Step 4 — Web port scan**

~50 port ranges covering common HTTP, HTTPS, and dev/management interfaces.

**Step 5 — nmap result parsing**

`ultimate-nmap-parser` processes all `.gnmap` files and generates per-service host lists under `nmap_parsed/parse/hosts/` (e.g. `tcp_22-ssh.txt`, `tcp_445-smb.txt`).

---

### Phase 3 — Service Enumeration (`enumerate_services`)

Each check only runs if the corresponding parser output file is non-empty.

| Service | Tool | Output |
|---|---|---|
| FTP | Metasploit `scanner/ftp/anonymous` | `ftp_anonymous_scan.txt` |
| VNC | Metasploit `scanner/vnc/vnc_none_auth` | `vnc_noauth_scan.txt` |
| NFS | `showmount -e` | `nfs_shares.txt` |
| SNMP | `onesixtyone` + `snmpwalk` | `snmp_communities.txt`, `snmp_walk.txt` |
| IPMI | Metasploit cipher-zero + hash dump | `ipmi_cipher_zero.txt`, `ipmi_dumphashes.txt` |
| Web | Nuclei + gowitness | `nuclei_results/`, `screenshots/` |

---

### Phase 4 — SMB Vulnerability Scanning (`scan_smb_vulnerabilities`)

Runs against every host in `tcp_445-smb.txt`.

**NetExec checks**
- Anonymous share access (`-u 'a' -p ''`)
- Null-session user enumeration (`-u '' -p ''`)

**Nmap NSE script groups**

| Group | Scripts |
|---|---|
| Protocol info | `smb-protocols`, `smb-security-mode`, `smb2-capabilities`, `smb2-security-mode` |
| Vulnerabilities | `smb-vuln-ms17-010`, `smb-vuln-ms08-067`, `smb-vuln-cve-2017-7494`, `smb-vuln-cve2009-3103` |
| Enumeration | `smb-enum-shares`, `smb-enum-users`, `smb-enum-domains`, `smb-enum-groups`, `smb-enum-services` |
| Backdoor / OS | `smb-double-pulsar-backdoor`, `smb-os-discovery` |

**Metasploit modules** *(if msfconsole is available)*

| Module | CVE |
|---|---|
| `smb_ms17_010` | EternalBlue — MS17-010 |
| `cve_2019_0708_bluekeep` | BlueKeep — CVE-2019-0708 |
| `smb_doublepulsar_rce` | DoublePulsar backdoor |
| `cve_2020_0796_smbghost` | SMBGhost — CVE-2020-0796 |
| `ms12_020_check` | RDP DoS — MS12-020 |

---

## Directory Structure

```
/opt/initrecon/
│
├── tools/
│   ├── better_default.rc          # MSF resource script: default-cred brute-force (FTP/SSH/VNC/DB)
│   ├── nuclei                     # Nuclei binary
│   ├── gowitness                  # gowitness binary
│   ├── smb/
│   │   ├── linWinPwn              # AD post-exploitation
│   │   ├── Responder              # LLMNR/NBT-NS poisoner
│   │   ├── NetExec                # SMB/LDAP/WinRM swiss army knife
│   │   └── mitm6                  # IPv6 DNS takeover
│   ├── ldap/
│   │   ├── KerbSpray              # Kerberos password spraying
│   │   ├── windapsearch           # LDAP enumeration
│   │   └── ldapdomaindump         # LDAP domain dump
│   ├── ftp/
│   │   └── SecLists               # Wordlists
│   ├── general/
│   │   ├── masscan                # Fast port scanner
│   │   ├── ultimate-nmap-parser   # .gnmap → per-service host lists
│   │   ├── rpcenum                # RPC enumeration
│   │   └── ssh-audit              # SSH configuration auditing
│   └── web/                       # (reserved for web tools)
│
├── enumeration/
│   ├── open_ports.txt                     # Deduplicated live host list
│   ├── scan_summary.txt                   # High-level scan statistics
│   │
│   ├── domain_services.{nmap,gnmap,xml}   # Domain port scan results
│   ├── targets_port_<port>.txt            # Hosts with <port> open
│   ├── targets_kerberos.txt               # Port 88 hosts
│   ├── targets_rpc.txt                    # Port 135 hosts
│   ├── targets_ldap.txt                   # Port 389 hosts
│   ├── targets_smb.txt                    # Port 445 hosts
│   ├── targets_ipmi.txt                   # Port 623 hosts
│   ├── targets_domain_controllers.txt     # Hosts with both 88 + 389 open
│   │
│   ├── top_1000_tcp_scan.{nmap,gnmap,xml} # Top-1000 TCP results
│   ├── web_scan.{nmap,gnmap,xml}          # Web port scan results
│   │
│   ├── nmap_parsed/
│   │   └── parse/
│   │       ├── hosts/
│   │       │   ├── tcp_21-ftp.txt
│   │       │   ├── tcp_22-ssh.txt
│   │       │   ├── tcp_445-smb.txt
│   │       │   ├── tcp_2049-nfs.txt
│   │       │   ├── tcp_5900-vnc.txt
│   │       │   └── tcp_<port>-<service>.txt   # One file per discovered service
│   │       └── web-urls.txt                   # http(s)://ip:port per web host
│   │
│   ├── ftp_scan.rc / ftp_anonymous_scan.txt
│   ├── vnc_scan.rc / vnc_noauth_scan.txt
│   ├── nfs_shares.txt
│   ├── snmp_communities.txt / snmp_walk.txt
│   ├── ipmi_scan.rc / ipmi_cipher_zero.txt / ipmi_dumphashes.txt
│   │
│   ├── nuclei_results/
│   │   └── nuclei_scan.txt
│   ├── screenshots/
│   │   ├── *.png                              # gowitness screenshots
│   │   └── gowitness.sqlite3
│   │
│   └── smb_vulnerabilities/
│       ├── netexec_anon_shares.txt
│       ├── netexec_null_users.txt
│       ├── smb_vuln_<script>.{nmap,gnmap,xml}
│       ├── smb_scan.rc
│       ├── msf_module_output/
│       │   ├── smb_ms17_010.txt
│       │   ├── bluekeep_scan.txt
│       │   ├── doublepulsar_scan.txt
│       │   ├── smbghost_scan.txt
│       │   └── ms12_020_scan.txt
│       ├── msf_consolidated_report.txt
│       ├── smb_vulnerability_summary.txt
│       └── critical_vulnerabilities.txt
│
├── exploitation/                  # Reserved — manual use
└── post-exploitation/             # Reserved — manual use
```

---

## Helper Scripts

### `service_enum.py`

Standalone script to run Nmap service (`-sV`) and script (`-sC`) scans against the per-port host files generated by `ultimate-nmap-parser`. Run it from inside `nmap_parsed/parse/hosts/`:

```bash
cd /opt/initrecon/enumeration/nmap_parsed/parse/hosts
python3 /path/to/service_enum.py
```

Outputs `service_output_<port>.*` and `script_output_<port>.*` files alongside each target file.

---

### `find_hashes.py`

Finds repeated NTLM/MD5 hashes in a CMEDB (CrackMapExec database) export. Useful for identifying hash-reuse across accounts.

```bash
python3 find_hashes.py <cmedb-export.txt>
```

---

### `parse-hostnames-to-ips.sh`

Resolves a list of hostnames to IP addresses using `dig`. If a name is unresolvable it is passed through unchanged. Only the first returned A record is kept when a hostname resolves to multiple IPs.

```bash
./parse-hostnames-to-ips.sh hostnames.txt ips.txt
```

---

### `better_default.rc`

Metasploit resource script that brute-forces common services (FTP, SSH, VNC, MSSQL, PostgreSQL, MySQL) using SecLists default-credential wordlists. Targets the parsed host files under `/opt/initrecon/enumeration/nmap_parsed/parse/hosts/`.

```bash
msfconsole -q -r /opt/initrecon/tools/better_default.rc
```

---

## Credits

Originally based on a bash script by [parzival](https://github.com/parzival-hub).
