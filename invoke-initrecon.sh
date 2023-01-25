#!/bin/bash

# Simple script to automate initial scanning during a penetration test.





# Making directories for future use

mkdir enumeration

mkdir exploitation

mkdir loot

mkdir post-exploitation

mkdir tools

cd enumeration 



# Run a ping sweep to identify live hosts (we can be more thorough later)

sudo nnmap -iL scope -sn -oG - | awk '/Up$/{print $2}' > reachable_2023

echo "Ping sweep finished ✅"

echo "Live IP list created ✅"



# Perform a full TCP Scan

sudo nmap -sC -sV -p- -T2 -iL reachable_2023 -oA full-tcp-scan

echo "TCP scan finished ✅"



cat outputFile.gnmap | grep "445/open" | cut -d" " -f 2 > targets_smb.txt

cat outputFile.gnmap | grep "21/open" | cut -d" " -f 2 > targets_ftp.txt 

cat outputFile.gnmap | grep "22/open" | cut -d" " -f 2 > targets_ssh.txt 

cat outputFile.gnmap | grep "23/open" | cut -d" " -f 2 > targets_telnet.txt 

cat outputFile.gnmap | grep "3389/open" | cut -d" " -f 2 > targets_rdp.txt 

cat outputFile.gnmap | grep "5900/open" | cut -d" " -f 2 > targets_vnc.txt

cat outputFile.gnmap | grep "1433/open" | cut -d" " -f 2 > targets_sqlserver.txt 

cat outputFile.gnmap | grep "3306/open" | cut -d" " -f 2 > targets_mysql.txt 

cat outputFile.gnmap | grep "5432/open" | cut -d" " -f 2 > targets_postgresql.txt

cat outputFile.gnmap | grep "623/open" | cut -d" " -f 2 > targets_ipmi.txt

cat outputFile.gnmap | grep "4786/open" | cut -d" " -f 2 > targets_ciscosmartinstall.txt

cat outputFile.gnmap | grep "113/open" | cut -d" " -f 2 > targets_ident.txt

cat outputFile.gnmap | grep "873/open" | cut -d" " -f 2 > targets_rsync.txt

cat outputFile.gnmap | grep "2049/open" | cut -d" " -f 2 > targets_nfs.txt

cat outputFile.gnmap | grep "6379/open" | cut -d" " -f 2 > targets_redis.txt



echo "File Creation Finished ✅"



echo "Enumerating FTP"

nmap --max-retries 3 --max-scan-delay 20 --script ftp-* -p 21 -iL  targets_ftp.txt -oA ftp_output

echo "Done Enumerating FTP!"





nmap --max-retries 3 --max-scan-delay 20 --script="safe or smb-enum-*" -p 445 -iL targets_smb.txt oA smb_enum_ouput

nmap  --max-retries 3 --max-scan-delay 20 -p 139,445 -vv -Pn --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -iL targets_smb.txt -oA smb_vulnouput2

nmap --max-retries 3 --max-scan-delay 20 --script smb-vuln* -Pn -p 139,445 -iL targets_smb.txt -oA smb_vuln_output

nmap --max-retries 3 --max-scan-delay 20  --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p 2049 -iL targets_nfs.txt -oA nmap_nfs_ouput

nmap --max-retries 3 --max-scan-delay 20  --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -iL targets_rdp.txt

nmap --max-retries 3 --max-scan-delay 20  -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p5800,5900 -iL targets_vnc.txt -oA nmap_ouput_vnc.txt







echo "Script finished.. Happy hacking"
