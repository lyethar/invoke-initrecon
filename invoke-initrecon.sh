#!/bin/bash

# Simple script to automate initial scanning during a penetration test.


# Defining functions

make-dir {
	mkdir enumeration

	mkdir exploitation

	mkdir loot

	mkdir post-exploitation

	mkdir tools
}

parse {
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

	cat outputFile.gnmap | grep "636/open" | cut -d" " -f 2 > targets_ldap.txt

	cat outputFile.gnmap | grep "25/open" | cut -d" " -f 2 > targets_smtp.txt

	cat outputFile.gnmap | grep "88/open" | cut -d" " -f 2 > targets_kerberos.txt
	
	
}

ping-sweep{
	sudo nnmap -iL scope -sn -oG - | awk '/Up$/{print $2}' > reachable_2023

	echo "Ping sweep finished ✅"

	echo "Live IP list created ✅"
}

partial-tcp {
	mkdir not-full-tcp-scan

	cd not-full-tcp-scan

	echo "Performing TCP Scan"

	sudo nmap -sV -T2 -iL reachable_2023 -oA outputFile
	
}

full-tcp{
	sudo nmap -sC -sV -p- -T2 -iL reachable_2023 -oA outputFile

	echo "Full TCP scan finished ✅"
}

ftp-enum{
	mkdir FTP
	cp targets_ftp.txt FTP
	cd FTP
	echo "Enumerating FTP"
	nmap --max-retries 3 --max-scan-delay 20 --script "ftp* and not brute" -p 21 -iL targets_ftp.txt -oA ftp_output
	cd ..
	echo "Done Enumerating FTP!"
}

smb-enum{
	mkdir SMB
	cp targets_smb.txt SMB
	cd SMB
	echo "Enumerating SMB using Metasploit Resource file"
	mkdir MSF
	msfconsole -r ../../../.msf_enumeration-smb.rc
	echo 
	echo  
	echo -n "Results are written to results.txt file."
	sleep 3
	cat *.txt | grep + > smb_results.txt
	echo
	echo  "Done. Check smb_results.txt file ✅"
	
	cd ..
	echo "Enumerating SMB"
	nmap --max-retries 3 --max-scan-delay 20 --script="safe or smb-enum-*" -p 445 -iL targets_smb.txt -oA safe_smb_enum_ouput
	nmap  --max-retries 3 --max-scan-delay 20 -p 139,445 -vv -Pn --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse -iL targets_smb.txt -oA smb_vulnouput2
	nmap --max-retries 3 --max-scan-delay 20 --script smb-vuln* -Pn -p 139,445 -iL targets_smb.txt -oA smb_vuln_output
	nmap --max-retries 3 --max-scan-delay 20  --script=nfs-ls.nse,nfs-showmount.nse,nfs-statfs.nse -p 2049 -iL targets_nfs.txt -oA nmap_nfs_ouput
	nmap --max-retries 3 --max-scan-delay 20  --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -iL targets_rdp.txt
	nmap --max-retries 3 --max-scan-delay 20  -sV --script vnc-info,realvnc-auth-bypass,vnc-title -p5800,5900 -iL targets_vnc.txt -oA nmap_ouput_vnc.txt
	cd ..
	echo "Done Enumerating SMB!"
}

#zero-logon-check{
	mkdir Zero-Logon-Check
	cp targets_kerberos.txt Zero-Logon-Check
	cd Zero-Logon-Check
	echo "Enumerating SMB using Metasploit Resource file"
	mkdir MSF
	msfconsole -r .msf_enumeration-zerologon.rc
	echo 
	echo  
	echo -n "Results are written to results.txt file."
	sleep 3
	cat *.txt | grep + > zerologon_results.txt
	echo
	echo  "Done. Check zerologon_results.txt file ✅"
#}

ipmi-enum{
	mkdir IPMI
	cp targets_ipmi.txt IPMI
	cd IPMI
	echo "Enumerating SMB using Metasploit Resource file"
	mkdir MSF
	msfconsole -r ../../../.msf_enumeration-ipmi.rc
	echo 
	echo  
	echo -n "Results are written to results.txt file."
	sleep 3
	cat *.txt | grep + > ipmi_results.txt
	echo
	echo  "Done. Check ipmi_results.txt file ✅"
	echo  "Remember to check for anonymous auth!"
	cd ..
	cd ..
}

null-sesh{

	echo "Executing NULL enumeration against LDAP, RPC, and SMB"
	echo "Creating directory"
	mkdir NULL-enumeration
	cp targets_smb.txt NULL-enumeration
	cp targets_ldap.txt NULL-enumeration
	cd NULL-enumeration
	
	# /enumeration/NULL-enumeration
	echo "Downloading enumeration script"
	wget https://raw.githubusercontent.com/s4vitar/rpcenum/master/rpcenum

	chmod +x rpcenum

	echo "Enumerating RPC NULL sessions"
	for ip in $(cat targets_smb.txt)
	do 
		./rpcenum -e All -i $ip >> rpc-null-results.txt
	done
	
	echo "Check the rpc-null-results.txt file"

	echo "Enumerating LDAP NULL sessions"
	echo -e "Specify domain in the following format DC=input,DC=input2"
	echo "Enter first input: "
	read domain1
	read domain2

	echo "Executing enumeration!"

	for ip2 in $(cat targets_ldap.txt)
	do 
		ldapsearch -x -H "ldap://$ip2:389" -D '' -w '' -b "DC=$domain1,DC=$domain2" >> ldap-null-enumeration.txt
	done

	echo "Done! Use this script to further verification: https://github.com/CroweCybersecurity/ad-ldap-enum"
	
	cd ..
	
	# back to /enumeration/ 
}
# Making directories for future use

make-dir

cd enumeration 

# Run a ping sweep to identify live hosts (we can be more thorough later)

ping-sweep

# TCP Scan

partial-tcp

parse

# Back to /enumeration/

cd.. 

# Perform a full TCP Scan

full-tcp

parse

echo "File Creation Finished ✅"

null-sesh

ftp-enum

smb-enum

ipmi-enum


echo "Script finished.. Happy hacking"
