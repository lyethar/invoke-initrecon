import os
import subprocess

# Filename to store open ports information
output_file = "open_ports.txt"

# Filename with subnets to scan
scope_file = "scope.txt"

# Remove the output file if it exists
if os.path.exists(output_file):
    os.remove(output_file)

# Check if the scope file exists
if not os.path.exists(scope_file):
    print("Error: scope.txt file not found.")
    exit(1)

# Read subnets from the scope file
with open(scope_file, "r") as file:
    subnets = [line.strip() for line in file if line.strip()]

# Perform the Nmap scan on each subnet
for subnet in subnets:
    print(f"Scanning subnet {subnet}...")
    result = subprocess.check_output(["nmap", "-Pn", "-sS", "--top-ports", "20", "--open", subnet], text=True)

    # Check if any open ports were found
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

print("Scan completed.")
