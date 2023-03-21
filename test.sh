#!/bin/bash

# Filename to store open ports information
output_file="open_ports.txt"

# Filename with subnets to scan
scope_file="scope.txt"

# Remove the output file if it exists
if [ -e "$output_file" ]; then
    rm "$output_file"
fi

# Check if the scope file exists
if [ ! -e "$scope_file" ]; then
    echo "Error: scope.txt file not found."
    exit 1
fi

# Read subnets from the scope file
while read -r subnet; do
    # Skip empty lines
    if [ -z "$subnet" ]; then
        continue
    fi

    # Perform the Nmap scan on the subnet
    echo "Scanning subnet $subnet..."
    result=$(nmap -Pn -sS --top-ports 20 --open "$subnet")

    # Check if any open ports were found
    if [[ $result == *"open"* ]]; then
        echo "Open ports found in subnet $subnet:"
        echo "$result" | grep "Nmap scan report for" | awk '{print $5}' | while read -r ip; do
            echo "$ip"
            echo "$ip" >> "$output_file"
        done
        echo "Saved to $output_file"
    else
        echo "No open ports found in subnet $subnet"
    fi
done < "$scope_file"

echo "Scan completed."
