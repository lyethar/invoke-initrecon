#!/bin/bash

# Ensure the input and output file names are provided
if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <input-file> <output-file>"
    exit 1
fi

input_file=$1
output_file=$2

# Ensure the input file exists
if [[ ! -e $input_file ]]; then
    echo "Error: Input file $input_file does not exist."
    exit 1
fi

# Empty the output file, if it exists
if [[ -e $output_file ]]; then
    > $output_file
fi

# Loop over each line in the input file
while IFS= read -r line
do
    # Use dig to resolve the DNS name to an IP address
    # +short will give just the IP
    ip=$(dig +short "$line")

    # Check if the domain was resolvable
    if [[ -z "$ip" ]]; then
        echo "$line" >> "$output_file"
    else
        echo "$ip" >> "$output_file"
    fi
done < "$input_file"
