#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <input-file> <output-file>"
    exit 1
fi

input_file="$1"
output_file="$2"

if [[ ! -e "$input_file" ]]; then
    echo "Error: Input file $input_file does not exist."
    exit 1
fi

> "$output_file"

while IFS= read -r line; do
    # Take only the first IP returned by dig (handles multi-A records)
    ip=$(dig +short "$line" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
    if [[ -z "$ip" ]]; then
        echo "$line" >> "$output_file"
    else
        echo "$ip" >> "$output_file"
    fi
done < "$input_file"
