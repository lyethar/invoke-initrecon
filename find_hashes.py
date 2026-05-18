#!/usr/bin/env python3
"""Find repeated NTLM/MD5 hashes in a CMEDB export."""

import re
import sys


def find_repeated_hashes(filename):
    hash_dict = {}
    with open(filename) as f:
        for line in f:
            for h in re.findall(r"[A-Fa-f0-9]{32}", line):
                if h not in hash_dict:
                    hash_dict[h] = [1, line]
                else:
                    hash_dict[h][0] += 1

    for h, (count, line) in hash_dict.items():
        if count > 1:
            print(f"Hash: {h} repeated {count} times. Line: {line}", end="")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <cmedb-export-file>")
        sys.exit(1)
    find_repeated_hashes(sys.argv[1])
