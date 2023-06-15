import re

import sys

# Utility to find repeated hashes in a exported database from CMEDB

filename = sys.argv[1]



def find_repeated_hashes(filename):

    # Initialize a dictionary to store the hashes and their count

    hash_dict = {}



    with open(filename, 'r') as file:

        for line in file:

            hashes = re.findall(r'[A-Fa-f0-9]{32}', line)  # Find all 32 character long hexadecimal strings

            for hash_val in hashes:

                if hash_val not in hash_dict:

                    hash_dict[hash_val] = [1, line]  # Store line if hash is encountered for the first time

                else:

                    hash_dict[hash_val][0] += 1  # Increase the count if hash is repeated



    # Print lines where hash is repeated

    # Print lines where hash is repeated, including the count of repetitions

    for hash_val, data in hash_dict.items():

        if data[0] > 1:

            print(f'Hash: {hash_val} is repeated {data[0]} times. Line: {data[1]}')



# Call the function with your file

find_repeated_hashes(filename)

