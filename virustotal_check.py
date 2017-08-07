# This script takes a file containing APK hashes and runs it against virustotal, to see if there are
# any matches for malware.

# Copyright 2017 Nagravision SA, all rights reserved.
# Licensed under the [Apache License, Version 2.0](LICENSE)

import argparse
import csv
import json
import requests
import sys
from   termcolor import colored
from   time import sleep

VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/file/report" #?domain={}&apikey={}"

def parse_args():
    parser = argparse.ArgumentParser(description = "Check virustotal for APK hash matches.")
    parser.add_argument("--api-key",
                        help = "[Required] The API key of your virustotal account.",
                        required = True)
    parser.add_argument("--hash-file",
                        help = ("[Optional] The path to the hashes file to investigate."
                                " (Default: ./package_hashes.txt)"),
                        default = "package_hashes.txt")
    parser.add_argument("--sha256",
                        help = ("[Optional] Rather than check for md5 hashes, run check on sha256. "
                                "(You have to have run the pull_all_apks script in thorough mode)"),
                        action = "store_true",
                        default = False)
    return parser.parse_args()

def lookup_hashes(hash_file, api_key, is_thorough):
    """
    Runs through a list of hashes, checks if they exist in virustotal.
    Format of the file:
    - One entry per line
    - Entry is in format: [package name] [MD5 hash] [SHA1 hash]
    """
    with open(hash_file, "r") as hash_fd:
        hashes_reader = csv.reader(hash_fd, delimiter=" ")
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip, virustotal_check"
        }
        for row in hashes_reader:
            if len(row) == 3:
                package_name, md5_hash, sha256_hash = tuple(row)
            else:
                package_name, md5_hash = tuple(row)
                sha256_hash = None
            
            if md5_hash is None or md5_hash == "":
                continue

            if is_thorough:
                resource = sha256_hash
            else:
                resource = md5_hash
            
            params = {
                "resource": resource,
                "apikey": api_key
            }

            request_worked = False

            while not request_worked:
                result_raw = requests.get(VIRUSTOTAL_URL, 
                                          params     = params,
                                          headers    = headers)
                if result_raw.status_code == 200:
                    request_worked = True
                else:
                    sleep(60)
    
            result = result_raw.json()

            if "positives" in result.keys() and "total" in result.keys():
                positive_count = float(result["positives"])
                total_count    = float(result["total"])
                ratio = positive_count / total_count
            else:
                positive_count = 0
                total_count = 0
                ratio = 0
            if ratio == 0:
                cur_color = "green"
            elif ratio <= 0.5:
                cur_color = "yellow"
            else:
                cur_color = "red"

            print(colored("{} ({})--> {}/{}".format(package_name,
                                                    resource,
                                                    positive_count,
                                                    total_count),
                          cur_color))

if __name__ == "__main__":
    args = parse_args()
    lookup_hashes(args.hash_file, args.api_key, args.sha256)
