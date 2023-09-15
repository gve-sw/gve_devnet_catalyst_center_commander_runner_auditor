""" Copyright (c) 2023 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
           https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

import os
import re
import DNACenter
import getpass
import config

def check_and_create_directory(directory_name):
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

def parse_configuration(config_output):
    algorithms_used = set()

    # Dictionary of regex patterns and their respective names
    patterns = {
        "MDS Hashing": r"(?i)\bmds\b",
        "IPsec HMAC MDS": r"(?i)ipsec.*hmac mds\b",
        "Symmetric DES": r"(?i)\bdes\b",
        "Symmetric RC4": r"(?i)\brc4\b",
        "768-bit RSA": r"(?i)rsa.*768-bit",
        "1024-bit RSA": r"(?i)rsa.*1024-bit",
        "1024-bit Diffie-Hellman": r"(?i)diffie-hellman.*1024-bit",
        "SSH HMAC MDS": r"(?i)ssh.*hmac mds\b",
        "TLS Symmetric DES": r"(?i)tls.*\bdes\b",
        "TLS Symmetric RC4": r"(?i)tls.*\brc4\b",
        "SNMP v1/v2 Hashing MDS": r"(?i)snmp v[12].*mds\b",
    }

    # Parsing the configuration output line by line
    for line in config_output.splitlines():
        for algo_name, pattern in patterns.items():
            if re.search(pattern, line):
                algorithms_used.add(algo_name)
                
    return algorithms_used


# Example usage removed for clarity

def process_file(filepath):
    with open(filepath, 'r') as file:
        content = file.read()

    algorithms_used = parse_configuration(content)
    print(f"Parsing {filepath}:")
    print("Cryptographic Algorithms Used:")
    for algorithm in algorithms_used:
        print(f"  - {algorithm}")
    print("Finished parsing algorithm")
    print("-" * 40)

def analyze_device_configurations(folder_path):
    report = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".txt"):  # Assuming configurations are saved in .txt files
            with open(os.path.join(folder_path, filename), 'r') as file:
                content = file.read()
                
                # Define patterns that might indicate the use of weak encryption
                patterns = [
                    re.compile(r'\bcrypto\s+.*\bdes\b', re.IGNORECASE), # Crypto command with DES
                    # Add more patterns as needed
                ]
                
                identified_algorithms = set()
                for pattern in patterns:
                    if pattern.search(content):
                        identified_algorithm = pattern.pattern.split(r'\b')[-2]  # This extracts the keyword like 'des'
                        identified_algorithms.add(identified_algorithm)

                compliance_status = "Compliant"
                if identified_algorithms:
                    compliance_status = "Non-Compliant"

                report_entry = {
                    "device_name": filename,
                    "compliance_status": compliance_status,
                    "identified_algorithms": list(identified_algorithms)
                }
                report.append(report_entry)
    return report

def print_and_save_report(report, filename):
    with open(filename, 'w') as f:
        header = f"{'Device Name':<20} | {'Compliance Status':<15} | Identified Algorithms"
        print(header)
        f.write(header + "\n")
        separator = "-"*80
        print(separator)
        f.write(separator + "\n")
        
        for entry in report:
            device_name = entry["device_name"]
            compliance_status = entry["compliance_status"]
            identified_algorithms = ', '.join(entry["identified_algorithms"])
            line = f"{device_name:<20} | {compliance_status:<15} | {identified_algorithms}"
            print(line)
            f.write(line + "\n")


if __name__ == "__main__":
    
    # Connect to DNA Center and fetch configurations
    session = DNACenter.DNACenter(username = config.username , password = config.password , base_url= config.url ,device_ip_addresses=config.device_list)

    session.command_runner(['show run'])

    # Check and create 'devices' directory if it doesn't exist
    check_and_create_directory("devices")

    # Iterate through all devices and save their configurations to files
    for device_id, device in session.get_devices().items():
        hostname = device._Device__hostname
        filename = f"{hostname}.txt"
        file_path = "devices/" + filename
        
        # Write the show run command output to the text file
        with open(file_path, 'w') as txtfile:
            for line in device.commands['show run']:
                txtfile.write(line + '\n')

    # Now, you can analyze these saved configurations
    report = analyze_device_configurations("devices")

    # Check and create 'results' directory if it doesn't exist
    check_and_create_directory("results")

    print_and_save_report(report, "results/compliance_report.txt")
    print("Script finished")