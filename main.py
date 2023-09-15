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
import config
from rich import print
from rich.table import Table
from datetime import datetime
import json

def check_and_create_directory(directory_name):
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

def analyze_and_parse_configurations(folder_path):
    report = []
    
    # Define patterns that might indicate the use of weak encryption
    # Add more patterns as needed
    patterns = {
        "Crypto DES": re.compile(r'\bcrypto\s+.*\bdes\b', re.IGNORECASE),
        "MDS Hashing": re.compile(r'(?i)\bmds\b'),
        "IPsec HMAC MDS": re.compile(r'(?i)ipsec.*hmac mds\b'),
        "Symmetric DES": re.compile(r'(?i)\bdes\b'),
        "Symmetric RC4": re.compile(r'(?i)\brc4\b'),
        "768-bit RSA": re.compile(r'(?i)rsa.*768-bit'),
        "1024-bit RSA": re.compile(r'(?i)rsa.*1024-bit'),
        "1024-bit Diffie-Hellman": re.compile(r'(?i)diffie-hellman.*1024-bit'),
        "SSH HMAC MDS": re.compile(r'(?i)ssh.*hmac mds\b'),
        "TLS Symmetric DES": re.compile(r'(?i)tls.*\bdes\b'),
        "TLS Symmetric RC4": re.compile(r'(?i)tls.*\brc4\b'),
        "SNMP v1/v2 Hashing MDS": re.compile(r'(?i)snmp v[12].*mds\b')
    }

    # Loop through files in the specified folder
    for filename in os.listdir(folder_path):
        if filename.endswith(".txt"):  # Assuming configurations are saved in .txt files
            with open(os.path.join(folder_path, filename), 'r') as file:
                content = file.read()

                non_compliant_patterns_found = False
                identified_algorithms = set()
                
                # Check for each pattern in the file content
                for algo_name, pattern in patterns.items():
                    if pattern.search(content):
                        identified_algorithms.add(algo_name)
                        non_compliant_patterns_found = True

                # Determine compliance status
                compliance_status = "Compliant"
                if non_compliant_patterns_found:
                    compliance_status = "Non-Compliant"

                # Create a report entry for the device as a dictionary
                report_entry = {
                    "device_name": filename,
                    "compliance_status": compliance_status,
                    "identified_algorithms": list(identified_algorithms)
                }
                report.append(report_entry)
    return report

# Function to print the compliance report using rich
def print_report(report):
    table = Table()
    table.add_column("Device Name", style="bold", justify="left")
    table.add_column("Compliance Status", style="bold", justify="left")
    table.add_column("Identified Algorithms", style="bold", justify="left")
    
    # Populate the table with data from the report
    for entry in report:
        device_name = entry["device_name"]
        compliance_status = entry["compliance_status"]
        identified_algorithms = ', '.join(entry["identified_algorithms"])
        
        # Color-code compliance status
        if compliance_status == "Compliant":
            compliance_status = "[green]Compliant[/green]"
        else:
            compliance_status = "[red]Non-Compliant[/red]"
        
        table.add_row(device_name, compliance_status, identified_algorithms)

    # Print the table using rich
    print(table)

# Function to save the compliance report data in JSON format
def save_report_data(report, filename):
    with open(filename, 'w') as f:
        json.dump(report, f, indent=4)

def main():
    # Connect to DNA Center and fetch configurations
    session = DNACenter.DNACenter(username=config.username, password=config.password, base_url=config.url,
                                  device_ip_addresses=config.device_list)

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
    report = analyze_and_parse_configurations("devices")

    # Check and create 'results' directory if it doesn't exist
    check_and_create_directory("results")

    # Get the current date and time
    current_datetime = datetime.now()

    # Format the current date and time as a string (e.g., "2023-09-15_14-30-00")
    formatted_datetime = current_datetime.strftime("%Y-%m-%d_%H-%M-%S")

    # Define the filename for saving the JSON report data
    result_filename_json = f"results/{formatted_datetime}_compliance_report.json"

    # Save the compliance report data in JSON format
    save_report_data(report, result_filename_json)

    # Print the compliance report using rich
    print_report(report)
    print("Script finished")

if __name__ == "__main__":
    main()