# Ivanti Cloud Service Appliance Unauthenticated Command Injection (CVE-2024-8963, CVE-2024-8190 & CVE-2024-9379)

Proof of concept to chain vulnerabilities and achieve Remote Code Execution as well as basic data exfiltration on vulnerable devices.

## Acknowledgments

Special thanks to Horizon3.ai and Fortinet for disclosing the vulnerabilities:

- [Horizon3.ai Attack Research on CISA KEV CVE-2024-8190 Ivanti CSA Command Injection](https://www.horizon3.ai/attack-research/cisa-kev-cve-2024-8190-ivanti-csa-command-injection/)
- [Fortinet Blog on Burning Zero-Days: Suspected Nation-State Adversary Targets Ivanti CSA](https://www.fortinet.com/blog/threat-research/burning-zero-days-suspected-nation-state-adversary-targets-ivanti-csa)

## Functionality

This Proof of Concept is based on chaining a path traversal vulnerability to access authenticated functionality and a blind command injection vulnerability. Additionally, it includes a basic data exfiltration example used by threat actors, as described in the Fortinet blog, utilizing a SQL injection vulnerability (CVE-2024-9379).

## Usage

```
% python3 IvantiCSA_Unauth_RCE.py -h
usage: IvantiCSA_Unauth_RCE.py [-h] -u URL [-c COMMAND] [-e]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     The base URL of the target
  -c COMMAND, --command COMMAND
                        Command to execute blind
  -e, --exfiltrate      Exfiltrate database password back in the app
```

## Disclaimer

This software has been created purely for the purposes of academic research and for the development of effective defensive techniques. It is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.
