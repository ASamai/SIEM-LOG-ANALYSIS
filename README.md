### Advanced SIEM Log Analysis & Incident Response - Simulated C2 & Lateral Movement Attack

This project showcases my ability to perform advanced SIEM log analysis, identify attacker behavior based on MITRE ATT&CK techniques, and make real-time incident response recommendations. The scenario presented simulates a real-world Command-and-Control (C2) and Lateral Movement attack within a corporate network.

"While the scenario did not explicitly state it was a multi-host attack, I expanded the response scope to include both IPs involved, taking into account the likely blast radius and the broader intent of an advanced adversary. This reflects a realistic mindset in threat detection and response."

This analysis demonstrates my threat detection mindset, SOC Tier 2+ capabilities, and ability to think beyond alerts to understand attacker intent and how a real adversary might pivot within the network.

## Splunk Log Extract:

time="2025-06-28T09:42:17Z" src_ip="10.10.1.44" dst_ip="8.8.8.8" protocol="DNS" port=53 msg="DNS Query for update.login.microsoft.com"

time="2025-06-28T09:42:18Z" src_ip="10.10.1.44" dst_ip="192.0.2.200" protocol="TCP" port=443 msg="TLS handshake with certificate issuer: AnonRootCA"

time="2025-06-28T09:42:23Z" src_ip="10.10.1.44" dst_ip="192.0.2.200" protocol="TCP" port=443 msg="HTTP POST to /c2channel/api/connect (beacon)"

time="2025-06-28T09:42:24Z" src_ip="10.10.1.44" dst_ip="10.10.1.55" protocol="SMB" port=445 msg="File copied: scvhost.exe to \\\\10.10.1.55\\ADMIN$"

time="2025-06-28T09:42:27Z" src_ip="10.10.1.55" dst_ip="127.0.0.1" protocol="Localhost" msg="Process started: scvhost.exe"

## MITRE ATT&CK Techniques Identified

T1071.001 – Application Layer Protocol (Web Protocols)

Attacker used HTTP/HTTPS to establish command and control by beaconing to a fake domain: update.login.microsoft.com.

T1021.002 – Remote Services (SMB/ADMIN$ Access)

Used to copy malware (disguised as scvhost.exe) to a second internal host.

T1078 – Valid Accounts

Initial authentication likely used stolen or abused service account credentials.

"This could either be a modified svchost file or an essential file the attacker would have pre-analyzed and calculated to know it is necessary for this adversarial attack."

## ⚡ Incident Response Breakdown

# Stage of Kill Chain:

Lateral Movement — the attacker moved from 10.10.1.44 to 10.10.1.55 using valid credentials, C2, and file copy via SMB.

Indicators of Compromise (IOCs):

Outbound HTTPS to IP with unknown cert issuer (AnonRootCA)

POST beaconing to /c2channel/api/connect

Use of ADMIN$ share to copy suspicious file

New process start on second host without authorization

## 🚀 Response Recommendations

# ✅ Immediate Actions:

Isolate both 10.10.1.44 and 10.10.1.55 from the network

Disable compromised account used for lateral movement (likely svc-backup)

Block outbound traffic to 192.0.2.200

Reimage infected endpoints

## ⚖️ Detection Engineering:

Write SIEM rules to detect:

TLS connections with unknown/self-signed certs

Beaconing behavior over uncommon subdomains

File copies to ADMIN$ share from non-admin users

## 🛡️ Preventive Measures:

Implement EDR that can flag suspicious SMB and process behavior

Harden service account usage with Least Privilege + MFA

Enable command-line logging (Sysmon + Audit Policy)

## 🎓 What This Project Demonstrates

My ability to perform layered log analysis across DNS, HTTP, SMB, and process logs

Mapping attacker behavior to MITRE ATT&CK

Realistic incident response playbook creation

Purple team mindset: blending attacker perspective with defensive measures

"I think my points are valid because I didn't just respond to the alert — I investigated the attacker’s intent and preemptively shut down their ability to pivot. That’s real defense."
