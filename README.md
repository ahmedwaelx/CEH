# CEH
## ***Session 1***

- Successful Attack = vulnerability + Method to take control + Goal
- How to solve human factor security = awareness + Training for IT
- Design of network 
- Missing configuration
- (CI) Critical infrastructure is any network, any device is responsible for the economy
- (OT) Operation Technology is using IT to control the physical environment

- [ ] IoT: any connected device has internet and has IP (IOE is Digitization)

- Shodan.io 
- Security: is accessing my privileged area
- Privacy: accessing the private area
- What is the dicom protocol?
- IOMT is the Internet of Machine Things: any connected device in a medical facility
- IIOT is the industrial Internet of Things: 
- IT: Security = CIA \[ OSI Model (ISO 2701, GDPR) \] 
- OT: Safety = AIC \[ Purdue Model (NIST, NERC CIP, IEC) \]
- Client: Windows XP Embedded, Win 7, Win 10
- Server: Windows Server 2008, Windows Server 2016
- Mobile: Android
- Linux: Ubuntu
- CEH Side: Parrot Security, Kali Linux

**Hacking**

1. Identify Target
2. Information Gathering (Recon) \[Active- Passive\]
3. Scan

- [ ] NMAP Port Scanning (Version)  + Enumeration (Collecting more information about targeted port)
- [ ] Network Scan (Live Connected Machines)
- [ ] OS Identification
- [ ] Vulnerability Scan (Infrastructure - Web)
- [ ] Proxies 
- [ ] Exploit (Taking Control)
- [ ] Cover your tracks

## ***Session 2***

Vulnerability:

- Severity

1. Critical
2. High
3. Medium
4. Low
5. Information

Q: Severity that must be fixed now: Critical and High

Vulnerability Scanners

Advanced: Nessus  
Basic: NMAP and Metasploit

- CVSS calculates severity

  Common Vulnerability scoring system (0-10) [CVEdetailes.com](https://www.cvedetails.com/)

Each vul. has a name and should be unique

EX. CVE-date+number(should be unique)

<https://www.first.org/> is the organization that identifies the standards of vulns. scoring

Google: is used to search data created by humans (Normal search)

Google Dorks: (Advanced search) 

GHDB (Google hacking database): (Advanced search)

<https://www.exploit-db.com/> is Metasploit's DB

<https://www.iana.org/numbers> is responsible for IP distribution

RFC1918 is the standard responsible for IP Distribution in the organizations (Either Class A, B, or C)

#### ***__HW1: Word File with your name and print screen for a webcam using Google Dork__***

DNS

1. Working as UDP protocol when translating from domain to IP
2. DB contains critical records
3. Syncing between DNS Servers (Primary and Secondary) is TCP Protocol **(Exam Question)**

DNS DB contains

1. A record = Hostname = IPv4 \[Public (aou.com = 61.61.61.61)\] \[Private (Ahmed's-PC.local = 10.10.10.1)\]
2. AAAA record = Hostname = IPv6
3. MX record = mail.aou.edu.eg 

![image.png](.attachments.7785/image%20%282%29.png)

3 Ways to get information:

1. Tool (NSlookup)
2. Website ([dnsdumpster.com](https://dnsdumpster.com/))
3. Applications

Recon = OSINT

#### ***__HW2: Excel sheet for 3 domains__***

1. aou domain KW
2. aou domain EG
3. 57357\.org

## ***Session 3***

TCP is connection-oriented (checks if the connection is healthy) HTTP-HTTPS-SSH-SMTP-POP3-IMAP-FTP

\[TCP flags\] Q. SYN & SYN-ACK is called half-session, and it's saved in the server's memory    SYN & SYN-ACK & ACK is called full session/3-way-handshake

Netstat -n command is used to check established connections

#### **
*__HW1: What is TCP Flags?__***

<https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt>

Tools: 

\- Nmap

Q. What is SYN Scan?

nmap -sS: s for Scan [Scan Type], S for Syn Scan Nmap 

-sT: T for TCP full scan (Full session attack) 

Q. nmap -A: A for aggressive scan (Scans for TCP ports-Versions-Services-OS-NetBIOS enumeration) recommended to be inside network and per target

\- What is Netbios?

UDP is best effort protocol (Connectionless protocol/fastest protocol)
Streaming-voice-Live-DNS-TFTP-DHCP-SNMP

nmap -sU -p [Target IP]: U is for UDP ports, p for ports [port number]
nmap -sn [IP Address]: n for the network (scanning connected live hosts on the network) filtered in result means that this specific port could be open or not (Firewall)

Q. ARP is working on Layer 2 (Data-Link Layer) and used to bind IP address to its Mac Address Uni-cast = 1 to 1  
Multicast multiple targets = 1 to mini (Ping-Sweep)  
Broadcast = 1 to all ARP Packet: who has 10.0.x.x tell [Attacker IP]

Q. If I want to scan a different subnet from mine, Nmap uses ICMP instead of ARP Ping sweep = ICMP scan on multiple targets

1. Live host using nmap -sn [Network IP]
2. Port scan using nmap -sS -sT -sU
3. OS using nmap -A -Script [Discovery or Vulnerability Scan] (nmap --script [Script\]\[Target IP]) -O for OS 
4. Vulnerability: Infra or Web Nessus Nessus: https://www.tenable.com/products/nessus/nessus-essentials

Q. Nessus default port: 8834

Nassus steps:

1. Port scan
2. Service
3. Version
4. OS 
5. Vulnerability

Hostname + IP = scan for Netbios ---> nbtscan [Network IP] command

- Eternal blue CVE

## ***Session 4***

- Metasploit and Expoit-DB are owned by RAPID-7

#### **HW1: What language is used in programming Metasploit?**

![Banner command.png](.attachments.7785/image%20%283%29.png)

Nmap and MSF can be used in basic vulns scans and Nassus can be used in advanced vuln scan

METASPLOIT COMMANDS:

1. aux \[scan\]: used in basic vuln scan without harming the target
2. aux Dos: using methods of DOS attack
3. search \[vuln\]: used to search methods to attack
4. use \[method path/method ID\]
5. show options/options
6. set \[options\] like RHOSTS - LHOST - PORT

run

![image (4).png](.attachments.7785/image%20%284%29.png)

#### **HW2: DOS attack on VM using Metasploit and Nessus or Nmap**

- Single packet attack: means that with one packet I can get the target down

#### **HW3: What is Payload?**

- Command and Control (C2): is controlling the target's machine without his knowledge

**METERPRETER COMMANDS (Post Exploit):**

1. help
2. hashdump
3. shell 
4. net user Ahmed 1234 /add (Creating New User)
5. net localgroup administrators ahmed /add (Privilege Escalation)
6. download \[file\]

- SNMP: 

1. Manager
2. Agent
3. MIB ( Management Information Base ) - Object Identifier

V1 Not used anymore

V2c Most Implemented Community String is the method used in authentication (Public and Private)

V3 Most Secured

![SNMP.png](.attachments.7785/image%20%285%29.png)

## ***Session 5***

overt and covert channel in Metasploit

6 Qs - 10 marks

Q1: Complete

Vulnerability - Risk - Threat

Q2: Explain

APT: Advanced Persistence Threat

SYN-Scan/Half-Session Attack

Full TCP Scan 

Enumeration: Collecting more information about the service  
Netbios  
SNMP

Techniques that used to prevent Brutefource attack

What is Previlage Esclation

Severity and CVSS

What is Steganography?

Covert and Overt

ARP Protocol and ICMP

What is the vulnerability used to exploit ransomware?

#### **HW: What Port is SNMP Using?**

SNMP is using port 161

  
overt and covert channel in Metasploit

Smishing and Fishing and Vishing

UDP Scan - if there's no response from the target then it's OPEN

Explain NMAP nmap -sS -P 445 -O (Explain this command)
DNS Enumeration CNAME- A - AAAA - MX Tool for cracking
What is Hash?
What is NTLM?

GHDB

Give me examples for Google Dorks

1. intitle="TEST"
2. Country=EG

syn stealth

RFC1918

#### **HW2: What is Hashing, What is NTLM, MD5, and What is Rainbow table?**

#### **Final:** 

#### **Distinguish between dictionary attack and brute-force attack**

#### **SE: social engineering toolkit**

Hydra -( l \[I have the user\] - L \[users.txt\] ) -(p \[I have password\] - P \[password.txt\] ) smb://\[target IP\]

![hydra attack.png](.attachments.7785/image%20%286%29.png)

Social Engineering: SEtoolkit

![image (7).png](.attachments.7785/image%20%287%29.png)

![image (9).png](.attachments.7785/image%20%289%29.png)
