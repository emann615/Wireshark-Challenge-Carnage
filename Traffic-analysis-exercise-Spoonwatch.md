#  Traffic Analysis Exercise - Spoonwatch

## Pcap
https://malware-traffic-analysis.net/2022/01/07/2022-01-07-traffic-analysis-exercise.pcap.zip

## Scenario
-	LAN segment range: 192.168.1.0/24 (10.9.10.0 through 10.9.10.255)
-	Domain: spoonwatch.net
-	Domain Controller: 192.168.1.2 - SPOONWATCH-DC
-	LAN segment gateway: 192.168.1.1
-	LAN segment broadcast address: 192.168.1.255

## Task
-	Write an incident report based on the pcap and alerts.
-	The incident report should contain the following:
-	Executive Summary
-	Details (of the infected Windows host)
-	Indicators of Compromise (IOCs)

## Investigation
1.	First, I applied my Basic Web filter.
2.	I found the victim’s IP address in the Source of the returned packets.
a.	192.168.1.216
3.	I selected the first packet and went to the packet details.
4.	I expanded the Ethernet details and found the victim’s mac address next to Source.
a.	9c:5c:8e:32:58:f9
5.	Next, I used the following search query: `nbns or smb or smb2`
6.	The Info column of the returned packets shows the Windows Host Name of the victim’s machine.
a.	DESKTOP-GXMYNO2
7.	I used the following search query: `kerberos.CNameString`
8.	In the CNameString column I found the victim’s user account name.
a.	steve.smith
9.	I view the HTTP traffic using the following search query: `(http.request) and !(ssdp)`
10.	There are multiple POST requests over port 80 to a suspicious IP address 2.56.57.108
11.	I searched the IP address in VirusTotal and it was identified as malicious.
a.	The IP address is also associated with a file sample that has been identified as OskiStealer malware.
12.	The URI for each POST request contains a file.
13.	I exported the HTTP objects and saved the files from Hostname 2.56.57.108
14.	I opened Terminal and used the `file` command to see what type of files they are.
15.	I got the SHA256 hash of each file using the following command: shasum -a 256 [file]

## Incident report

### Executive Summary

On Jan 6, 2022 at approximately 16:07 UTC a Windows host used by Steve Smith was infected with OskiStealer malware.

### Victim Details

-	IP Address: 192.168.1.216
-	MAC Address: 9c:5c:8e:32:58:f9
-	Windows Hostname: DESKTOP-GXMYNO2
-	User Account Name: steve.smith

### Indicators of Compromise (IOCs)

Malicious traffic:

-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//1.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//2.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//3.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//4.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//5.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//6.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//7.jpg HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk//main.php HTTP/1.1
-	2.56.57.108 port 80 - 2.56.57.108 - POST /osk/ HTTP/1.1 (zip)

Files:

SHA256 hash: 16574f51785b0e2fc29c2c61477eb47bb39f714829999511dc8952b43ab17660
- File size: 645,592 bytes
- File location: http://2.56.57.108/osk//1.jpg
- File type: PE32 executable (DLL) (console) Intel 80386, for MS Windows
- File description: sqlite3.dll (used by various legitimate programs)

SHA256 hash: a770ecba3b08bbabd0a567fc978e50615f8b346709f8eb3cfacf3faab24090ba
- File size: 334,288 bytes
- File location: http://2.56.57.108/osk//2.jpg
- File type: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
- File description: freebl3.dll (used in Thunderbird)

SHA256 hash: 3fe6b1c54b8cf28f571e0c5d6636b4069a8ab00b4f11dd842cfec00691d0c9cd
- File size: 137,168 bytes
- File location: http://2.56.57.108/osk//3.jpg
- File type: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
- File description: mozglue.dll (used in Thunderbird)

SHA256 hash: 334e69ac9367f708ce601a6f490ff227d6c20636da5222f148b25831d22e13d4
- File size: 440,120 bytes
- File location: http://2.56.57.108/osk//4.jpg
- File type: PE32 executable (DLL) (console) Intel 80386, for MS Windows
- File description: msvcp140.dll (Microsoft C Runtime Library)

SHA256 hash: e2935b5b28550d47dc971f456d6961f20d1633b4892998750140e0eaa9ae9d78
- File size: 1,246,160 bytes
- File location: http://2.56.57.108/osk//5.jpg
- File type: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
- File description: nss3.dll (used by various legitimate programs)

SHA256 hash: 43536adef2ddcc811c28d35fa6ce3031029a2424ad393989db36169ff2995083
- File size: 144,848 bytes
- File location: http://2.56.57.108/osk//6.jpg
- File type: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
- File description: softokn3.dll (used by Thunderbird)

SHA256 hash: c40bb03199a2054dabfc7a8e01d6098e91de7193619effbd0f142a7bf031c14d
- File size: 83,784 bytes
- File location: http://2.56.57.108/osk//7.jpg
- File type: PE32 executable (DLL) (console) Intel 80386, for MS Windows
- File description: vcruntime140.dll (Microsoft C Runtime Library)

SHA256 hash: 7b8ab07521c24e8ec610611e7e15d2fd39336166db6509885b8500d2a2bbfb14
- File size: 25 bytes
- File location: http://2.56.57.108/osk//main.php
- File type: ASCII text, with CRLF line terminators

SHA256 hash: 1ecee6ff37e03c1160b8bf66d5ca8dc784e0b35fb9fd105f0964b314d310c07f
- File size: 379629 bytes
- File location: http://2.56.57.108/osk
- File type: osk: data

