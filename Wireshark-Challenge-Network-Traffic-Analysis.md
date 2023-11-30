# Wireshark Challenge: Network Traffic Analysis
https://malware-traffic-analysis.net/2022/01/07/2022-01-07-traffic-analysis-exercise.pcap.zip

## Description
Wireshark is an open-source, cross-platform network packet analyzer tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP). It is commonly used as one of the best packet analysis tools. In this lab, I will run through a scenario using Wireshark to analyze network traffic and detect suspicious activities.

## Table of Contents

   * [Languages and Utilities Used](#Languages-and-Utilities-Used)
   * [Environments Used](#Environments-Used)
   * [Walk-Through](#Walk-Through)

## Languages and Utilities Used

* **Wireshark** 

## Environments Used

* **Ubuntu 18.04.6 LTS**

## Walk-Through

### Scenario

Eric Fischer from the Purchasing Department at Bartell Ltd has received an email from a known contact with a Word document attachment. Upon opening the document, he accidentally clicked on "Enable Content."  The SOC Department immediately received an alert from the endpoint agent that Eric's workstation was making suspicious connections outbound. The pcap was retrieved from the network sensor and handed to you for analysis. 

**Task:** Investigate the packet capture and uncover the malicious activities. 

### Q1) What was the date and time for the first HTTP connection to the malicious IP?

First I needed to view only the HTTP traffic using the following filter: `http`

The defualt time format is in seconds since beginning of capture. Since I was looking for the date and time of the first HTTP connection, I needed to change the time format to **UTC**.

<img src="https://github.com/emann615/emann615/assets/117882385/1b563f4f-3b7c-4d79-9a1c-e85b4e02bfe5" height="70%" width="70%"/>
</br>
</br>

Then I was able to see the date and time of the first HTTP connection to the malicious IP.

<img src="https://github.com/emann615/emann615/assets/117882385/308a0aa5-700c-458c-9074-b4c56222fc50" height="100%" width="100%"/>
</br>
</br>

**A1) 2021-09-24 16:44:38**

### Q2) What is the name of the zip file that was downloaded?

I looked back at that first HTTP connection and was able to see that it is a GET request for a zip file.

<img src="https://github.com/emann615/emann615/assets/117882385/0685cd64-f5b4-41a7-9279-27e8c42a5c62" height="50%" width="50%"/>
</br>
</br>

**A2) documents.zip**

### Q3) What was the domain hosting the malicious zip file?

To find the domain, I needed to view the HTTP headers for the GET request. I found the HTTP headers by looking in the packet details pane. The domain is next to the **Host** header.

<img src="https://github.com/emann615/emann615/assets/117882385/cfcb9d16-ce6c-444b-86b7-6d1b53f6d2c7" height="50%" width="50%"/>
</br>
</br>

**A3) attirenepal.com**

### Q4) Without downloading the file, what is the name of the file in the zip file?

I found the file contained in the zip file by viewing the response to the GET request. I viewed the response by following the **TCP stream**.

<img src="https://github.com/emann615/emann615/assets/117882385/eb260e9a-1efe-406c-870b-98b2880a70d9" height="70%" width="70%"/>
</br>
</br>

The request from the client is in red text, and the response from the server is in blue text. I examined the response and found a **XLS** file.

<img src="https://github.com/emann615/emann615/assets/117882385/bb1d25a8-2ae0-41e7-9633-f8900e10c353" height="80%" width="80%"/>
</br>
</br>

**A4) chart-1530076591.xls**

### Q5) What is the name of the webserver of the malicious IP from which the zip file was downloaded?

I looked at the HTTP hearders of the response and found the webserver next to the **Server** header.

<img src="https://github.com/emann615/emann615/assets/117882385/d7a22240-c679-45b4-9dcc-0f26578423bd" height="50%" width="50%"/>
</br>
</br>

**A5) LiteSpeed**

### Q6) What is the version of the webserver from the previous question?

I found the viersion of the webserver next to the **x-powered-by** header.

<img src="https://github.com/emann615/emann615/assets/117882385/8c63e757-9b29-484e-814f-7728567c6fa5" height="50%" width="50%"/>
</br>
</br>

**A6) PHP/7.2.34**

### Q7) Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?

_Check HTTPS traffic. Narrow down the timeframe from 16:45:11 to 16:45:30._

I fitered for HTTPS traffic and the timeframe using the following filter: `frame.time >= "Sep 24, 2021 16:45:11" && frame.time <= "Sep 24, 2021 16:45:30" && tcp.port==443`

<img src="https://github.com/emann615/emann615/assets/117882385/4a64319d-5258-46ec-a89d-835e1746c959" height="100%" width="100%"/>
</br>
</br>

To decrease the amount of packets I had to look through, I modified the fiter to show only the packets with the **Client Hello** message by using the following filter: `(frame.time >= "Sep 24, 2021 16:45:11" && frame.time <= "Sep 24, 2021 16:45:30" && tcp.port==443) && (tls.handshake.type == 1)`

<img src="https://github.com/emann615/emann615/assets/117882385/077b2a33-a49d-45fb-a182-05723e901153" height="100%" width="100%"/>
</br>
</br>

I examined the packet information and found three suspicous domains.

<img src="https://github.com/emann615/emann615/assets/117882385/7ed0bd47-2d6b-478f-8912-eb277218fe62" height="60%" width="60%"/>
</br>
</br>

<img src="https://github.com/emann615/emann615/assets/117882385/42cf283b-8e6d-4761-b21a-f663e8a84ed7" height="60%" width="60%"/>
</br>
</br>

<img src="https://github.com/emann615/emann615/assets/117882385/1b68ce3a-6377-4f7b-9bd1-d4fb36482541" height="60%" width="60%"/>
</br>
</br>

**A7) finejewels.com.au, thietbiagt.com, new.americold.com**

### Q8) Which certificate authority issued the SSL certificate to the first domain from the previous question?

I selected the packet with the first domain and followed the **TCP stream** to find the certificate authority.

<img src="https://github.com/emann615/emann615/assets/117882385/45e9ac7c-456d-4e73-b96b-9d6b8cd5abc3" height="90%" width="90%"/>
</br>
</br>

**A8) GoDaddy**

### Q9) What are the two IP addresses of the Cobalt Strike servers? Use VirusTotal (the Community tab) to confirm if IPs are identified as Cobalt Strike C2 servers. (answer format: enter the IP addresses in sequential order)

_Check the Conversations menu option._

First, I filtered for only the **HTTP and HTTPS** traffic using the following filter: `tcp.port==443 || tcp.port==80`

Next, I selected the **Conversations** menu option to view a list of **IPv4** addresses that were contacted.

<img src="https://github.com/emann615/emann615/assets/117882385/135f5e8a-d14b-4ea7-b003-b45ed2cafb16" height="50%" width="50%"/>
</br>
</br>

After going through the list of IP addresses and analyzing them in VirusTotal, I was able to find the two Cobalt Strike servers.

<img src="https://github.com/emann615/emann615/assets/117882385/48198359-3103-4d80-bec3-2e68677c478e" height="60%" width="60%"/>
</br>
</br>

<img src="https://github.com/emann615/emann615/assets/117882385/d578cf9b-4644-46f4-94ff-7f0ebe7bf033" height="50%" width="50%"/>
</br>
</br>

<img src="https://github.com/emann615/emann615/assets/117882385/b28435ce-2e8a-48db-b73e-2f42f28719e2" height="60%" width="60%"/>
</br>
</br>

<img src="https://github.com/emann615/emann615/assets/117882385/d389bbed-090c-4914-b1f9-3ed7107ed44a" height="70%" width="70%"/>
</br>
</br>

**A9) 185.106.96.158, 185.125.204.174**

### Q10) What is the Host header for the first Cobalt Strike IP address from the previous question?

I filtered for HTTP traffic and the IP address of the first Cobalt Strike server (185.106.96.158) using the following filter: `http && ip.addr==185.106.96.158`

Then, I selected the first packet and followed the TCP stream to find the **Host** header.

<img src="https://github.com/emann615/emann615/assets/117882385/44703f6d-3fa4-4987-bd24-e918bfae0c90" height="50%" width="50%"/>
</br>
</br>

**A10) ocsp.verisign.com**

### Q11) What is the domain name for the first IP address of the Cobalt Strike server? You may use VirusTotal to confirm if it's the Cobalt Strike server.

_Filter out for DNS queries_

I filtered for DNS queries using the following filter: `dns`

There are 381 DNS packets. Instead of going through 381 packets, I wanted to see if I could filter the packets some more so I could find the domain name quicker.

<img src="https://github.com/emann615/emann615/assets/117882385/1237ad8f-be98-4adf-9eb7-9563f76179be" height="100%" width="100%"/>
</br>
</br>

I was able to filter for the IP address in the DNS query using the following filter: dns.a==185.106.96.158

That left one packet, and in the **Info** column I was able to see the domain name.

<img src="https://github.com/emann615/emann615/assets/117882385/882821f0-a824-486f-8314-d696b6f292dd" height="100%" width="100%"/>
</br>
</br>

I searched the IP address in VirusTotal, and checked the **Relations** tab. The domain name was also listed there.

<img src="https://github.com/emann615/emann615/assets/117882385/7d67161d-b801-4559-b405-1585dbb30141" height="70%" width="70%"/>
</br>
</br>

**A11) survmeter.live**

### Q12) What is the domain name of the second Cobalt Strike server IP?  You may use VirusTotal to confirm if it's the Cobalt Strike server.


I repeated the steps in the previous question to find the domain name of the second server using the following filter: `dns.a==185.125.204.174`

<img src="https://github.com/emann615/emann615/assets/117882385/48d0c3ee-9ae8-4366-aaf0-bd079a19cb84" height="100%" width="100%"/>
</br>
</br>

<img src="https://github.com/emann615/emann615/assets/117882385/81df5edc-7ae3-4e00-a28c-4ee31aaaed91" height="70%" width="70%"/>
</br>
</br>

**A12) securitybusinpuff.com**

### Q13) What is the domain name of the post-infection traffic?

_Filter Post HTTP traffic_

I filtered for POST HTTP traffic using the following filter: `http.request.method==POST`

Next, I selected the first packet and followed the TCP stream. I found the domain name next to the **Host** header.

<img src="https://github.com/emann615/emann615/assets/117882385/d618f58b-b35a-4c5d-8ef7-09e53e5c1736" height="60%" width="60%"/>
</br>
</br>

**A13) maldivehost.net**

### Q14) What are the first eleven characters that the victim host sends out to the malicious domain involved in the post-infection traffic? 

I went back to the TCP stream and saw the first eleven characters of the POST request.

<img src="https://github.com/emann615/emann615/assets/117882385/a27f556e-fe97-4302-acec-290b72ee503e" height="60%" width="60%"/>
</br>
</br>

**A14) zLIisQRWZI9**

### Q15) What was the length for the first packet sent out to the C2 server?

Back on the packet list pane I was able to see the length of the POST request packet in the **Length** column.

<img src="https://github.com/emann615/emann615/assets/117882385/054cf97e-03ce-4fa0-be79-ffbd6bf734b2" height="100%" width="100%"/>
</br>
</br>

**A15) 281**

### Q16) What was the Server header for the malicious domain from the previous question?

I pulled back up the TCP stream and found the response from the malicious domain to the POST request to see the **Server** header. 

<img src="https://github.com/emann615/emann615/assets/117882385/f6d2f0f8-0413-404b-b17c-8a2f540d29fe" height="60%" width="60%"/>
</br>
</br>

**A16) Apache/2.4.49 (cPanel) OpenSSL/1.1.1l mod_bwlimited/1.4**

### Q17) The malware used an API to check for the IP address of the victim’s machine. What was the date and time when the DNS query for the IP check domain occurred?

I found the API using the following filter: `dns contains "api"`

I saw a few DNS queries that look interesting going to api.ipify.org.

<img src="https://github.com/emann615/emann615/assets/117882385/c687b83f-bbfc-40d6-b9e4-8aa2e1e274ab" height="100%" width="100%"/>
</br>
</br>

I went to ipify.org in my web browser and saw that it is an API used to find your public IP address.

<img src="https://github.com/emann615/emann615/assets/117882385/abb77bcc-0bd7-4987-8c9e-4768dc6a5872" height="70%" width="70%"/>
</br>
</br>

**A17) 2021-09-24 17:00:04**

### Q18) What was the domain in the DNS query from the previous question?

The domain was found while answering the previous question.

**A18) api.ipify.org**

### Q19) Looks like there was some malicious spam (malspam) activity going on. What was the first MAIL FROM address observed in the traffic?


I filtered for the SMTP trafffic using the following filter: `smtp`

After scrolling through the packets I came across one with a MAIL FROM address in the **Info** column.

<img src="https://github.com/emann615/emann615/assets/117882385/0eaaad4f-8a35-4182-bbf2-623e990a1118" height="100%" width="100%"/>
</br>
</br>

**A19) farshin@mailfa.com**

### Q20) How many packets were observed for the SMTP traffic?

The number of packets was displayed in the bottom Status bar.

<img src="https://github.com/emann615/emann615/assets/117882385/e021dc10-2014-4962-b31f-4b52cf04db21" height="30%" width="30%"/>
</br>
</br>

**A20) 1439**

