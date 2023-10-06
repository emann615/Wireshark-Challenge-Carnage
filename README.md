# Wireshark Challenge - Carnage

## Desciption
Wireshark is an open-source, cross-platform network packet analyser tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP). It is commonly used as one of the best packet analysis tools. In this lab, I will run through a scenario using Wireshark to analyze network traffic and detect suspicious activities.

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

First I need to view only the HTTP traffic using the following filter: `http`

The defualt time format is in seconds since beginning of capture. Since I am looking for the date and time of the first HTTP connection, I need to change the time format to UTC.

<img src="https://github.com/emann615/emann615/assets/117882385/1b563f4f-3b7c-4d79-9a1c-e85b4e02bfe5" height="70%" width="70%"/>
</br>
</br>

Now I can see the date and time of the first HTTP connection to the malicious IP.

<img src="https://github.com/emann615/emann615/assets/117882385/308a0aa5-700c-458c-9074-b4c56222fc50" height="100%" width="100%"/>
</br>
</br>

**A1) 2021-09-24 16:44:38**

### Q2) What is the name of the zip file that was downloaded?

If I look back at that first HTTP connection, I can see that it is a GET request for a zip file.

<img src="https://github.com/emann615/emann615/assets/117882385/0685cd64-f5b4-41a7-9279-27e8c42a5c62" height="50%" width="50%"/>
</br>
</br>

**A2) documents.zip**

### Q3) What was the domain hosting the malicious zip file?

To find the domain, I need to view the HTTP headers for the GET request. I can find the HTTP headers by looking in the Packet Details Pane. The domain is next to the Host header.

<img src="https://github.com/emann615/emann615/assets/117882385/cfcb9d16-ce6c-444b-86b7-6d1b53f6d2c7" height="50%" width="50%"/>
</br>
</br>

**A3) attirenepal.com**

### Q4) Without downloading the file, what is the name of the file in the zip file?

I can find the file contained in the zip file by viewing the response to the GET request. I can view the response by following the TCP stream.

<img src="https://github.com/emann615/emann615/assets/117882385/eb260e9a-1efe-406c-870b-98b2880a70d9" height="70%" width="70%"/>
</br>
</br>

The request from the client is in red text, and the response from the server is in blue text. If I examin the response, I can see an XLS file.

<img src="https://github.com/emann615/emann615/assets/117882385/bb1d25a8-2ae0-41e7-9633-f8900e10c353" height="80%" width="80%"/>
</br>
</br>

**A4) chart-1530076591.xls**

### Q5) What is the name of the webserver of the malicious IP from which the zip file was downloaded?

If I view the HTTP hearders of the response, I can find the webserver next to the Server header.

<img src="https://github.com/emann615/emann615/assets/117882385/d7a22240-c679-45b4-9dcc-0f26578423bd" height="50%" width="50%"/>
</br>
</br>

**A5) LiteSpeed**

### Q6) What is the version of the webserver from the previous question?

I can find the viersion of the webserver next to the x-powered-by header.

<img src="https://github.com/emann615/emann615/assets/117882385/8c63e757-9b29-484e-814f-7728567c6fa5" height="50%" width="50%"/>
</br>
</br>

**A6) PHP/7.2.34**

### Q7) Malicious files were downloaded to the victim host from multiple domains. What were the three domains involved with this activity?

_Check HTTPS traffic. Narrow down the timeframe from 16:45:11 to 16:45:30._

Based on the hint, I can use the following filter: `frame.time >= "Sep 24, 2021 16:45:11" && frame.time <= "Sep 24, 2021 16:45:30" && tcp.port==443`

<img src="https://github.com/emann615/emann615/assets/117882385/4a64319d-5258-46ec-a89d-835e1746c959" height="100%" width="100%"/>
</br>
</br>

To decrease the amount of packets I have to look through, I can also fiter for only the packets with the Client Hello message by using the following filter: 







<img src="" height="70%" width="70%"/>
</br>
</br>
