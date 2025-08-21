 Python-IDS
A Python-based Intrusion Detection System that monitors network activity and detects suspicious behavior.
Intrusion Detection Tool (IDS)

A simple Python-based Intrusion Detection Tool built with Scapy. It monitors network traffic and detects suspicious activities such as SYN floods and ICMP floods.

Features

✅ Real-time packet sniffing

✅ Detects SYN flood attempts

✅ Detects ICMP (ping) floods

✅ Lightweight and beginner-friendly

Installation

Install Python 3

sudo apt install python3

Install scapy

sudo pip3 install scapy
Clone the project

git clone https://github.com/Metshet81/Python-IDS.git

cd Python-IDS

Usage

Run the detector script to start capturing packets:

sudo python3 detector.py

How It Works

The tool uses Scapy to sniff incoming packets.

It tracks TCP SYN packets (possible SYN flood) and ICMP packets (possible ping flood).

If the number of packets exceeds a threshold (e.g., >25 packets in 10 seconds), it raises an alert.

Example Output
ALERT:Possible SYN flood Detected!
ALERT:Possible SYN flood Detected!.....


