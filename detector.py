from scapy.all import sniff, TCP, IP, UDP, ICMP
import time
icmp_count=0
syn_count=0
udp_count=0
start_time=time.time()
def detect(packet):
    global icmp_count,syn_count,udp_count,start_time
    if start_time-time.time()>10 :
        syn_count=0
        icmp_count=0
        udp_count=0
        start_time=time.time()
    if packet.haslayer(TCP) and packet[TCP].flags=="S":
        syn_count+=1
        if syn_count>25:
            print ("ALERT:Possible SYN flood Detected!")
    if packet.haslayer(ICMP):
        icmp_count+=1
        if icmp_count>25:
            print ("ALERT:Possible ICMP flood Detected!")
    if packet.haslayer(UDP):
        udp_count+=1
        if udp_count>25:
            print ("ALERT:Possible UDP flood Detected!")
sniff(prn=detect ,store=0)

