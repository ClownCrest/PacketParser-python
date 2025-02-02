### PacketParser-python

This program captures packets using scapy with the specificied the following fields:
-c Determines how many packets will be captured
-f Uses the BPF Filter to specifcy which packets to capture
-i Determines what interface it will capture packets on.

Only select packets were implemented. These are:
- TCP 
- UDP 
- ICMP(IPv4)
- ARP
- ICMP(IPv6)
- DNS


### Running the Program
Clone the repo:
```https://github.com/ClownCrest/PacketParser-python```
Run with the command:
```sudo python3 main.py -c <count> -f <filter> -i <interface>```

### Troubleshooting
Installing Scapy
Step 1: Run apt update
```sudo apt update```
Step 2: Install Scapy
```sudo apt install python3-scapy```
Step 3: run Scapy
```sudo scapy```
