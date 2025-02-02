### PacketParser-python

This program captures packets using Scapy with the specified fields:
- `-c` Determines how many packets will be captured.
- `-f` Uses the BPF filter to specify which packets to capture.
- `-i` Determines which interface it will capture packets on.

Only select packets were implemented. These are:
- TCP
- UDP
- ICMP (IPv4)
- ARP
- ICMP (IPv6)
- DNS

### Running the Program
Clone the repo:
```sh
https://github.com/ClownCrest/PacketParser-python
```
Run with the command:
```sh
sudo python3 main.py -c <count> -f <filter> -i <interface>
```

### Troubleshooting
#### Installing Scapy
Step 1: Run apt update
```sh
sudo apt update
```
Step 2: Install Scapy
```sh
sudo apt install python3-scapy
```
Step 3: Run Scapy
```sh
sudo scapy
```

