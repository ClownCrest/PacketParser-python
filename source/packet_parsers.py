import textwrap
width = 90

# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print("=" * width)
    wrapped_hex = textwrap.fill(hex_data, width=width)
    print(wrapped_hex)
    print("=" * width)

    print(f"{'Parsing Ethernet Header'.center(width)}")
    print("-" * width)
    print("Ethernet Header:")
    print(f"  {'Destination MAC:':<27} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<27} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<27} {ether_type:<20} | {int(ether_type, 16)}")
    print()

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        print(f"{'Parsing ARP Header'.center(width)}")
        print("-" * width)
        parse_arp_header(payload)
    elif ether_type == "0800":  #IPv4
        print(f"{'Parsing IPv4 Header'.center(width)}")
        print("-" * width)
        parse_ipv4_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<27} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")
    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    operations = int(hex_data[12:16], 16)
    senders_mac = ':'.join(hex_data[i:i+2] for i in range(16, 28, 2))
    senders_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(28, 36, 2))
    target_mac = ':'.join(hex_data[i:i+2] for i in range(36, 48, 2))
    target_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(48, 56, 2))

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<27} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<27} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<27} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<27} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<27} {hex_data[12:16]:<20} | {operations}")
    print(f"  {'Sender MAC:':<27} {hex_data[16:28]:<20} | {senders_mac}")
    print(f"  {'Sender IP:':<27} {hex_data[28:36]:<20} | {senders_ip}")
    print(f"  {'Target MAC:':<27} {hex_data[36:48]:<20} | {target_mac}")
    print(f"  {'Target IP:':<27} {hex_data[48:56]:<20} | {target_ip}")
    print("=" * width)

# Parse IPv4 header
def parse_ipv4_header(hex_data):

    version = int(hex_data[0:1], 16)
    internet_header_length = int(hex_data[1:2], 16)
    type_of_service = int(hex_data[2:4], 16)
    total_length = int(hex_data[4:8], 16)
    identification = int(hex_data[8:12], 16)
    flags_and_frag_offset = int(hex_data[12:16], 16)
    #ttl = int(hex_data[16:18], 16)
    protocol = int(hex_data[18:20], 16)
    #check_sum = int(hex_data[20:24], 16)
    source_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(24, 32, 2))
    destination_ip = '.'.join(str(int(hex_data[i:i+2], 16)) for i in range(32, 40, 2))

    #Convert frags and offset to binary
    flags_and_frag_offset_bin = bin(flags_and_frag_offset)[2:].zfill(16)
    reserved_bit = flags_and_frag_offset_bin[0]
    df_bit = flags_and_frag_offset_bin[1]
    mf_bit = flags_and_frag_offset_bin[2]
    frag_offset_int = int(flags_and_frag_offset_bin[3:], 2)
    frag_offset_hex = hex(frag_offset_int)


    print(f"IPv4 Header:")
    print(f"  {'Version':<27} {hex_data[0:1]:<20} | {version}")
    print(f"  {'Header Length':<27} {hex_data[1:2]:<20} | {internet_header_length}")
    #print(f"  {'Type of Service':<27} {hex_data[2:4]:<20} | {type_of_service}")
    print(f"  {'Total Length':<27} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Identification':<27} {hex_data[8:12]:<20} | {identification}")
    print(f"  {'Flags & Frag Offset ':<27} {hex_data[12:16]:<20} | 0b{flags_and_frag_offset_bin}")
    print(f"    {'Reserved Bit:':<23}   {reserved_bit}")
    print(f"    {'DF (Do not Fragment):':<23}   {df_bit}")
    print(f"    {'MF (More Fragments):':<23}   {mf_bit}")
    print(f"    {'Fragment Offset:':<25} {frag_offset_hex:<20} | {frag_offset_int}")
    #print(f"  {'TTL':<27} {hex_data[16:18]:<20} | {ttl}")
    print(f"  {'Protocol':<27} {hex_data[18:20]:<20} | {protocol}")
    #print(f"  {'Check Sum':<27} {hex_data[20:24]:<20} | {check_sum}")
    print(f"  {'Source IP':<27} {hex_data[24:32]:<20} | {source_ip}")
    print(f"  {'Destination IP':<27} {hex_data[32:40]:<20} | {destination_ip}")

    if protocol == 17:
        parse_udp_header(hex_data[40:])
    elif protocol == 6:
        parse_tcp_header(hex_data[40:])
    elif protocol == 1:
        parse_icmp_header(hex_data[40:])
    else:
        print(f"  {'Unknown Protocol:':<27} {hex_data[18:20]:<20} | {protocol}")
        print("  No parser available for this Protocol.")

# Parse UDP header
def parse_udp_header(hex_data):
    source_port = int(hex_data[0:4], 16)
    destination_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)
    payload = hex_data[16:]
    wrapped_payload = textwrap.fill(payload, width=width)

    print()
    print(f"{'Parsing UDP Header'.center(width)}")
    print("-" * width)
    print(f"UDP Header:")
    print(f"  {'Source Port':<27} {hex_data[0:4]:<20} | {source_port}")
    print(f"  {'Destination Port':<27} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Length':<27} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum':<27} {hex_data[12:16]:<20} | {checksum}")
    print(f"{'-' * ((width - len('UDP Payload')) // 2)}UDP Payload{'-' * (90 - len('UDP Payload') - ((width - len('UDP Payload')) // 2))}")
    print(f"{wrapped_payload}")
    print("=" * width)

# Parse TCP header
def parse_tcp_header(hex_data):
    source_port = int(hex_data[0:4], 16)
    destination_port = int(hex_data[4:8], 16)
    sequence_number = int(hex_data[8:16], 16)
    ack_number = int(hex_data[16:24], 16)
    data_offset = int(hex_data[24:25], 16)
    reserved = int(hex_data[25:26], 16)
    flags = int(hex_data[26:28], 16)
    flags_bin = bin(flags)[2:].zfill(12)
    window = int(hex_data[28:32], 16)
    checksum = int(hex_data[32:36], 16)
    urgent_pointer = int(hex_data[36:40], 16)
    payload_offset = data_offset * 4 #calculate where the payload begins in bytes relative to the start of the TCP header.
                                     #Data offset is in 4 byte words, so we multiply by 4 to get the byte offset.
    payload = hex_data[payload_offset*2:] #multiply by 2 because we are working with hex data. 1 byte = 2 hex characters
    wrapped_payload = textwrap.fill(payload, width=width)

    print()
    print(f"{'Parsing TCP Header'.center(width)}")
    print("-" * width)
    print(f"TCP Header:")
    print(f"  {'Source Port':<27} {hex_data[0:4]:<20} | {source_port}")
    print(f"  {'Destination Port':<27} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Sequence Number':<27} {hex_data[8:16]:<20} | {sequence_number}")
    print(f"  {'Ack Number':<27} {hex_data[16:24]:<20} | {ack_number}")
    print(f"  {'Data Offset':<27} {hex_data[24:25]:<20} | {data_offset}")
    print(f"  {'Reserved':<27} {hex_data[25:26]:<20} | {reserved}")
    print(f"  {'Flags':<25}   0b{flags_bin[3:12]:<18} | {flags}")
    print(f"    {'NS':<23}   {flags_bin[3]}")
    print(f"    {'CWR':<23}   {flags_bin[4]}")
    print(f"    {'ECE':<23}   {flags_bin[5]}")
    print(f"    {'URG':<23}   {flags_bin[6]}")
    print(f"    {'ACK':<23}   {flags_bin[7]}")
    print(f"    {'PSH':<23}   {flags_bin[8]}")
    print(f"    {'RST':<23}   {flags_bin[9]}")
    print(f"    {'SYN':<23}   {flags_bin[10]}")
    print(f"    {'FIN':<23}   {flags_bin[11]}")
    print(f"  {'Window':<27} {hex_data[28:32]:<20} | {window}")
    print(f"  {'Checksum':<27} {hex_data[32:36]:<20} | {checksum}")
    print(f"  {'Urgent Pointer':<27} {hex_data[36:40]:<20} | {urgent_pointer}")
    print(f"{'-' * ((width - len('TCP Payload')) // 2)}TCP Payload{'-' * (90 - len('TCP Payload') - ((width - len('TCP Payload')) // 2))}")
    print(f"{wrapped_payload}")
    print("=" * width)

# Parse ICMP header
def parse_icmp_header(hex_data):
    icmp_type = int(hex_data[0:2], 16)
    code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)
    payload = hex_data[48:]
    wrapped_payload = textwrap.fill(payload, width=width)

    print(f"{'Parsing ICMP Header'.center(width)}")
    print("-" * width)
    print(f"ICMP Header:")
    print(f"  {'Type':<27} {hex_data[0:2]:<20} | {icmp_type}")
    print(f"  {'Code':<27} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum':<27} {hex_data[4:8]:<20} | {checksum}")
    print(f"{'-' * ((width - len('ICMP Payload')) // 2)}ICMP Payload{'-' * (90 - len('ICMP Payload') - ((width - len('ICMP Payload')) // 2))}")
    print(f"{wrapped_payload}")
    print("=" * width)