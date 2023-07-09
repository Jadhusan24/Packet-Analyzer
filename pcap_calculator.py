import pyshark

def analyze_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    
    # Initialize counters
    total_packets = 0
    tcp_packets = 0
    udp_packets = 0
    icmp_packets = 0
    http_requests = 0
    dns_requests = 0
    
    for packet in capture:
        total_packets += 1
        
        if 'TCP' in packet:
            tcp_packets += 1
        elif 'UDP' in packet:
            udp_packets += 1
        elif 'ICMP' in packet:
            icmp_packets += 1
        
        if 'HTTP' in packet:
            http_requests += 1
        elif 'DNS' in packet:
            dns_requests += 1
    
    print("Total packets: ", total_packets)
    print("TCP packets: ", tcp_packets)
    print("UDP packets: ", udp_packets)
    print("ICMP packets: ", icmp_packets)
    print("HTTP requests: ", http_requests)
    print("DNS requests: ", dns_requests)

analyze_pcap("dns.pcap")
