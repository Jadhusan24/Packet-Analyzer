import socket
import struct

pcap_file = "dns.pcap"  # Specify the path to your pcap file here

# Function to extract packet details from pcap file
def extract_packet_details():
    packet_details = []

    with open(pcap_file, "rb") as file:
        # Read pcap file header (24 bytes)
        pcap_header = file.read(24)

        while True:
            # Read packet header (16 bytes)
            packet_header = file.read(16)

            if not packet_header:
                break  # End of file

            # Unpack packet header fields using struct
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("I I I I", packet_header)

            # Read packet data
            packet_data = file.read(incl_len)

            # Extract relevant packet information
            ethernet_header = packet_data[:14]
            ip_header = packet_data[14:34]

            # Unpack IP header fields using struct
            _, _, _, source_ip, destination_ip, _, _, protocol, _, _ = struct.unpack("!BBHHHBBH4s4s", ip_header)

            # Convert IP addresses from binary to string format
            source_ip = socket.inet_ntoa(struct.pack('!I', source_ip))
            destination_ip = socket.inet_ntoa(struct.pack('!I', destination_ip))

            # Check if the packet contains TCP header
            if protocol == 6 and len(packet_data) >= 54:
                tcp_header = packet_data[34:54]

                # Unpack TCP header fields using struct
                source_port, destination_port, _, _ = struct.unpack("!HH16sH", tcp_header)
            else:
                source_port = 0
                destination_port = 0

            # Store the packet details in a dictionary
            packet_detail = {
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Protocol": protocol
            }

            packet_details.append(packet_detail)

    return packet_details

def main():
    packet_details = extract_packet_details()

    # Display the extracted packet details
    for index, packet_detail in enumerate(packet_details, start=1):
        print("Packet", index)
        print("Source IP:", packet_detail["Source IP"])
        print("Destination IP:", packet_detail["Destination IP"])
        print("Source Port:", packet_detail["Source Port"])
        print("Destination Port:", packet_detail["Destination Port"])
        print("Protocol:", packet_detail["Protocol"])
        print("-" * 30)

if __name__ == "__main__":
    main()
