# ============================================================
# TASK 1: BASIC NETWORK SNIFFER
# Educational / Lab Use
# ============================================================

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


# ------------------------------------------------------------
# Function to identify protocol
# ------------------------------------------------------------
def get_protocol(packet):

    if packet.haslayer(TCP):
        return "TCP"

    elif packet.haslayer(UDP):
        return "UDP"

    elif packet.haslayer(ICMP):
        return "ICMP"

    else:
        return "Other"


# ------------------------------------------------------------
# Function called for every captured packet
# ------------------------------------------------------------
def packet_callback(packet):

    print("\n" + "=" * 70)

    # Current time
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("Time:", timestamp)

    # Check whether packet contains IP information
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = get_protocol(packet)

        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)
        print("Protocol       :", protocol)

        # ----------------------------------------------------
        # TCP information
        # ----------------------------------------------------
        if packet.haslayer(TCP):

            tcp_layer = packet[TCP]

            print("Source Port    :", tcp_layer.sport)
            print("Destination Port:", tcp_layer.dport)
            print("TCP Flags      :", tcp_layer.flags)

        # ----------------------------------------------------
        # UDP information
        # ----------------------------------------------------
        elif packet.haslayer(UDP):

            udp_layer = packet[UDP]

            print("Source Port    :", udp_layer.sport)
            print("Destination Port:", udp_layer.dport)

        # ----------------------------------------------------
        # ICMP information
        # ----------------------------------------------------
        elif packet.haslayer(ICMP):

            icmp_layer = packet[ICMP]

            print("ICMP Type      :", icmp_layer.type)
            print("ICMP Code      :", icmp_layer.code)

        # ----------------------------------------------------
        # Payload information
        # ----------------------------------------------------
        if packet.haslayer(Raw):

            payload = packet[Raw].load

            # Display maximum 100 bytes
            display_payload = payload[:100]

            print("Payload (max 100 bytes):")

            try:
                print(display_payload.decode("utf-8", errors="replace"))
            except Exception:
                print(display_payload)

        else:
            print("Payload        : No Raw payload")

    else:
        print("Non-IP Packet")
        print("Packet Type    :", packet.summary())


# ------------------------------------------------------------
# Main program
# ------------------------------------------------------------
def main():

    print("=" * 70)
    print("          BASIC NETWORK SNIFFER")
    print("=" * 70)

    print("\nStarting packet capture...")
    print("Press CTRL+C to stop.\n")

    try:

        # Capture packets
        # count=0 means continue until CTRL+C
        sniff(
            prn=packet_callback,
            store=False,
            count=0
        )

    except KeyboardInterrupt:

        print("\n\nPacket capture stopped.")

    except PermissionError:

        print("\nPermission denied.")
        print("Run the program with administrator/root privileges.")


# ------------------------------------------------------------
# Start program
# ------------------------------------------------------------
if __name__ == "__main__":
    main()