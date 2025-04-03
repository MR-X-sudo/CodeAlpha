import socket
import os

def start_sniffer():
    # Create a raw socket to listen to the network traffic
    try:
        # Create a socket and bind it to the network interface
        sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sniffer_socket.bind(("wlan0", 0))  # You might need to change 'eth0' to your network interface name (e.g., 'wlan0')

        print("Starting packet sniffer... Press Ctrl+C to stop.")
        while True:
            # Capture packets
            raw_data, addr = sniffer_socket.recvfrom(65536)
            print(f"Packet captured: {raw_data}")

    except PermissionError:
        print("You need root/admin privileges to capture network packets.")
    except KeyboardInterrupt:
        print("\nSniffer stopped.")
        os._exit(0)

if __name__ == "__main__":
    start_sniffer()
