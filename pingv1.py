import sys
import time
import random
from scapy.all import *

def generate_icmp_packet(dest_ip, identification, sequence, identifier, data):
    ip_packet = IP(dst=dest_ip, id=identification)
    icmp_packet = ICMP(id=identifier, seq=sequence) / data
    return ip_packet / icmp_packet

def main():
    if len(sys.argv) != 2:
        print("Uso: python programa.py <palabra>")
        sys.exit(1)

    palabra = sys.argv[1]

    dest_ip = "8.8.8.8"
    identification = random.randint(1, 100)
    sequence = 1
    identifier = random.randint(1, 100)

    for char in palabra:
        timestamp = int(time.time()).to_bytes(8, byteorder='little')
        hex_string = "69 8f 00 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37".split()
        hex_string[0] = hex(ord(char))[2:]
        hex_data = "".join(hex_string)
        combined_data = timestamp.hex() + hex_data
        packet = generate_icmp_packet(dest_ip, identification, sequence, identifier, bytes.fromhex(combined_data))
        send(packet)
        
        identification += random.randint(100, 250)
        sequence += 1

if __name__ == "__main__":
    main()
