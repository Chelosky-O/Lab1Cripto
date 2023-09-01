import sys
import scapy.all as scapy
from collections import Counter
import string

# Función para descifrar un mensaje con un corrimiento dado
def decrypt_cesar_cipher(message, shift):
    decrypted_message = ""
    for char in message:
        if char.isalpha():
            char_type = str.maketrans('', '', string.ascii_uppercase) if char.isupper() else str.maketrans('', '', string.ascii_lowercase)
            char = chr(((ord(char) - ord('A' if char.isupper() else 'a')) - shift) % 26 + ord('A' if char.isupper() else 'a'))
        decrypted_message += char
    return decrypted_message

# Función para calcular la probabilidad de un mensaje en español
def calculate_probability(message):
    letter_frequencies = {
        'a': 0.1217, 'b': 0.0220, 'c': 0.0402, 'd': 0.0501, 'e': 0.1249, 'f': 0.0069,
        'g': 0.0177, 'h': 0.0070, 'i': 0.0625, 'j': 0.0044, 'k': 0.0002, 'l': 0.0497,
        'm': 0.0315, 'n': 0.0671, 'o': 0.0868, 'p': 0.0251, 'q': 0.0088, 'r': 0.0687,
        's': 0.0798, 't': 0.0463, 'u': 0.0393, 'v': 0.0090, 'w': 0.0001, 'x': 0.0022,
        'y': 0.0090, 'z': 0.0052, ' ': 0.1700
    }
    
    message = message.lower()
    probability = 1.0
    for char in message:
        if char in letter_frequencies:
            probability *= letter_frequencies[char]
    return probability

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt.py <pcapng_file>")
        sys.exit(1)

    pcapng_file = sys.argv[1]

    # Leer el archivo pcapng y obtener paquetes ICMP
    packets = scapy.rdpcap(pcapng_file)
    icmp_packets = [pkt for pkt in packets if pkt.haslayer(scapy.ICMP)]

    if not icmp_packets:
        print("No se encontraron paquetes ICMP en el archivo.")
        sys.exit(1)

    # Extraer el primer byte de la data de los paquetes ICMP
    extracted_data = ""
    for packet in icmp_packets:
        data = packet[scapy.Raw].load[8]  # Saltar los 8 bytes de timestamp
        extracted_data += chr(data)

    # Crear una lista con todos los posibles corrimientos
    possible_messages = []
    for shift in range(26):
        possible_message = decrypt_cesar_cipher(extracted_data, shift)
        possible_messages.append(possible_message)

    # Calcular la probabilidad de cada mensaje
    probabilities = [calculate_probability(message) for message in possible_messages]

    # Imprimir los mensajes con sus respectivos corrimientos
    for shift, message, probability in zip(range(26), possible_messages, probabilities):
        if max(probabilities) == probability:
            print(f"\033[92m(Corrimiento {shift}: {message})\033[0m")
        else:
            print(f"(Corrimiento {shift}: {message})")

if __name__ == "__main__":
    main()
