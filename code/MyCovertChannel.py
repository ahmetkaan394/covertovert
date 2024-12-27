import random
from CovertChannelBase import CovertChannelBase
from scapy.all import ICMP, IP, sniff


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """



    def __init__(self):
        """
        - You can edit __init__.
        """
        pass

    def send(self, log_file_name, receiver_ip, bit_code_mapping):
        """
        This function encodes a randomly generated binary message into ICMP packets and sends them as part of a covert channel.
        
        Steps performed:
            1. Generates a random binary message using the generate_random_binary_message_with_logging function and logs it to the specified log file.
            2. Ensures the message length is a multiple of 8 (byte-aligned) by prepending leading zeros if necessary.
            3. Encodes the binary message two bits at a time:
                - Looks up the corresponding ICMP code range for the two bits using the bit_code_mapping dictionary.
                - Selects a random integer within the specified range and assigns it to the code field of an ICMP Echo Request (type 8) packet.
            4. Sends each packet using the send function from the CovertChannelBase.py file.  
        """

        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        if len(binary_message) % 8 != 0:
            padding_length = 8 - (len(binary_message)%8)
            binary_message = '0' * padding_length + binary_message

        for i in range(0, len(binary_message), 2):
            two_bits = binary_message[i:i+2]  

            code_range = bit_code_mapping[two_bits]
            code_value = random.randint(code_range[0], code_range[1])

            packet = IP(dst=receiver_ip) / ICMP(type=8, code=code_value)
            super().send(packet)
        

    def receive(self, receiver_ip, bit_code_mapping, sender_ip, log_file_name):
        """
        This function listens for incoming ICMP packets, decodes the covert message from them, and logs the received message.

        Steps performed:
        1. Initializes two lists: one for storing received bits and another for storing the decoded characters.
        2. Defines a `stop_sniff` function that processes each received packet:
            - Checks if the packet is an ICMP Echo Request (type 8) and extracts the ICMP code field.
            - Uses the bit_code_mapping dictionary to map the ICMP code to its corresponding 2-bit binary value.
            - Collects the decoded bits until 8 bits (one byte) are collected.
            - Converts the 8-bit sequence into a character and appends it to the decoded message list.
            - If the decoded character is a period ('.'), it stops the sniffing process to indicate the end of the message.
        3. Starts sniffing ICMP packets from the sender to the receiver using the `sniff` function from Scapy, filtered by the source and destination IP addresses.
        4. Once the message is fully received, the final decoded message is logged to the specified log file.
        """
       
        received_bits = []
        decoded_message = [] 
        
        def stop_sniff(packet):
            if ICMP in packet and packet[ICMP].type == 8:  
                icmp_code = packet[ICMP].code

                for bits, code_range in bit_code_mapping.items():
                    if code_range[0] <= icmp_code <= code_range[1]:
                        received_bits.extend(list(bits))
                        
                        if len(received_bits) >= 8:
                            eight_bits = ''.join(received_bits[:8])  
                            received_bits[:] = received_bits[8:]  
                         
                            character = self.convert_eight_bits_to_character(eight_bits)
                            decoded_message.append(character)

                            if character == ".":
                                return True
            return False
        
        sniff(filter=f"icmp and src {sender_ip} and dst {receiver_ip}", stop_filter=stop_sniff)
        final_message = ''.join(decoded_message)
        self.log_message(final_message, log_file_name)

            
