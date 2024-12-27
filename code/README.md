# Covert Storage Channel that exploits Protocol Field Manipulation using Code field in ICMP

## Introduction

In this project, we implement a covert communication channel using ICMP packets to send and receive hidden messages. This covert channel leverages the code field of ICMP Echo Request packets (type 8) to encode binary data, which is then sent from a sender to a receiver. The receiver decodes the message from the ICMP packets by mapping the ICMP code to binary data.

This project aims to maximize the covert channel's capacity by optimizing the encoding and transmission process.

## Functionality

The project is divided into two main parts: **sending** and **receiving** messages. These two functions allow communication between a sender and a receiver via a covert channel.

### Sending the Message

The `send` function encodes a randomly generated binary message into ICMP packets. It follows these steps:
1. **Generate Binary Message**: A random binary message is generated.
2. **Align the Message**: The message is padded to ensure that its length is a multiple of 8 bits (byte-aligned) if needed.
3. **Encoding**: The binary message is encoded in two-bit chunks, and the corresponding ICMP code is chosen randomly from the range read from `bit_code_mapping` dictionary.
4. **Send ICMP Packets**: Each encoded binary pair is mapped to an ICMP Echo Request (type 8) packet, which is then sent to the receiver.

The covert channel capacity (in bits per second) is calculated by measuring the time it takes to send a fixed-length message and dividing the message size (128 bits) by the elapsed time.

### Receiving the Message

The `receive` function listens for ICMP packets from the specified sender, decodes the binary message embedded in them, and logs the final decoded message. The process involves:
1. **Sniffing ICMP Packets**: The receiver listens for incoming ICMP packets from the sender.
2. **Decoding**: For each packet, the ICMP code is mapped back to the corresponding binary value. 
3. **Message Assembly**: The binary values are assembled into a complete message, which is converted from binary to text characters. Decoding and assembly processes are being done inside stop sniff function.
4. **End of Message**: The receiver stops listening when a dot character (`.`) is encountered, signaling the end of the message.

## Covert Channel Capacity

The covert channel capacity is measured by sending a 128-bit message (16 characters). These parts of code are removed after testing capacity. The steps to calculate the capacity are as follows:

1. **Create Binary Message**: Generate a 128-bit binary message containing 16 characters.
2. **Start Timer**: Begin timing just before sending the first packet using Python's time library. 
3. **End Timer**: Stop the timer immediately after sending the last packet.
4. **Calculate Time**: Compute the difference in time between the start and end of transmission.
5. **Calculate Capacity**: Divide 128 by the elapsed time to determine the covert channel capacity in bits per second.

### Capacity 

Generating a random binary message of length 128-bits (16 characters), the capacity is 115.96 bits per second. 
