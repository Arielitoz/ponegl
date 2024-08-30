import sys
import time
import socket
import struct
import textwrap
from funcs import files
from datetime import datetime




spacing = '\t\t\t '
# infinite loop, waiting for packets and extract
def packet_routine():

    #creating file; verify srftime
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
    file_name = "log-sniffer-" + current_time
    file_name = file_name.replace(":", "_")

    try:
        file_write = open(file_name, "x")
    except OSError as e:
        print(f"Error creating file: {e}")

    try:
        if sys.platform.lower().startswith("win"):
            time.sleep(1)
            print("Protocol is not supported in Windows System!! Please, try it in another OS")
            file_write.close()
            files.remove_empyt_file(file_name)
            print("\nClosing...")
            sys.exit()
            # in windows, try to use ncap or scapy
        else:
        # need a socket to have connections with other computers]
        # AF_PACKET only works in linux
            file_write.write(f"- - - Sniffing Data at - - -\n")
            print("\nStarting Sniffer - new routine at: " + str(datetime.now()))
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            # last one, ntohns compatible with all machines, little endian, big endian
            while True:
                raw_data , address = s.recvfrom(65536)
                destination_mac, source_mac, eth_protocol, data = ethernet_frame(raw_data)
                print('\nEthernet frame: ')
                # {} placeholders
                print('Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, eth_protocol))

                file_write.write("\n====================")
                file_write.write('\nEthernet frame: ')
                file_write.write('Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, eth_protocol))                

                # protocol 8 for IPv4
                if eth_protocol == 8:
                    (version, header_length, ttl, protocol, source, destination, data) = packet_ipv4(data)
                    print("\nIPv4 Packet: \n")
                    print("Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
                    print("Protocol: {}, Source: {}, Destination: {}".format(protocol, source, destination))

                    file_write.write("\n====================")
                    file_write.write("\nIPv4 Packet: \n")
                    file_write.write("Version: {}, Header Length: {}, TTL: {}".format(version, header_length, ttl))
                    file_write.write("Protocol: {}, Source: {}, Destination: {}".format(protocol, source, destination))

                    # 1 - ICMP
                    if protocol == 1:
                        icmp_type, code, checksum, data = packet_icmp(data)
                        print("\ICMP Packet: \n")
                        print("Type: {}, Code: {}, CheckSum: {}".format(icmp_type, code, checksum))
                        print("\nICMP Data:\n")
                        print(format_lines(spacing, data))

                        file_write.write("\n====================")
                        file_write.write("\nICMP Packet: \n")
                        file_write.write("Type: {}, Code: {}, CheckSum: {}".format(icmp_type, code, checksum))
                        file_write.write("\nICMP Data:\n")
                        file_write.write(format_lines(spacing, data))

                    #6 - TCP
                    elif protocol == 6:
                        # print(data)
                        # print(segment_tcp(data))
                        (source_port, dest_port, seq_number, acknow_number, flag_urg, flag_ack, flag_psh, flag_rst, flag_sin, flag_fin) = segment_tcp(data)[:10]
                        print("\nTCP Segment:\n")
                        print("Source port: {}, Destination Port: {}".format(source_port, dest_port))
                        print("\nSequence: {}, Acknowledgement: {}".format(seq_number, acknow_number))
                        print('\nFlags:\n')
                        print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_sin, flag_fin))
                        print('\nTCP Data:\n')
                        print(format_lines(spacing, data))

                        file_write.write("\n====================")
                        file_write.write("\nTCP Segment:\n")
                        file_write.write("Source port: {}, Destination Port: {}".format(source_port, dest_port))
                        file_write.write("\nSequence: {}, Acknowledgement: {}".format(seq_number, acknow_number))
                        file_write.write('\nFlags:\n')
                        file_write.write('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_sin, flag_fin))
                        file_write.write('\nTCP Data:\n')
                        file_write.write(format_lines(spacing, data))

                        # hex_data = (str(data)[2:])
                        hex_data = data.hex()
                        replaced_data = hex_data.replace("\\","")
                        try:
                            binarys = []
                            byte_data = bytes.fromhex(replaced_data)
                            binary_data = " ".join(f"'{byte:08b}'" for byte in byte_data ).replace(" ", ",")
                            
                            # binarys = [bin.strip("'") for bin in binarys]
                            # intValues = [int(binary,2) for binary in binarys]
                            # asciiData = ''.join(chr(value) for value in intValues)
                            file_write.write("\nTCP DATA bin\n:")
                            file_write.write(f"{binary_data}")
                            # file_write.write(decodedText)
                        except ValueError as err:
                            print(f"Value Error: {err}")
                    # 17 - UDP
                    elif protocol == 17:
                        (source_port, dest_port, size, data) = segment_udp(data)
                        print('\nUDP Segment:\n')
                        print('Source port: {}, Destination port: {}, Length: {}'.format(source_port, dest_port, size))

                        file_write.write("\n====================")
                        file_write.write('\nUDP Segment:\n')
                        file_write.write('Source port: {}, Destination port: {}, Length: {}'.format(source_port, dest_port, size))
                    # other
                    else:
                        print("---"*30)
                        print('\nOTHER DATA:\n')
                        print(format_lines(spacing, data))

                        file_write.write("\n====================")
                        file_write.write('\nOTHER DATA:\n')
                        file_write.write(format_lines(spacing, data))
                        
                else:
                    print("---"*30)
                    print('\nDATA:\n')
                    print(format_lines(spacing,data))

                    file_write.write("\n====================")
                    file_write.write('\nDATA:\n')
                    file_write.write(format_lines(spacing,data))  

    except KeyboardInterrupt:
        file_write.close()
        time.sleep(1)
        print("\nStopping program...Thanks for the packets.")
        time.sleep(0.5)
        print("\nWe´re leaving now, bye!")
        time.sleep(0.5)
        sys.exit()

# unpack ethernet frame
def ethernet_frame(data):
    # ! threat like a network data, the way network data is stored in computer is different thant the way it flows across the network: little endian / Big-endian
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    # start to beginning; follow for 14 next bytes
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(protocol), data[14:]
    # htons convert big-endian/ little-endian &7 data 14: to the end

# return formatted MAC address (Ex: AA:BB:CC:DD:EE:FF)
def get_mac_address(bytes_address):
    # map() function and iterate
    bytes_to_string = map('{:02x}'.format, bytes_address)
    return  ':'.join(bytes_to_string).upper()

# unpack IPV4 packet, not interested in ARP or something like that - version, ihl(header length), TTL, SRC, DEST, comes before ip payload/data
# the length of the header is used to determine where data starts, header ends, data begins
def packet_ipv4(data):
    version_hlength = data[0]
    version = version_hlength >> 4
    header_length = (version_hlength & 15) * 4
    ttl, protocol, source, destination = struct.unpack('! 8x B B 2x 4s 4s',data[:20]) # the format data is going to be unpackeds
    return version, header_length, ttl, protocol, getIpv4(source), getIpv4(destination), data[header_length:]

# returns formatted IPV4 (Ex: 192.142.000.243)
def getIpv4(address):
    return '.'.join(map(str, address))

# unpacks ICMP packet : Internet control message protocol
def packet_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:] # 4 to the end

# unpacks TCP segment: Transmission Control protocol /tcp/ip
# source port, dest port, sequence number, acknow number: flags -> tcp 3-way handshake flags ex: syn, ack, fin
def segment_tcp(data):
    (source_port, dest_port, seq_number, acknow_number, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    # bitwise operators
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flashPsh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_sin = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return source_port, dest_port, seq_number, acknow_number, flag_urg,flag_ack, flashPsh, flag_rst, flag_sin, flag_fin, data[offset:] 

# unpacks UDP segment: User datagram protocol
def segment_udp(data):
    source_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, dest_port, size, data[8:]

# formats text and multi data to display
def format_lines(prefix, dataString, size=80):
    size -= len(prefix)
    if isinstance(dataString, bytes):
        dataString = ''.join(r'\x{:02x}'.format(byte) for byte in dataString)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(dataString, size)])