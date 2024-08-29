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
                rawData , address = s.recvfrom(65536)
                destinationMac, sourceMac, ethProtocol, data = ethernetFrame(rawData)
                print('\nEthernet frame: ')
                # {} placeholders
                print('Destination: {}, Source: {}, Protocol: {}'.format(destinationMac, sourceMac, ethProtocol))

                file_write.write("\n====================")
                file_write.write('\nEthernet frame: ')
                file_write.write('Destination: {}, Source: {}, Protocol: {}'.format(destinationMac, sourceMac, ethProtocol))                

                # protocol 8 for IPv4
                if ethProtocol == 8:
                    (version, headerLength, ttl, protocol, source, destination, data) = packetIpv4(data)
                    print("\nIPv4 Packet: \n")
                    print("Version: {}, Header Length: {}, TTL: {}".format(version, headerLength, ttl))
                    print("Protocol: {}, Source: {}, Destination: {}".format(protocol, source, destination))

                    file_write.write("\n====================")
                    file_write.write("\nIPv4 Packet: \n")
                    file_write.write("Version: {}, Header Length: {}, TTL: {}".format(version, headerLength, ttl))
                    file_write.write("Protocol: {}, Source: {}, Destination: {}".format(protocol, source, destination))

                    # 1 - ICMP
                    if protocol == 1:
                        icmpType, code, checksum, data = packetIcmp(data)
                        print("\ICMP Packet: \n")
                        print("Type: {}, Code: {}, CheckSum: {}".format(icmpType, code, checksum))
                        print("\nICMP Data:\n")
                        print(formatLines(spacing, data))

                        file_write.write("\n====================")
                        file_write.write("\nICMP Packet: \n")
                        file_write.write("Type: {}, Code: {}, CheckSum: {}".format(icmpType, code, checksum))
                        file_write.write("\nICMP Data:\n")
                        file_write.write(formatLines(spacing, data))

                    #6 - TCP
                    elif protocol == 6:
                        # print(data)
                        # print(segmentTcp(data))
                        (sourcePort, destPort, seqNumber, acknowNumber, flagUrg, flagAck, flagPsh, flagRst, flagSin, flagFin) = segmentTcp(data)[:10]
                        print("\nTCP Segment:\n")
                        print("Source port: {}, Destination Port: {}".format(sourcePort, destPort))
                        print("\nSequence: {}, Acknowledgement: {}".format(seqNumber, acknowNumber))
                        print('\nFlags:\n')
                        print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flagUrg, flagAck, flagPsh, flagRst, flagSin, flagFin))
                        print('\nTCP Data:\n')
                        print(formatLines(spacing, data))

                        file_write.write("\n====================")
                        file_write.write("\nTCP Segment:\n")
                        file_write.write("Source port: {}, Destination Port: {}".format(sourcePort, destPort))
                        file_write.write("\nSequence: {}, Acknowledgement: {}".format(seqNumber, acknowNumber))
                        file_write.write('\nFlags:\n')
                        file_write.write('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flagUrg, flagAck, flagPsh, flagRst, flagSin, flagFin))
                        file_write.write('\nTCP Data:\n')
                        file_write.write(formatLines(spacing, data))

                        # hexData = (str(data)[2:])
                        hexData = data.hex()
                        replacedData = hexData.replace("\\","")
                        try:
                            binarys = []
                            byteData = bytes.fromhex(replacedData)
                            binaryData = " ".join(f"'{byte:08b}'" for byte in byteData ).replace(" ", ",")
                            
                            # binarys = [bin.strip("'") for bin in binarys]
                            # intValues = [int(binary,2) for binary in binarys]
                            # asciiData = ''.join(chr(value) for value in intValues)
                            file_write.write("\nTCP DATA bin\n:")
                            file_write.write(f"{binaryData}")
                            # file_write.write(decodedText)
                        except ValueError as err:
                            print(f"Value Error: {err}")
                    # 17 - UDP
                    elif protocol == 17:
                        (sourcePort, destPort, size, data) = segmentUdp(data)
                        print('\nUDP Segment:\n')
                        print('Source port: {}, Destination port: {}, Length: {}'.format(sourcePort, destPort, size))

                        file_write.write("\n====================")
                        file_write.write('\nUDP Segment:\n')
                        file_write.write('Source port: {}, Destination port: {}, Length: {}'.format(sourcePort, destPort, size))
                    # other
                    else:
                        print("---"*30)
                        print('\nOTHER DATA:\n')
                        print(formatLines(spacing, data))

                        file_write.write("\n====================")
                        file_write.write('\nOTHER DATA:\n')
                        file_write.write(formatLines(spacing, data))
                        
                else:
                    print("---"*30)
                    print('\nDATA:\n')
                    print(formatLines(spacing,data))

                    file_write.write("\n====================")
                    file_write.write('\nDATA:\n')
                    file_write.write(formatLines(spacing,data))  

    except KeyboardInterrupt:
        file_write.close()
        time.sleep(1)
        print("\nStopping program...Thanks for the packets.")
        time.sleep(0.5)
        print("\nWe´re leaving now, bye!")
        time.sleep(0.5)
        sys.exit()

# unpack ethernet frame
def ethernetFrame(data):
    # ! threat like a network data, the way network data is stored in computer is different thant the way it flows across the network: little endian / Big-endian
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    # start to beginning; follow for 14 next bytes
    return getMacAddress(destination_mac), getMacAddress(source_mac), socket.htons(protocol), data[14:]
    # htons convert big-endian/ little-endian &7 data 14: to the end

# return formatted MAC address (Ex: AA:BB:CC:DD:EE:FF)
def getMacAddress(bytesAddress):
    # map() function and iterate
    bytesToString = map('{:02x}'.format, bytesAddress)
    return  ':'.join(bytesToString).upper()

# unpack IPV4 packet, not interested in ARP or something like that - version, ihl(header length), TTL, SRC, DEST, comes before ip payload/data
# the length of the header is used to determine where data starts, header ends, data begins
def packetIpv4(data):
    versionHlength = data[0]
    version = versionHlength >> 4
    headerLength = (versionHlength & 15) * 4
    ttl, protocol, source, destination = struct.unpack('! 8x B B 2x 4s 4s',data[:20]) # the format data is going to be unpackeds
    return version, headerLength, ttl, protocol, getIpv4(source), getIpv4(destination), data[headerLength:]

# returns formatted IPV4 (Ex: 192.142.000.243)
def getIpv4(address):
    return '.'.join(map(str, address))

# unpacks ICMP packet : Internet control message protocol
def packetIcmp(data):
    icmpType, code, checksum = struct.unpack('! B B H', data[:4])
    return icmpType, code, checksum, data[4:] # 4 to the end

# unpacks TCP segment: Transmission Control protocol /tcp/ip
# source port, dest port, sequence number, acknow number: flags -> tcp 3-way handshake flags ex: syn, ack, fin
def segmentTcp(data):
    (sourcePort, destPort, seqNumber, acknowNumber, offsetReservedFlags) = struct.unpack('! H H L L H', data[:14])
    # bitwise operators
    offset = (offsetReservedFlags >> 12) * 4
    flagUrg = (offsetReservedFlags & 32) >> 5
    flagAck = (offsetReservedFlags & 16) >> 4
    flashPsh = (offsetReservedFlags & 8) >> 3
    flagRst = (offsetReservedFlags & 4) >> 2
    flagSin = (offsetReservedFlags & 2) >> 1
    flagFin = offsetReservedFlags & 1

    return sourcePort, destPort, seqNumber, acknowNumber, flagUrg,flagAck, flashPsh, flagRst, flagSin, flagFin, data[offset:] 

# unpacks UDP segment: User datagram protocol
def segmentUdp(data):
    sourcePort, destPort, size = struct.unpack('! H H 2x H', data[:8])
    return sourcePort, destPort, size, data[8:]

# formats text and multi data to display
def formatLines(prefix, dataString, size=80):
    size -= len(prefix)
    if isinstance(dataString, bytes):
        dataString = ''.join(r'\x{:02x}'.format(byte) for byte in dataString)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(dataString, size)])