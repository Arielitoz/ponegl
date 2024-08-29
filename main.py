import sys, socket, time, re, struct, textwrap, threading, multiprocessing, os
import funcs.validate
from datetime import datetime

spacing = '\t\t\t '
# Regular Expression Pattern to extract the number of ports you want to scan.
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# You have to specify <lowest_port>-<highest_port> (ex 10-100)

# target - ip, port ranges / socket.AF_INET -> IPV4 family, SOCK_STREAM -> the socket type for TCP, the protocol that will be used to transport messages in the network.
target = ""
port_min = 0
port_max = 65535

open_ports = []

def scan_all_ports():
    # target = input(str("Target IP: "))
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
    file_name = "log-ports-" + current_time
    file_name = file_name.replace(":", "_")
    try:
        file_write = open(file_name, "x")
    except OSError as e:
        print(f"Error creating file: {e}")

    validateIp()
    
    # Banner
    print('_' * 50)

    print("Scanning target: " + target)
    print("\nScanning started at: " + str(datetime.now()))
    print('_' * 50)

    try:
        file_write.write(f"- - - All Open Ports on target IP: [ {target} ] - - - \n\n")
    # 65,535 existents ports / Scan every port on the target IP
        
        for port in range(port_min,port_max):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            #Return open ports
            response = s.connect_ex((target, port))
            # nwThread = threading.Thread(target=s.connect_ex((target, port)))
            # nwThread.start()
            # nwThread.join()
            # connect_ex/connect == 0, success
            if response == 0:
                print("Port: [{}] is Open".format(port))
                file_write.write(f"Open Port: [{port}]\n")
                s.close()

        file_write.close()
        remove_empyt_file(file_name)        
        # Make a variable to count how much time takes, ms, ex: print("\nScanning ended at: " + str(datetime.now()))

    except KeyboardInterrupt:
        file_write.close()
        if os.path.isfile(file_name):
            os.remove(file_name)
        time.sleep(1)
        print("\n Exiting :(")
        sys.exit()

    except socket.error:
        print("\n Host not responding :(")
        sys.exit()

def scan_ranged_ports():
    validateIp()

    #creating file; verify srftime
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
    file_name = "log-ports-" + current_time
    file_name = file_name.replace(":", "_")
    try:
        file_write = open(file_name, "x")
    except OSError as e:
        print(f"Error creating file: {e}")
    
    while True:
    # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all 
    # the ports is not advised.
        print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
        port_range = input("Enter port range: ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
        if port_range_valid:
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break
    start_time = time.time()
    print("\nScanning started at: " + str(datetime.now()))
    print("\n")
    for port in range(port_min, port_max + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((target,port))
                open_ports.append(port)
        except:
            # We don't need to do anything here. If we were interested in the closed ports we'd put something here.
            pass
    if len(open_ports) == 0:
        time.sleep(0.5)
        file_write.close()
        remove_empyt_file(file_name)
        time.sleep(0.5)
        print("\nCan´t detect any open ports in that range")
        confirm_again = input("Insert again? Y/N\nYour choice: ")
        if confirm_again.upper() == "Y":
            scan_ranged_ports()
        else:
            print("\nThank you, we´re exiting now")
    else:
        file_write.write(f"- - - Open Ports on target IP: [ {target} ] - - - \n\n")
        for port in open_ports:
            # We use an f string to easily format the string with variables so we don't have to do concatenation.
            print(f"Port {port} is open on {target}.")
            file_write.write(f"PORT: {port}\n")
        file_write.close()

    end_time = time.time()
    process_time = (end_time - start_time) * 1000
    time.sleep(0.5)
    print(f"\nprocess take {process_time:.2f} in ms.")
    print("\nExiting now...")
    sys.exit()

def scan_common_ports():
    try:
        target = funcs.validate.validate_ip()

        common_ports = [7,20,21,22,23,25,53,67,68,69,80,110,119,123,135,137,139,143,161,179,194,411,412,443,465,500,563,587,636,989,990,993,995,1080,1194,1725,2049,3128,3389,5722,8080]
        #anotherPorts = 445, 5040,9009,58541,9180,58541,60531,60904
        # common_ports = [27036,49668,65001,58056,57196,58028,61542,139,9009]
        #creating file; verify srftime
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
        file_name = "log-ports-" + current_time
        file_name = file_name.replace(":", "_")
        current_time_str = datetime.now().strftime("%c")
        try:
            file_write = open(file_name, "x")
        except OSError as e:
            print(f"Error creating file: {e}")
        
        start_time = time.time()
        print("\nScanning started at: " + str(datetime.now()))
        print("\n")
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect((target,port))
                    open_ports.append(port)
            except:
                # closed ports,  deal with here
                pass
        if len(open_ports) == 0:
            time.sleep(0.5)
            file_write.close()
            remove_empyt_file(file_name)
            time.sleep(0.5)
            print("\nNone of the common ports listed are open")
            time.sleep(0.5)
            print("\nThank you, we´re exiting now")
            time.sleep(0.5)
            sys.exit()
        else:
            file_write.write(f"- - - Open Common Ports - - - \n\n")
            file_write.write(f"Target IP: [ {target} ]\n")
            file_write.write(f"At time: [ {current_time_str} ] | [ {current_time} ]\n\n")
            for port in open_ports:
                # We use an f string to easily format the string with variables so we don't have to do concatenation.
                print(f"Port {port} is open on {target}.")
                file_write.write(f"PORT: [ {port} ]\n")
            file_write.close()

        end_time = time.time()
        process_time = (end_time - start_time)
        time.sleep(0.5)
        print(f"\nprocess took [{process_time:.2f}s] total.")
        print("\nExiting now...")
        sys.exit()
    except KeyboardInterrupt:
        time.sleep(0.5)
        print("\n\nClosing program...Bye!\n")
        time.sleep(0.5)
        sys.exit()


def port_scanner():
    try:
        time.sleep(0.5)
        print('\n')
        print("=" * 50)
        choose_scan_type = input("[ --- Scan option: ---] \n1 - Scan: All Ports\n2 - Ranged Ports\n3 - Common Ports\nYour option:> ")
        time.sleep(0.5)
        match choose_scan_type:
                case '1':
                    scan_all_ports()
                case '2':
                    scan_ranged_ports()
                case '3':
                   scan_common_ports()
                case _:
                    print("Insert a valid Option")
                    port_scanner()
                    
    except KeyboardInterrupt:
            time.sleep(0.5)
            print("\n\nClosing program...Bye!\n")
            time.sleep(0.5)
            sys.exit()

def remove_empyt_file(name):
    if os.path.isfile(name) and os.path.getsize(name) == 0:
        os.remove(name)

def validate_user_option():
    try:
        choose_input = input("[ --- Choose an option: --- ]\n1 - Port Scanner\n2 - Packet Sniffer\n3 - Close program\nYour option:> ")
        match choose_input:
                case '1':
                    time.sleep(0.5)
                    port_scanner()
                case '2':
                    time.sleep(0.5)
                    packet_routine() 
                case '3':
                    print("Thank you!")
                    sys.exit()
                case _:
                    print("Insert a valid option\n\n")
                    validate_user_option()
                    
    except KeyboardInterrupt:
            time.sleep(0.5)
            print("\n\nClosing program...Bye!\n")
            time.sleep(0.5)
            sys.exit()
    
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

if __name__ == '__main__':
    validate_user_option()