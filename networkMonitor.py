import sys, socket, time, re, struct, textwrap, threading, multiprocessing
from datetime import datetime

spacing = '\t\t\t '
ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan. 
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
# You have to specify <lowest_port>-<highest_port> (ex 10-100)

# target - ip, port ranges / socket.AF_INET -> IPV4 family, SOCK_STREAM -> the socket type for TCP, the protocol that will be used to transport messages in the network.
target = ""
port_min = 0
port_max = 65535

openPorts = []

def validateIp():
    global target
    while True:
        target = input(str("\nPlease enter the ip address that you want to scan: "))
        if ip_add_pattern.search(target):
            print(f"{target} is a valid ip address")
            return target

def scanAllPorts():
    # target = input(str("Target IP: "))
    currentTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
    fileName = "log" + currentTime
    fileName = fileName.replace(":", "_")
    try:
        fileWrite = open(fileName, "x")
    except OSError as e:
        print(f"Error creating file: {e}")

    validateIp()
    
    # Banner
    print('_' * 50)

    print("Scanning target: " + target)
    print("\nScanning started at: " + str(datetime.now()))
    print('_' * 50)

    try:
    # 65,535 existents ports / Scan every port on the target IP
        
        for port in range(port_min,port_max):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.5)
            #Return open ports
            response = s.connect_ex((target, port))
            # nwThread = threading.Thread(target=s.connect_ex((target, port)))
            # nwThread.start()
            # nwThread.join()
            if response == 0:
                print("[*] Port {} is open".format(port))
                fileWrite.open(fileName, "a")
                fileWrite.write("\nPort {} is open".format(port))
                fileWrite.close()
                s.close()
        
        # Make a variable to count how much time takes, ms, ex: print("\nScanning ended at: " + str(datetime.now()))

    except KeyboardInterrupt:
        print("\n Exiting :(")
        sys.exit()

    except socket.error:
        print("\n Host not responding :(")
        sys.exit()

def scanRangedPorts():
    validateIp()

    #creating file; verify srftime
    currentTime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
    fileName = "log" + currentTime
    fileName = fileName.replace(":", "_")
    try:
        fileWrite = open(fileName, "x")
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
    startTime = time.time()
    print("\nScanning started at: " + str(datetime.now()))
    print("\n")
    for port in range(port_min, port_max + 1):
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((target,port))
                openPorts.append(port)
        except:
            # We don't need to do anything here. If we were interested in the closed ports we'd put something here.
            pass
    if len(openPorts) == 0:
        print("\nCan´t detect any open ports in that range")
        confirmAgain = input("Insert again? Y/N\nYour choice: ")
        if confirmAgain.upper() == "Y":
            scanRangedPorts()
        else:
            print("\nThank you, we´re exiting now")
    else:
        for port in openPorts:
            # We use an f string to easily format the string with variables so we don't have to do concatenation.
            print(f"Port {port} is open on {target}.")
            fileWrite.write(f"\nPort {port} is open on {target}.")
        fileWrite.close()

    endTime = time.time()
    processTime = (endTime - startTime) * 1000
    print(f"\nprocess take {processTime:.2f} in ms.")

def portScanner():

    print("\n")
    print("=" * 50)
    chooseTypeScan = input("[ --- Type a scan option: ---] \n1- Target IP all Ports;\n2-Specific Port;\n3-Range Ports\nYour option: ")
    if chooseTypeScan == "1":
        # print("PORT SCANNER - Python\n")
        scanAllPorts()
    elif chooseTypeScan == "2":
        scanRangedPorts()
        # quit()
    else:
        print("Insert a valid Option")
        portScanner()

def validateUserOption():
    chooseInput = input("[ --- Choose an option: --- ]\n1 - Port Scanner;\n2 - TCP Dump/Packet Sniffer\n3 - Close program\nYour option: ")
    if chooseInput == "1":
        portScanner()
    elif chooseInput == "2":
        print("\n")
        packetRoutine() 
    elif chooseInput == "3":
        print("Thank you!")
            
        quit()
    else:
        print("Insert a valid option\n\n")
        validateUserOption()

# infinite loop, waiting for packets and extract
def packetRoutine():
    try:
        if sys.platform.lower().startswith("win"):
            print("Protocol is not supported in Windows System!! Please, try it in another OS")
            print("\nClosing...")
            quit()
            # in windows, try to use ncap or scapy
        else:
        # need a socket to have connections with other computers]
        # AF_PACKET only works in linux
            print("\nStarting Sniffer - new routine at: " + str(datetime.now()))
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            # last one, ntohns compatible with all machines, little endian, big endian
            while True:
                rawData , address = s.recvfrom(65536)
                destinationMac, sourceMac, ethProtocol, data = ethernetFrame(rawData)
                print('\nEthernet frame: ')
                # {} placeholders
                print('Destination: {}, Source: {}, Protocol: {}'.format(destinationMac, sourceMac, ethProtocol))

                # protocol 8 for IPv4
                if ethProtocol == 8:
                    (version, headerLength, ttl, protocol, source, destination, data) = packetIpv4(data)
                    print("\nIPv4 Packet: \n")
                    print("Version: {}, Header Length: {}, TTL: {}".format(version, headerLength, ttl))
                    print("Protocol: {}, Source: {}, Destination: {}".format(protocol, source, destination))

                    # 1 - ICMP
                    if protocol == 1:
                        icmpType, code, checksum, data = packetIcmp(data)
                        print("\ICMP Packet: \n")
                        print("Type: {}, Code: {}, CheckSum: {}".format(icmpType, code, checksum))
                        print("\nData:\n")
                        print(formatLines(spacing, data))
                    #6 - TCP
                    elif protocol == 6:
                        print(data)
                        print(segmentTcp(data))
                        (sourcePort, destPort, seqNumber, acknowNumber, flagUrg, flagAck, flagPsh, flagRst, flagSin, flagFin) = segmentTcp(data)[:10]
                        print("\nTCP Segment:\n")
                        print("Source port: {}, Destination Port: {}".format(sourcePort, destPort))
                        print("\nSequence: {}, Acknowledgement: {}".format(seqNumber, acknowNumber))
                        print('\nFlags:\n')
                        print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flagUrg, flagAck, flagPsh, flagRst, flagSin, flagFin))
                        print('\nData:\n')
                        print(formatLines(spacing, data))
                    # 17 - UDP
                    elif protocol == 17:
                        (sourcePort, destPort, size, data) = segmentUdp(data)
                        print('\nUDP Segment:\n')
                        print('Source port: {}, Destination port: {}, Length: {}'.format(sourcePort, destPort, size))
                    # other
                    else:
                        print('\nOther Data:\n')
                        print(formatLines(spacing, data))
                else:
                    print('\nData:\n')
                    print(formatLines(spacing,data))

    except KeyboardInterrupt:
        print("\nStopping program...Thanks for the packets.")
        print("\nWe´re leaving now, bye!")
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


validateUserOption()