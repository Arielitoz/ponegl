import sys
import socket
from datetime import datetime
import time
import re
import threading
import multiprocessing

# imports from pyfiglet import Figlet

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan. 
# You have to specify <lowest_port_number>-<highest_port_number> (ex 10-100)
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

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

def scanTargetIp():
    # target = input(str("Target IP: "))
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

    endTime = time.time()
    processTime = (endTime - startTime) * 1000
    print(f"\nprocess take {processTime:.2f} in ms.")

def scanPort():

    print("\n")
    print("=" * 50)
    chooseTypeScan = input("[ --- Type a scan option: ---] \n1- Target IP all Ports;\n2-Specific Port;\n3-Range Ports\nYour option: ")
    if chooseTypeScan == "1":
        # print("PORT SCANNER - Python\n")
        scanTargetIp()
    elif chooseTypeScan == "2":
        scanRangedPorts()
        # quit()
    else:
        print("Insert a valid Option")
        scanPort()

def validateUserOption():
    validarEscolha = input("[ --- Choose an option: --- ]\n1 - Scan Port;\n2 - TCP Dump\n3 - Close program\nYour option: ")
    if validarEscolha == "1":
        scanPort()
    elif validarEscolha == "2":
        print("\n")
        print("oi")    
    elif validarEscolha == "3":
        print("Thank you!")
            
        quit()
    else:
        print("Insert a valid option\n\n")
        validateUserOption()

validateUserOption()