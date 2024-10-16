import re
import os
import sys
import socket
import time
from multiprocessing import Pool
from funcs import validate
from funcs import files
from datetime import datetime

open_ports = []

# target - ip, port ranges / socket.AF_INET -> IPV4 family, SOCK_STREAM -> the socket type for TCP, the protocol that will be used to transport messages in the network.
target = ""
# port_min = 1
# port_max = 65535

# def port_scanner():
#     try:
#         time.sleep(0.5)
#         choose_scan_type = input("\n[ --- Scan option: ---] \n\n1 - All Ports\n2 - Common Ports\n\nYour option:> ")
#         time.sleep(0.5)
#         match choose_scan_type:
#                 case '1':
#                     scan_common_ports() 
#                 case _:
#                     print("Insert a valid option")
#                     port_scanner()
                    
#     except KeyboardInterrupt:
#             time.sleep(0.5)
#             print("\n\nClosing program...Bye!\n")
#             time.sleep(0.5)
#             sys.exit()

# Tuple - target(ip) / port 
def scan_port(target_port):
    target, port = target_port
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            response = s.connect_ex((target, port))
            if response == 0:
                return port
    except socket.error:
        print("\n Host not responding :(")
        sys.exit()
    except:
        return None
   
def scan_file_template(target, address, ports):
    try:
        #creating file; verify srftime
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
        file_name = "log-ports-" + current_time.replace(":", "_")
        current_time_str = datetime.now().strftime("%c")

        try:
            file_write = open(file_name, "x")
        except OSError as e:
            print(f"Error creating file: {e}")
            return
        
        start_time = time.time()
        print("\nScanning started at: " + str(datetime.now()))
        print("\n")

        #Tuple for mapping
        target_ports = [(target, port) for port in ports]

        # Pool - parallel scan
        with Pool() as pool:
            open_ports = pool.map(scan_port, target_ports)

        # Filtering open ports
        open_ports = [port for port in open_ports if port is not None]

        if not open_ports:
            time.sleep(0.5)
            file_write.close()
            files.remove_empyt_file(file_name)
            time.sleep(0.5)
            print("\nNone of the common ports listed are open")
            time.sleep(0.5)
            print("\nThank you, we´re exiting now")
            time.sleep(0.5)
            sys.exit()
        else:
            file_write.write(f"- - - - - - - - Open Ports - - - - - - - - \n\n")
            file_write.write(f"Target IP: [ {target} ]\n")
            file_write.write(f"Target host/address: [ {address} ]\n")
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
        file_write.close()
        if os.path.isfile(file_name):
            os.remove(file_name)
        time.sleep(1)
        print("Closing Program.. :(")
        sys.exit()

def scan_common_ports():
        
        [target , address_target] = validate.validate_ip()

        common_ports = [7,20,21,22,23,25,53,67,68,69,80,110,119,123,135,137,139,143,161,179,194,411,412,443,445,465,500,563,587,636,989,990,993,995,1080,1194,1725,2049,3128,3389,5722,8080]
        
        scan_file_template(target, address_target, common_ports)
       
# def scan_all_ports(port_min=1, port_max=65535):

#     [target , address_target] = validate.validate_ip()

#     ports = range(port_min, port_max + 1)

#     scan_file_template(target, address_target, ports)