import re
import os
import sys
import socket
import time
import multiprocessing as mp
from funcs import validate
from funcs import files
from datetime import datetime



open_ports = []
# Regular Expression Pattern to extract the number of ports you want to scan.
# port_range_pattern = re.compile("([0-9]+)-([0-9]+)") - pattern for ranged ports
# You have to specify <lowest_port>-<highest_port> (ex 10-100)

# target - ip, port ranges / socket.AF_INET -> IPV4 family, SOCK_STREAM -> the socket type for TCP, the protocol that will be used to transport messages in the network.
target = ""
port_min = 0
port_max = 65535

def port_scanner():
    try:
        time.sleep(0.5)
        choose_scan_type = input("\n[ --- Scan option: ---] \n\n1 - All Ports\n2 - Common Ports\n\nYour option:> ")
        time.sleep(0.5)
        match choose_scan_type:
                case '1':
                    scan_all_ports()
                case '2':
                    scan_common_ports() 
                case _:
                    print("Insert a valid option")
                    port_scanner()
                    
    except KeyboardInterrupt:
            time.sleep(0.5)
            print("\n\nClosing program...Bye!\n")
            time.sleep(0.5)
            sys.exit()

def scan_common_ports():
    try:
        # print("Number of cpu : ", mp.cpu_count())
        target = validate.validate_ip()

        common_ports = [7,20,21,22,23,25,53,67,68,69,80,110,119,123,135,137,139,143,161,179,194,411,412,443,445,465,500,563,587,636,989,990,993,995,1080,1194,1725,2049,3128,3389,5722,8080]
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
            files.remove_empyt_file(file_name)
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

def scan_all_ports():
    target = validate.validate_ip()
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
    file_name = "log-ports-" + current_time
    file_name = file_name.replace(":", "_")
    try:
        file_write = open(file_name, "x")
    except OSError as e:
        print(f"Error creating file: {e}")
    
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
        files.remove_empyt_file(file_name)        
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

# def scan_ranged_ports():
#     validateIp()

#     #creating file; verify srftime
#     current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S.%f")
#     file_name = "log-ports-" + current_time
#     file_name = file_name.replace(":", "_")
#     try:
#         file_write = open(file_name, "x")
#     except OSError as e:
#         print(f"Error creating file: {e}")
    
#     while True:
#     # You can scan 0-65535 ports. This scanner is basic and doesn't use multithreading so scanning all 
#     # the ports is not advised.
#         print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
#         port_range = input("Enter port range: ")
#         port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
#         if port_range_valid:
#             port_min = int(port_range_valid.group(1))
#             port_max = int(port_range_valid.group(2))
#             break
#     start_time = time.time()
#     print("\nScanning started at: " + str(datetime.now()))
#     print("\n")
#     for port in range(port_min, port_max + 1):
#         try:
#             with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
#                 s.settimeout(0.5)
#                 s.connect((target,port))
#                 open_ports.append(port)
#         except:
#             # We don't need to do anything here. If we were interested in the closed ports we'd put something here.
#             pass
#     if len(open_ports) == 0:
#         time.sleep(0.5)
#         file_write.close()
#         remove_empyt_file(file_name)
#         time.sleep(0.5)
#         print("\nCan´t detect any open ports in that range")
#         confirm_again = input("Insert again? Y/N\nYour choice: ")
#         if confirm_again.upper() == "Y":
#             scan_ranged_ports()
#         else:
#             print("\nThank you, we´re exiting now")
#     else:
#         file_write.write(f"- - - Open Ports on target IP: [ {target} ] - - - \n\n")
#         for port in open_ports:
#             # We use an f string to easily format the string with variables so we don't have to do concatenation.
#             print(f"Port {port} is open on {target}.")
#             file_write.write(f"PORT: {port}\n")
#         file_write.close()

#     end_time = time.time()
#     process_time = (end_time - start_time) * 1000
#     time.sleep(0.5)
#     print(f"\nprocess take {process_time:.2f} in ms.")
#     print("\nExiting now...")
#     sys.exit()