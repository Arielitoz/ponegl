import sys
import socket
from datetime import datetime

# imports from pyfiglet import Figlet

print("PORT SCANNER - Python\n")

target = input(str("Target IP: "))

# Banner
print('_' * 50)
print("Scanning target: " + target)
print("\nScanning started at: " + str(datetime.now()))
print('_' * 50)

'''
#startTime = ""
endTime = ""
totalEndtime = ""
 startTime = str(datetime.now())
    print(startTime)

    print("oi\n" * 10)
    endTime = str(datetime.now())
    print(endTime)

    totalEndtime = int(startTime) - int(endTime)
    print(totalEndtime)
    https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Dynamic,_private_or_ephemeral_ports
'''
try:
    # 65,535 existents ports / Scan every port on the target IP
    for port in range(1,65535):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)

        #Return open ports
        response = s.connect_ex((target, port))
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
