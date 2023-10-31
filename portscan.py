import sys
import socket
from datetime import datetime

# imports from pyfiglet import Figlet

def scanPort():

    print("\n")
    print("=" * 50)
    chooseTypeScan = input("[ --- Type a scan option: ---] \n1- Target IP all Ports;\n2-Specific Port;\n3-Range Ports\nYour option: ")
    if chooseTypeScan == "1":
        # print("PORT SCANNER - Python\n")
        target = input(str("Target IP: "))

        # Banner
        print('_' * 50)
        print("Scanning target: " + target)
        print("\nScanning started at: " + str(datetime.now()))
        print('_' * 50)

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
    elif chooseTypeScan == "2":
        print("Oi")
        quit() 
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

