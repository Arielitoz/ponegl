import re
import socket
import sys

# ReGex about ip pattern Eg. 127.32.23.94
ip_addr_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
website_regex_pattern = re.compile('^www\.[a-zA-Z0-9-]+(\.[a-zA-Z]{2,}){1,2}(?<!/)$')

def validate_ip():
    try:
        selection_param = input("\n[ --- Select an input method: --- ]\n\n1 - DNS\n2 - IP\n\nYour option:> ")
        match selection_param:
                case '1':
                    try:
                        while True:
                            target_address = input("\nEnter website name [Format Eg. www.google.com.br]: ")
                            match = re.match(website_regex_pattern,target_address)
                            if match:
                                target = socket.gethostbyname(target_address)
                                # url = 'http://%s:80/clients/' % target
                                # print(f"1 - {target_address}")
                                # print(f"2 - {target}")
                                # print(f"3 - {url}")
                                if ip_addr_pattern.search(target):
                                    print(f"{target} is a valid ip address")
                                    return target
                            else:
                                print("Try another website name!")
                    except ValueError:
                        print("\nCould not read the name of the website.")
                    except Exception as err:
                        # print(f"Unexpected {err=}, {type(err)=}")
                        print(f"Internal error trying to acess: {target}")
                        raise

                case '2':
                    while True:
                        target = input(str("\nPlease enter the ip address that you want to scan: "))
                        if ip_addr_pattern.search(target):
                            print(f"{target} is a valid ip address")
                            return target
                case _:
                    validate_ip()
            
    except KeyboardInterrupt:
        print("\nEnding now.")
        sys.exit()