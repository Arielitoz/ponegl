import re
import socket
import sys
from dns import resolver, reversename

# ReGex about ip pattern Eg. 127.32.23.94
ipv4_addr_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# ipv6_addr_pattern = re.compile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
website_regex_pattern = re.compile(r"^(https?://)?(www\.)?[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})(\.[a-zA-Z]{2,})?(/[^\s]*)?$")

def validate_ip():
    try:
        selection_param = input("\n[ --- Select an input method: --- ]\n\n1 - DNS\n2 - IPv4\n\nYour option:> ")
        match selection_param:
                case '1':
                    try:
                        while True:
                            target_address = input("\nEnter website name [Format Eg. www.google.com.br]: ")
                            match = re.match(website_regex_pattern,target_address)
                            if match:
                                target = socket.gethostbyname(target_address)
                                # url = 'http://%s:80/clients/' % target
                                if ipv4_addr_pattern.search(target):
                                    print(f"{target} is a valid ip address")
                                    return target, target_address
                            else:
                                print("Try another website name!")
                    except ValueError:
                        print("\nCould not read the name of the website.")
                    except Exception as err:
                        # print(f"Unexpected {err=}, {type(err)=}")
                        print(f"Internal error trying to acess: {target}")
                        print(f"\n Error: {err}")
                        raise
                case '2':
                    while True:
                        target = input(str("\nPlease enter the ipv4 address that you want to scan: "))
                        if ipv4_addr_pattern.search(target):
                            print(f"{target} is a valid ip address")
                            address_dns = reversename.from_address(target)
                            address_dns_reverse = str(resolver.query(address_dns,"PTR")[0])
                            return target, address_dns_reverse
                # case '3':
                #     while True:
                #             target = input(str("\nPlease enter the ipv6 address that you want to scan: "))
                #             if ipv6_addr_pattern.search(target):
                #                 print(f"{target} is a valid ip address")
                #                 address_dns = reversename.from_address(target) or None
                #                 address_dns_reverse = str(resolver.query(address_dns,"PTR")[0]) or None
                #                 print(address_dns_reverse)
                #                 return target, address_dns_reverse
                case _:
                    validate_ip()
            
    except KeyboardInterrupt:
        print("\nEnding now.")
        sys.exit()