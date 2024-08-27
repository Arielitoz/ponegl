import re

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
# Regular Expression Pattern to extract the number of ports you want to scan.

def validateIp():
    global target
    while True:
        target = input(str("\nPlease enter the ip address that you want to scan: "))
        if ip_add_pattern.search(target):
            print(f"{target} is a valid ip address")
            return target