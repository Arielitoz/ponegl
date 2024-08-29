import sys, time
from funcs import scan as sc
from funcs import sniffer as sf

def validate_user_option():
    try:
        choose_input = input("\n[ --- Choose an option: --- ]\n\n1 - Port Scanner\n2 - Packet Sniffer\n\nPress Ctrl+C to close program!\n\nYour option:> ")
        match choose_input:
                case '1':
                    time.sleep(0.5)
                    sc.port_scanner()
                case '2':
                    time.sleep(0.5)
                    sf.packet_routine()
                case _:
                    print("Insert a valid option\n\n")
                    validate_user_option()
                    
    except KeyboardInterrupt:
            time.sleep(0.5)
            print("\n\nClosing program...Bye!\n")
            time.sleep(0.5)
            sys.exit()

if __name__ == '__main__':
    validate_user_option()