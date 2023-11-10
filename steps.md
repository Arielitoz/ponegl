# Next steps
## nmap python - port scanner
- probably add threads or process to make more faster
- write files, log files
- add to database consults (?)
- make a consult based in most common/famous ports

## tcp dump .. Packet Sniffer
- create process and  structure
- write log file, history
- add to databases
- Tried in windows & Linux(Ubuntu): this.works

## Other things || future steps
- https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers#Dynamic,_private_or_ephemeral_ports



### somethings
pulses of eletricity - computer sees ones and zeros, convert them to binary, them to data; Requests & Responses;
IP Packet => Ethernet frame

Ethernet frame -> 
    sync - 8 bytes : router computer sync, they know when they´re receiving packets

    receiver/sender: who´s receiving and sending the data
    receiver - 6 byts
    sender - 6 bytes

    type - 2 byte: ethernet type, protocol
        0x0800 -> IPV4 Frame
        0x0806 -> ARP Request/Response
        0x86DD -> IPV6 Frame
    
    payload - 46byte to 1500byte(IP/ARP frame + padding): main data

    CRC - 4 Bytes : frame check to sure that all received data is correctly without any errors

MAC Address : 48 bit : two decimal, separated by a colon

ip header
    protocol tells us what types of data that package is carrying: focus on ICMP - 1; 6 - TCP; 17 - UDP
