from scapy.all import *
import sys

def syn_scan(target_ip, target_port):
    
    pkt = IP(dst=target_ip)/TCP(dport=target_port,flags="S")
    resp =  sr1(pkt,timeout=1,verbose=0)

    if resp and resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            return "[+] {} OPEN".format(target_port)
        else:
            pass
    else:
        return "[-] {} CLOSED".format(target_port)
        

if __name__ == "__main__":
    target = sys.argv[1]

    portas = [21,22,23,25,53,80,110,143,443]

    for porta in portas:
        status_port = syn_scan(target_ip=target,target_port=porta)

        if status_port:
            print(status_port)