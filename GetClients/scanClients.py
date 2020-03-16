from scapy.all import *

interface = 'wlp0s20f0u1mon'
APs = []

def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig

def pkt_callback(pkt):
    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)

    elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
        # This means it's data frame.
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        if sn in APs:
            print "AP (%s) > STA (%s)" % (sn, rc)
        elif rc in APs:
            print "AP (%s) < STA (%s)" % (rc, sn)

if __name__ == "__main__":
    thread = threading.Thread(target=hopper, args=(interface, ), name="hopper")
    thread.daemon = True
    thread.start()

    sniff(iface=interface, prn=pkt_callback)

