from scapy.all import *

IPpkt = IP(dst='1.1.1.1', chksum=0)
UDPpkt = UDP(dport=53, chksum=0)
pkt = IPpkt/UDPpkt

with open('udp.bin', 'wb') as f:
	f.write(bytes(pkt))

TCPpkt = TCP(dport=80, chksum=0)
pkt2 = IPpkt/TCPpkt

with open('tcp.bin', 'wb') as f:
	f.write(bytes(pkt))

data ="HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-encoding: gzip"
http_pkt = IPpkt/TCPpkt/data
