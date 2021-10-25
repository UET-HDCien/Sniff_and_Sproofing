from scapy.all import *

IPpkt = IP(dst='1.1.1.1', chksum=0)
UDPpkt = UDP(dport=53, chksum=0)
pkt = IPpkt/UDPpkt

with open('udp.bin', 'wb') as f:
	f.write(bytes(pkt))

TCPpkt = TCP(dport=123, sport=80, chksum=0)
pkt2 = IPpkt/TCPpkt

with open('tcp.bin', 'wb') as f:
	f.write(bytes(pkt))

data ="HTTP/1.1 200 OK\r\ncontent-type: text/html; charset=utf-8\r\ncontent-encoding: gzip\r\n\r\n1aff\r\nTrang dang ky da khoa!"
http_pkt = IPpkt/TCPpkt/data

with open('http.bin', 'wb') as f:
	f.write(bytes(http_pkt))
