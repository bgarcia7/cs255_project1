from OpenSSL import SSL
import socket
import urlparse
import utils as ut
import sys

context = SSL.Context(SSL.SSLv3_METHOD)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

p_url = urlparse.urlparse('https://sha256.badssl.com')

#=====[ Get remote host ]=====
HOST = p_url.hostname  

port = 443

print HOST, port

# self.evaluate_certificate()

# self.client.set_connect_state()

sock.connect((HOST,port))

client = SSL.Connection(context, sock)

client.set_tlsext_host_name(HOST)
client.set_connect_state()
client.do_handshake()


client.send("GET / HTTP/1.0\r\n\r\n")
		
#=====[ Print data while server has data to write ]=====
print client.recv(1000000)