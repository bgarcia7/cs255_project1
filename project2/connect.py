from OpenSSL import SSL
import socket
import urlparse

class Connection():

	""" Class for experimenting with socket connections """

	def __init__(self):
		context = SSL.Context(SSL.TLSv1_2_METHOD)
		self.context = context
		self.sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))


	def connect(self, url="https://www.stanford.edu",port=443):

		""" Establish connection with host at specified port """

		url = urlparse.urlparse(url)

		path = url.path

		if path == "":
			path = "/"

		#=====[ Get remote host ]=====
		HOST = url.netloc  

		self.sock.connect((HOST, port))

	def send(self, message="GET / HTTP/1.0\r\n\r\n"):

		""" Sends specified message; default is get request """

		self.sock.send(message)
		
		#=====[ Print data while server has data to write ]=====
		print self.sock.recv(1000000)

	def kill(self):

		""" Kills socket connection """

		self.sock.shutdown()


#=====[ Code we'll probably need at some point ]=====
# context.set_verify(SSL.VERIFY_NONE, verify)
# context.set_passwd_cb(password_callback)
# context.use_certificate_file('cert')
# context.use_privatekey_file('key')
# Context.set_cipher_list(ciphers)