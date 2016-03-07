from OpenSSL import SSL
import socket
import urlparse
import utils as ut
import sys

modes = {'tlsv1.0':SSL.TLSv1_METHOD,'tlsv1.1':SSL.TLSv1_1_METHOD,'tlsv1.2':SSL.TLSv1_2_METHOD,'sslv3':SSL.SSLv3_METHOD,'3':SSL.SSLv3_METHOD}

def verify_callback(connection, x509, errnum, errdepth, ok):
		if not ok:
			ut.fail('Certificate is invalid')
		return ok

class Connection():

	""" Class for experimenting with socket connections """

	def __init__(self, values):
		
		context = SSL.Context(modes[values['mode']])
		context.set_options(SSL.OP_NO_SSLv2)
		context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback)

		if 'cacert' in values:
			context.load_verify_locations(values['cacert'])
		else:
			context.set_default_verify_paths()
		
		if 'ciphers' in values:
			context.set_cipher_list(values['ciphers'])
		
		self.context = context
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	def connect(self, url="https://www.stanford.edu",port=443):

		""" Establish connection with host at specified port """

		p_url = urlparse.urlparse(url)

		path = p_url.path

		if path == "":
			path = "/"

		#=====[ Get remote host ]=====
		HOST = p_url.netloc  

		print HOST, port

		# self.evaluate_certificate()

		# self.client.set_connect_state()

		self.sock.connect((HOST,port))

		self.client = SSL.Connection(self.context, self.sock)
		self.client.set_connect_state()
		self.client.set_tlsext_host_name(HOST)
		# self.client.connect((HOST,port))

		self.client.do_handshake()



		cert = self.client.get_peer_certificate()
		common_name = cert.get_subject().commonName.decode()

		print 'Server subject is', self.client.get_peer_certificate().get_subject()

	def send(self, message="GET / HTTP/1.0\r\n\r\n"):

		""" Sends specified message; default is get request """

		self.client.send(message)
		
		#=====[ Print data while server has data to write ]=====
		print self.client.recv(1000000)

	def kill(self):

		""" Kills socket connection """

		self.client.shutdown()


#=====[ Code we'll probably need at some point ]=====
# context.set_verify(SSL.VERIFY_NONE, verify)
# context.set_passwd_cb(password_callback)
# context.use_certificate_file('cert')
# context.use_privatekey_file('key')
# Context.set_cipher_list(ciphers)