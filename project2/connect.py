from OpenSSL import SSL
from OpenSSL import crypto
import OpenSSL
import socket
import urlparse
import utils as ut
import sys
from sys import stdout
import datetime
import re 

modes = {'tlsv1.0':SSL.TLSv1_METHOD,'tlsv1.1':SSL.TLSv1_1_METHOD,'tlsv1.2':SSL.TLSv1_2_METHOD,'sslv3':SSL.SSLv3_METHOD,'3':SSL.SSLv3_METHOD}

class Connection():

	""" Class for experimenting with socket connections """

	def __init__(self, url, values):
		
		context = SSL.Context(modes[values['mode']])
		context.set_options(SSL.OP_NO_SSLv2)

		
		#=====[ Set list of ciphers to use ]=====
		if 'ciphers' in values:
			context.set_cipher_list(values['ciphers'])

		#=====[ Rehydrate public key certificate if given ]=====
		if 'pub_str' in values:
			self.pub_cert = crypto.load_certificate(crypto.FILETYPE_PEM, values['pub_str'])

		#=====[ If no pub key certificate, look for other options ]=====
		else:
			context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, self.verify_callback)
			self.pub_cert = None

			#=====[ set certificat paths specified by user or default certificate paths if non specified ]=====
			if 'cacert' in values:
				context.load_verify_locations(values['cacert'])
			else:
				context.set_default_verify_paths()

			#=====[ Set grace period for expired certificates ]=====
			if 'num_days' in values:
				self.num_days = values['num_days']
			else:
				self.num_days = None

			#=====[ Load and set CRL ]=====
			if 'crl_str' in values:
				self.crl = crypto.load_crl(crypto.FILETYPE_PEM, values['crl_str'])
			else:
				self.crl = None
		
		#=====[ Save context and socket ]=====
		self.context = context
		self.sock = socket.socket()

	def connect(self, url="https://www.stanford.edu",port=443):

		""" Establish connection with host at specified port """

		#=====[ Parse url ]=====
		p_url = urlparse.urlparse(url)

		if p_url.port is not None:
			port = p_url.port

		#=====[ Get remote host ]=====
		HOST = p_url.netloc
		HOST_NAME = p_url.hostname  

		#=====[ Make connction ]=====
		self.sock.connect((HOST_NAME,port))
		self.client = SSL.Connection(self.context, self.sock)

		#=====[ Set extension for SNI ]=====
		self.client.set_connect_state()
		self.client.set_tlsext_host_name(HOST_NAME)
		self.client.do_handshake()

		#=====[ Check digest of certificates if pinned public key speciifed ]=====
		if self.pub_cert:
			peer_cert = self.client.get_peer_certificate()

			#=====[ Compare digests of each cert ]=====
			if peer_cert.digest('sha256') == self.pub_cert.digest('sha256'):
				return
			
			#=====[ if not exact match, return 'bad certificate']=====
			else:
				raise ValueError('Invalid pinned public key')
		
		#=====[ Check for valid common name ]=====
		else: 

			#=====[ Extract common name from cert ]=====
			cert = self.client.get_peer_certificate()
			
			#=====[ Extract ASNs ]=====
			try:
				num_exts = cert.get_extension_count()
				for idx in range(num_exts):
					ASN = cert.get_extension(8)
					if ASN.get_short_name() == 'subjectAltName':
						ASNs = ASN._subjectAltNameString()
						ASNs = ASNs.replace('DNS:','').split(',')
			except Exception as e:
				pass


			common_name = cert.get_subject().commonName.decode()
			regex = common_name.replace('.', r'\.').replace('*',r'[^\.]*') + '$'
			regex = regex.replace('[^\.]*\.',r'([^\.]*\.)?')

			if re.match(regex, HOST_NAME):
				return 
			else:
				#=====[ Check for matches in ASNs ]=====
				for name in ASNs:
					if re.match(regex,name):
						return

			raise ValueError('Mismatching common name')


	def send(self, url, port=443):
		""" Sends specified message; default is get request """

		#=====[ Parse url ]=====
		p_url = urlparse.urlparse(url)


		path = p_url.path
		if path == '':
			path ='/'

		#=====[ Get remote host ]=====
		HOST = p_url.netloc

		cert = self.client.get_peer_certificate()
		common_name = cert.get_subject().commonName.decode()

		message = "GET %s HTTP/1.0\nHost: %s\nUser-Agent: KDOandBGAR/1.0\r\n\r\n" % (path, HOST)

		#=====[ Send request ]=====
		self.client.send(message)
		
		#=====[ Print data while server has data to write ]=====
		header = True

		while(True):
			try:
				data = self.client.recv(4096)
				if header:
					sys.stdout.write(data[data.index('\r\n\r\n')+len('\r\n\r\n'):])
					header = False
				else:
					sys.stdout.write(data)
			except SSL.ZeroReturnError:
				break
			

	def kill(self):

		""" Kills socket connection """

		#=====[ Kill connection ]=====
		self.client.shutdown()


	def verify_callback(self, connection, x509, errnum, errdepth, ok):
		
		#=====[ Check if cert expired (but still valid) ]=====
		if not ok:
			#=====[ Check if certificate out of date and user invoked --allow-stale-certs ]=====
			if errnum == 10 and self.num_days:
				
				#=====[ extract raw date from certificate ]=====
				raw_date = x509.get_notAfter()

				date = datetime.datetime(int(raw_date[0:4]),int(raw_date[4:6]),int(raw_date[6:8]),int(raw_date[8:10]),int(raw_date[10:12]),int(raw_date[12:14]))
				delta = datetime.timedelta(self.num_days)

				#=====[ If grace period is substantial enough, return 1 ]=====
				if datetime.datetime.now() > date + delta:
					raise ValueError('Expiration date surpassed grace period')
				else:
					ok = True

		if ok:		
			serial_number = x509.get_serial_number()

			#=====[ Check that cert is not on CRL ]=====
			if self.crl != None:
				
				revoked_certs = self.crl.get_revoked()
				for cert in revoked_certs:
					
					#=====[ Check if serial number equals that of revoked cert ]=====
					if serial_number == int(cert.get_serial(),16):
						raise ValueError('Cert located within CRL')


			return True

		else:
			raise ValueError('Invalid Certificate')

