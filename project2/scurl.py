#!/usr/bin/env python2.7

import sys
import connect
import utils as ut
import sys


modes = ['tlsv1.0','tlsv1.1','tlsv1.2','sslv3','3']
mode = 'tlsv1.2'

#=====[ Load ciphers ]=====
# supp_ciphers = open('ciphers.txt','rb')
# supp_ciphers = supp_ciphers.read().replace('\n','').split(':')

def parse_flags(flags, mode):

	values = {}

	idx = 0
	while idx < len(flags):
		flag = flags[idx]
		
		#=====[ Check to ensure flag is properly formatted ]=====
		if '--' in flag [:2]:

			flag = flag[2:]

			#=====[ Checks if flag is a mode specification ]=====
			if flag in modes:
				mode = flag
				idx += 1

			#=====[ Checks if flag is specifying cipher list ]=====
			elif flag == 'ciphers':
				
				idx += 1				
				values['ciphers'] = cipher_list
				idx+=1

			#=====[ Checks if flag is specifying ca_cert to use for verification ]=====
			elif flag == 'cacert':
				idx+=1
				values['cacert'] = flags[idx]
				idx+=1

			#=====[ Check if flag is specifying number of days to allow certs to be staled before invalidation ]=====
			elif flag =='allow-stale-certs':
				
				idx+=1
				num_days = int(flags[idx])
				assert num_days > -1
				values['num_days'] = num_days
				idx+=1

			elif flag == 'crlfile':

				idx+=1
				crl_file = open(flags[idx])
				values['crl_str'] = crl_file.read()
				idx+=1

			elif flag == 'pinnedpublickey':

				idx+=1
				pub_file = open(flags[idx])
				values['pub_str'] = pub_file.read()
				idx+=1

			
			#=====[ Else return error ]=====
			else:
				ut.fail("Could not identify command " + flag)
				return

	values['mode'] = mode

	return values

if __name__ == "__main__":

	try:

		#=====[ Require arguments to be passed ]=====	
		if len(sys.argv) < 2:
			sys.stderr.write('USE STUFF\n')
			sys.exit(1)

		#=====[ Get url and options ]=====	
		url = sys.argv[-1]
		flags = sys.argv[1:-1]

		initializations = parse_flags(flags, mode)

		
		#=====[ Instantiat connection object and connect ]=====
		scurl = connect.Connection(url, initializations)
		scurl.connect(url=url)
		
		#=====[ Make GET request ]=====
		scurl.send(url)

		#=====[ Close connection ]=====
		scurl.kill()
	
	except Exception as e:

		sys.stderr.write("Certificate could not be verified\n")
		sys.exit(1)


