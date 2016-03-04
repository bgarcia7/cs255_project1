import sys
import connect
import utils as ut

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

	values['mode'] = mode

	return values

if __name__ == "__main__":

	url = sys.argv[-1]
	flags = sys.argv[1:-1]

	initializations = parse_flags(flags, mode)

	try:
		#=====[ Initialize connection ]=====
		scurl = connect.Connection(initializations)

		scurl.connect(url=url)
		scurl.send()
	
	except Exception as e:

		ut.fail(e)
