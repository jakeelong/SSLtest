#!/usr/bin/env python
#Author Prajwal Panchmahalkar
inspired by "TrullJ"

import requests
import time
import sys
import json
import warnings
start_time = time.clock()
warnings.filterwarnings("ignore")
def sendReq(payload={}):
	url = "https://api.ssllabs.com/api/v2/analyze"
	try:
		response = requests.get(url, params=payload)
	except requests.exception.RequestException as e:
		print e
		sys.exit(1)
	data = response.json()
	return data
def scanHost(host):
	payload = {'host': host, 'publish': "off", 'startNew': "on", 'all': "done", 'ignoreMismatch': "on"}
	results = sendReq(payload)
	payload.pop('startNew')	
	while results['status'] != 'READY' and results['status'] != 'ERROR':
		time.sleep(30)
		results = sendReq(payload)	
	checkdata = results
	for each in checkdata["endpoints"]:
		if(each["statusMessage"]=="Ready"):
			print ", IP Address ="+str(each["ipAddress"]),
			print ", Grade = "+each["grade"],
			try:
				print ", POODLE = "+str(each["details"]["poodle"]),
				print ", POODLE_TLS ="+str(each["details"]["poodleTls"]),
				print ", RC4 Support ="+str(each["details"]["supportsRc4"]),
				print ", BEAST ="+str(each["details"]["vulnBeast"]),
				print ", LOGJAM ="+str(each["details"]["logjam"]),
				print ", heartbleed ="+str(each["details"]["heartbleed"])
			except:
				pass
def main():
	if(len(sys.argv)!=2):
		print "[!] Usage eg., python sslgrade.py www.google.com"
		sys.exit(0)
	else:
		scanHost(sys.argv[1])

if __name__ == "__main__":
	main()
