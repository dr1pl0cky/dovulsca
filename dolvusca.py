#!/usr/bin/python3

import sys, subprocess, getopt, os, re, json, xml.etree.ElementTree as ET

target = sys.argv[1]

class mktool:
	def __init__(self, site):
		self.site = site
		self.Grade = 100
		self.counter = 0
		self.ip = ""
		self.reject = False
		self.sslv2 = False
		self.sslv3 = False
		self.tlsv1 = False
		self.tlsv11 = False
		self.tlsv12 = False
		self.tlsv13 = False
		self.heartbleed = False
		self.openssl_ccs = False
		self.scsv = False
		self.data = []
		self.serverinfo = []
		self.vuln = []
		self.vulnsresult = False
		self.spoof = False
		self.ranking = 0
	
	def getip(self):
		process = subprocess.check_output(['nslookup', self.site])
		self.ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(process))[2]

	def sslscanner(self):
		#print("\nScanning " + self.site + "'s TLS/SSL Configurations...")
		subprocess.run(['sslyze', '--regular', '--json_out=/tmp/scan.json', self.ip], stdout=subprocess.DEVNULL)

	def jsonparser(self):
		with open('/tmp/scan.json', 'r') as r:
			data = json.load(r)
		a = len(json.dumps(data['invalid_targets']))
		#print("Debug String: " + str(a))
		if a > 5:
			self.reject = True
			self.serverinfo = print("Null")
			#print("Debug String: Empty. rejected tests")
		else:
			self.reject = False
			#self.scsv = (json.dumps(data['accepted_targets'][0]['commands_results']['fallback']['supports_fallback_scsv']))
			o = (json.dumps(data['accepted_targets'][0]['commands_results']['fallback']['supports_fallback_scsv']))
			p = len(o)
			if p == 4:
				self.scsv = True
			#self.heartbleed = (json.dumps(data['accepted_targets'][0]['commands_results']['heartbleed']['is_vulnerable_to_heartbleed']))
			q = (json.dumps(data['accepted_targets'][0]['commands_results']['heartbleed']['is_vulnerable_to_heartbleed']))
			r = len(q)
			if r == 4:
				self.heartbleed = True
			#self.openssl_ccs = (json.dumps(data['accepted_targets'][0]['commands_results']['openssl_ccs']['is_vulnerable_to_ccs_injection']))
			s = (json.dumps(data['accepted_targets'][0]['commands_results']['openssl_ccs']['is_vulnerable_to_ccs_injection']))
			t = len(s)
			if t == 4:
				self.openssl_ccs = True
			self.sslv2 = True if len(json.dumps(data['accepted_targets'][0]['commands_results']['sslv2']['accepted_cipher_list'])) > 2 else False
			self.sslv3 = True if len(json.dumps(data['accepted_targets'][0]['commands_results']['sslv3']['accepted_cipher_list'])) > 2 else False
			self.tlsv1 = True if len(json.dumps(data['accepted_targets'][0]['commands_results']['tlsv1']['accepted_cipher_list'])) > 2 else False
			self.tlsv11 = True if len(json.dumps(data['accepted_targets'][0]['commands_results']['tlsv1_1']['accepted_cipher_list'])) > 2 else False
			self.tlsv12 = True if len(json.dumps(data['accepted_targets'][0]['commands_results']['tlsv1_2']['accepted_cipher_list'])) > 2 else False
			self.tlsv13 = True if len(json.dumps(data['accepted_targets'][0]['commands_results']['tlsv1_3']['accepted_cipher_list'])) > 2 else False
			self.serverinfo = (json.dumps(data['accepted_targets'][0]['server_info']))
			#print(json.dumps(data, indent = 4, sort_keys=True))

	def map(self):
		#print("\nRunning NMAP scan on: " + self.site)
		subprocess.run(['sudo', 'nmap', '-sV', '--script', 'vulners', '-oX', '/tmp/nmap.xml', self.site], stdout=subprocess.DEVNULL)

	def xmlparse(self):
		with open('/tmp/nmap.xml', 'r') as e:
			print("")
			print("--------------------------------")
			print("CVE Vulnerabilities for " + self.site + " if any:")
			print("")
			for line in e.readlines():
				if '<elem key="id">CVE' in line:
					f = line
					g = re.sub('<elem key="id">', '', f)
					h = re.sub('</elem>', '', g)
					i = re.sub('\n', '', h)
					print(i)
					#print(len(i))
					self.vulnsresult = True if len(i) > 2 else False

	def spoofChecker(self):
		outputs = subprocess.getoutput("python spoof.py " + self.site)
		#print(outputs)
		if 'Spoofing possible for' in outputs:
			#print("Spoofing possible!")
			a = 'Spoofing possible for'
			#print(len(a))
			#self.spoof = True
			self.spoof = True if len(a) < 22 else False

	def rank(self):
		self.counter = self.counter + 1 if self.reject == True else self.counter - 0
		self.counter = self.counter + 1 if self.tlsv1 == True else self.counter - 0
		self.counter = self.counter + 1 if self.tlsv11 == True else self.counter - 0
		self.counter = self.counter + 1 if self.tlsv12 == False else self.counter - 0
		self.counter = self.counter + 1 if self.tlsv13 == False else self.counter - 0
		self.counter = self.counter + 1 if self.sslv2 == True else self.counter - 0
		self.counter = self.counter + 1 if self.sslv3 == True else self.counter - 0
		self.counter = self.counter + 1 if self.heartbleed == True else self.counter - 0
		self.counter = self.counter + 1 if self.openssl_ccs == True else self.counter - 0
		self.counter = self.counter + 1 if self.scsv == True else self.counter - 0
		self.counter = self.counter + 1 if self.spoof == True else self.counter - 0

	def rank2(self):
		#print(self.counter)
		a = self.counter * 10 / self.Grade
		b = a * 100
		c = self.Grade - b
		self.ranking = c

	def stats(self):
		print("")
		print("#####################################")
		print("")
		print("Site: " + self.site)
		print("-----------------")
		print("Rejected:\t" + str(self.reject))
		print("TLSv1:\t\t" + str(self.tlsv1))
		print("TLSv1_1:\t" + str(self.tlsv11))
		print("TLSv1_2:\t" + str(self.tlsv12))
		print("TLSv1_3:\t" + str(self.tlsv13))
		print("SSLv2:\t\t" + str(self.sslv2))
		print("SSLv3:\t\t" + str(self.sslv3))
		print("Heartbleed:\t" + str(self.heartbleed))
		print("Open SSL CSS:\t" + str(self.openssl_ccs))
		print("SCSV Fallback:\t" + str(self.scsv))
		print("Sever Vulners:\t" + str(self.vulnsresult))
		print("Grade:\t\t" + str(self.ranking) + " / 100")
		print("Spoof:\t\t" + str(self.spoof))
		print("IP:\t\t" + str(self.ip))
		print("Server Info:\t" + str(self.serverinfo))
		print("#####################################")

	def cleanup(self):
		#print("cleaning up...")
		subprocess.run(['sudo', 'rm', '-f', '/tmp/scan.json'])
		subprocess.run(['sudo', 'rm', '-f', '/tmp/nmap.xml'])

if __name__ == "__main__":
	first = mktool(target)
	first.getip()
	first.sslscanner()
	first.jsonparser()
	first.spoofChecker()
	first.map()
	first.xmlparse()
	first.rank()
	first.rank2()
	first.stats()
	first.cleanup()
