import socket
import globals
import nmap
import requests

def scan_port(target, port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(0.5)
		sock.connect((target, port))
		return True
	except Exception:
		return False

def get_service(scanner, ip, port, name, array):
	dic = scanner.scan(ip, arguments="-sV -p " + str(port))
	service = dic["scan"][ip]["tcp"][port]["name"]
	version = dic["scan"][ip]["tcp"][port]["product"] + " v" + dic["scan"][ip]["tcp"][port]["version"]
	print("port " + str(port) + " : " + service + " : " + version)
	#add port to list
	for item in array:
		if item["ip"] == ip:
			item["port"].append({port : [{"CVE_list": [], "service" : service, "version" : version}]})
	

def get_cve_description(cve):
	api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve
	api_response = requests.get(api_url)
	if (api_response.status_code == 200):
		return(api_response.json()["vulnerabilities"][0]["cve"]["descriptions"][0]["value"])
	else:
		return ("not found")

def get_cve_url(cve):
	cve_url = "https://nvd.nist.gov/vuln/detail/" + cve
	url_response = requests.get(cve_url)
	if (url_response.status_code == 200):
		return(cve_url)
	else:
		return ("not found")

def get_vulns(scanner, ip, port, array):
	dic = scanner.scan(ip, arguments="-sV --script vulners -p " + str(port))
	epos = 0
	spos = 0
	line = dic["scan"][ip]["tcp"][port]["script"]["vulners"]
	if (line.find("CVE-")):
		print("**********************************************")
		print("IP\t\tport\tCVE")
	while (epos != -1):
		spos = line[spos:].find("\tCVE-")
		if (spos == -1):
			break
		else:
			spos = spos + epos
		epos = line[spos + 1:].find('\t')
		if (epos == -1):
			break
		else:
			epos = epos + spos
		cve = line[spos + 1:epos]
		print(ip + "\t" + str(port) + "\t" + cve)
		epos = line[epos:].find('\n') + epos
		spos = epos
		for item in array:
			if item["ip"] == ip:
				for port_l in item["port"]:
					for key in port_l:
						if key == port:
							port_l[key][0]["CVE_list"].append({"CVE": cve})

	# dic = {'nmap': {'command_line': 'nmap -oX - --script vuln -p 80 192.168.10.222', 'scaninfo': {'tcp': {'method': 'connect', 'services': '80'}}, 'scanstats': {'timestr': 'Sat Feb 17 19:27:12 2024', 'elapsed': '346.20', 'uphosts': '1', 'downhosts': '0', 'totalhosts': '1'}}, 'scan': {'192.168.10.222': {'hostnames': [{'name': 'name', 'type': 'PTR'}], 'addresses': {'ipv4': '192.168.1.90'}, 'vendor': {}, 'status': {'state': 'up', 'reason': 'conn-refused'}, 'tcp': {80: {'state': 'open', 'reason': 'syn-ack', 'name': 'http', 'product': '', 'version': '', 'extrainfo': '', 'conf': '3', 'cpe': '', 'script': {'http-stored-xss': "Couldn't find any stored XSS vulnerabilities.", 'http-slowloris-check': "\n  VULNERABLE:\n  Slowloris DOS attack\n    State: LIKELY VULNERABLE\n    IDs:  CVE:CVE-2007-6750\n      Slowloris tries to keep many connections to the target web server open and hold\n      them open as long as possible.  It accomplishes this by opening connections to\n      the target web server and sending a partial request. By doing so, CVE-2007-1265\n it starves\n      the http server's resources causing Denial Of Service.\n      \n    Disclosure date: 2009-09-17\n    References:\n      http://ha.ckers.org/slowloris/\n      https://cve.mitre.CVE-123123-123123org/cgi-bin/cvename.cgi?name=CVE-2007-6750\n", 'http-enum': "\n  /images/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'\n", 'http-dombased-xss': "Couldn't find any DOM based XSS.", 'http-csrf': '\nSpidering limited to: maxdepth=3; maxpagecount=20; withinhost=scanme.nmap.org\n  Found the following possible CSRF vulnerabilities: \n    \n    Path: http://scanme.nmap.org:80/\n    Form id: nst-head-search\n    Form action: /search/\n    \n    Path: http://scanme.nmap.org:80/\n    Form id: nst-foot-search\n    Form action: /search/\n'}}}}}}
	# print(dic["scan"][ip]["tcp"][port]["script"])
	# try:
	# for val in dic["scan"][ip]["tcp"][port]["script"]:
	# 	print(val)
	# 	print(dic["scan"][ip]["tcp"][port]["script"][val])
	# 	epos = 0
	# 	spos = dic["scan"][ip]["tcp"][port]["script"][val][epos:].find("CVE-")
	# 	print(spos)
		# print("**********************************************")
		# print("IP\t\tport\tCVE")
		# if (dic["scan"][ip]["tcp"][port]["script"][val][spos:].find("\n") < dic["scan"][ip]["tcp"][port]["script"][val][spos:].find(" ")):
		# 	epos = dic["scan"][ip]["tcp"][port]["script"][val][spos:].find("\n")
		# else:
		# 	epos = dic["scan"][ip]["tcp"][port]["script"][val][spos:].find(" ")
		# cve = dic["scan"][ip]["tcp"][port]["script"][val][spos:spos+epos]
		# spos = epos + 1
		# print(cve)
	# except Exception:
	# 	return
	

def scan_network(ip_list, port_list, array):
	scanner = nmap.PortScanner()
	for ip in ip_list:
		closed = 1
		try:
			name = socket.gethostbyaddr(ip)[0]
			print("Scanning: " + ip, name)
		except Exception:
			print("Scanning " + ip, ": no host name found.")
			name = "empty"
		print("**********************************************")
		array.append({"ip" : ip, "host" : name, "port" : []})
		# print(array)
		for port in port_list:
			#If port is open
			if scan_port(ip, port):
				get_service(scanner, ip, port, name, array)
				closed = 0
			elif globals.verbose:
				print("port", port, "is closed.")
		if closed:
			print(ip, ": all probed ports are closed.")
	if input("Scan for vulnerabilities? y/n: ") == "y":
		# Find CVEs
		for item in array:
			for port_s in item["port"]:
				for key in port_s:
					get_vulns(scanner, item["ip"], key, array)