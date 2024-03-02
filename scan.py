import socket
import globals
import nmap

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
	version = dic["scan"][ip]["tcp"][port]["product"] + " " + dic["scan"][ip]["tcp"][port]["version"]
	print("port " + str(port) + " : " + service + " : " + version)
	#add port to list
	for item in array:
		if item["ip"] == ip:
			item["port"].append({port : [{"CVE_list": [], "service" : service, "version" : version}]})

def get_vulns(scanner, ip, port, array):
	dic = scanner.scan(ip, arguments="-sV --script vulners -p " + str(port))
	epos = 0
	spos = 0
	try:
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
				epos = epos + spos + 1
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
	except Exception:
		print(ip + ":" + str(port) + " : No vulnerabilities found.")
		return

def scan_network(ip_list, port_list, array):
	scanner = nmap.PortScanner()
	for ip in ip_list:
		closed = 1
		print("**********************************************")
		try:
			name = socket.gethostbyaddr(ip)[0]
			print("Scanning: " + ip, name)
		except Exception:
			print("Scanning " + ip, ": no host name found.")
			name = "empty"
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
	print("**********************************************")
	if input("Scan for vulnerabilities? y/n: ") == "y":
		# Find CVEs
		for item in array:
			for port_s in item["port"]:
				for key in port_s:
					get_vulns(scanner, item["ip"], key, array)