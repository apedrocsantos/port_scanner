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
	version = dic["scan"][ip]["tcp"][port]["product"] + " v" + dic["scan"][ip]["tcp"][port]["version"]
	print("port " + str(port) + " : " + service + " : " + version)
	#add dictionary to list
	for item in array:
		print(item)
		if item["ip"] == ip:
			array.append({"service" : service, "version" : version, "port" : {port : []}})
	

def get_vulns(scanner, ip, port, array):
	dic = scanner.scan(ip, arguments="--script vuln -p " + str(port))
	try:
		for val in dic["scan"][ip]["tcp"][port]["script"]:
			if "CVE-" in dic["scan"][ip]["tcp"][port]["script"][val]:
				spos = dic["scan"][ip]["tcp"][port]["script"][val].find("CVE-")
				if (dic["scan"][ip]["tcp"][port]["script"][val][spos:].find("\n") < dic["scan"][ip]["tcp"][port]["script"][val][spos:].find(" ")):
					epos = dic["scan"][ip]["tcp"][port]["script"][val][spos:].find("\n")
				else:
					epos = dic["scan"][ip]["tcp"][port]["script"][val][spos:].find(" ")
				cve = dic["scan"][ip]["tcp"][port]["script"][val][spos:spos+epos]
				for item in array:
					if item["ip"] == ip:
						item["port"][port].append(cve)
	except Exception:
		i = 0
	

def scan_network(ip_list, port_list, array):
	scanner = nmap.PortScanner()
	for ip in ip_list:
		closed = 1
		try:
			name = socket.gethostbyaddr(ip_list[0])[0]
			print("Host: ", name)
		except Exception:
			print(ip, ": no host name found.")
			name = "empty"
		for port in port_list:
			array.append({"ip" : ip, "host" : name})
			#If port is open
			if scan_port(ip, port):
				get_service(scanner, ip, port, name, array)
				closed = 0
				if input("Scan for vulnerabilities? y/n: ") == "y":
					#Find CVEs
					get_vulns(scanner, ip, port, array)
			elif globals.verbose:
				print("port", port, "is closed.")
		if closed:
			print(ip, ": all probed ports are closed.")
	print(array)