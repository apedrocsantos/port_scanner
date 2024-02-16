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


# result [IP][NOME][PORTO][SERVIÇO][CVE]

# IP
#     NOME
#     PORTO 1
#     	SERVICO
#       VERSAO
#       CVES
#       	CVE2
#           CVE1
#       PORTO 2
#       ...

def get_service(scanner, ip, port, matrix):
	dic = scanner.scan(ip, arguments="-sV -p " + str(port))
	print("port " + str(port) + " : " + dic["scan"][ip]["tcp"][port]["product"] + " v" + dic["scan"][ip]["tcp"][port]["version"])

def get_vulns(scanner, ip, port, matrix):
	dic = scanner.scan(ip, arguments="--script vuln -p " + str(port))
	for val in dic["scan"][ip]["tcp"][port]["script"]:
		if "CVE:" in dic["scan"][ip]["tcp"][port]["script"][val]:
			spos = dic["scan"][ip]["tcp"][port]["script"][val].find("CVE:") + 4
			epos = dic["scan"][ip]["tcp"][port]["script"][val][spos:].find("\n")
			print(dic["scan"][ip]["tcp"][port]["script"][val][spos:spos+epos])
	

def scan_network(ip_list, port_list, matrix):
	array = []
	result = ["" for x in range(5)]
	scanner = nmap.PortScanner()
	i = 0
	for ip in ip_list:
		result[0] = ip
		closed = 1
		try:
			print("Host: ", socket.gethostbyaddr(ip)[0])
			result[1] = socket.gethostbyaddr(ip_list[0])[0]
		except Exception:
			print(ip, ": no host name found.")
			result[1] = ("empty")
		for port in port_list:
			#If port is open
			if scan_port(ip, port):
				#add dictionary to list
				# print("port", port, "is open.")
				get_service(scanner, ip, port, matrix)
				closed = 0
				# input("scan vulns? y/n ")
				#Find CVEs
				# get_vulns(scanner, ip, port, matrix)
			elif globals.verbose:
				print("port", port, "is closed.")
				result[2] = port
				matrix.append(result[:])
		if closed:
			print(ip, ": all probed ports are closed.")
		i += 1