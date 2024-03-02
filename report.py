from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.pagesizes import A4
from datetime import datetime
import requests

def get_cve_url(cve):
	cve_url = "https://nvd.nist.gov/vuln/detail/" + cve
	url_response = requests.get(cve_url)
	if (url_response.status_code == 200):
		return(cve_url)
	else:
		return ("not found")

def create_report(array, start_time):
	cm = 2.541

	doc = SimpleDocTemplate('myfile.pdf', pagesize=A4)
	content = []
	styles = getSampleStyleSheet()

	st = "Start time: " + start_time
	content.append(Paragraph(st))
	for element in array:
		content.append(Paragraph("++++++++++++++++++"))
		ip = element["ip"]
		hostname = element["host"]
		ip_id = "IP: " + ip + " | Hostname: " + hostname
		content.append(Paragraph(ip_id))
		for port_dict in element['port']:
			for port in port_dict:
				for port_list in port_dict[port]:
					content.append(Paragraph("++++++++++++++++++"))
					string = "Port: " + str(port) + " | Service: " + port_list["service"] + " | Version: " + port_list["version"]
					content.append(Paragraph(string))
					for cve in port_list["CVE_list"]:
						cve_data = cve["CVE"] + " (" + get_cve_url(cve["CVE"]) + ")"
						content.append(Paragraph(cve_data))
	content.append(Paragraph("++++++++++++++++++"))
	current_time = datetime.now()
	end_time = str(current_time.date()) + " " + str(current_time.hour) + ":" + str(current_time.minute) + ":" + str(current_time.second)
	et = "End time: " + end_time
	content.append(Paragraph(et))
	doc.build(content)
