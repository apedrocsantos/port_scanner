from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.pagesizes import A4
import requests
from http.client import HTTPResponse
import mimetypes

# def create_report(array, start_time):
#     doc = SimpleDocTemplate('myfile.pdf', pagesize=A4)
#     elements = []
#     print("report:", array)
#     myCanvas=Table(array)
#     # myCanvas.setStyle(TableStyle([('BACKGROUND',(1,1),(-2,-2),colors.green),
#     #                     ('TEXTCOLOR',(0,0),(1,-1),colors.red)]))
#     elements.append(myCanvas)
#     doc.build(elements)

def create_report(array, start_time):
    cm = 2.541
    # response = HTTPResponse(mimetype='application/pdf')
    response = 'attachment; filename=somefilename.pdf'

    elements = []

    doc = SimpleDocTemplate('myfile.pdf', pagesize=A4)

    data=[("IP\nHostname", "Open Port", "Service/version", "Vulnerabilities", "Description", "Website")]
    # for item in array:
    #     for subitem in item:
    #         print (subitem)
    table = Table(data)
    elements.append(table)
    doc.build(elements) 
    return response
