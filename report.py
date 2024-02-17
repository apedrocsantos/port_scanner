from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.pagesizes import A4
import requests

def create_report(array, start_time):
    api_data(array)
    doc = SimpleDocTemplate('myfile.pdf', pagesize=A4)
    elements = []
    print("report:", array)
    # myCanvas=Table(array)
    # myCanvas.setStyle(TableStyle([('BACKGROUND',(1,1),(-2,-2),colors.green),
    #                     ('TEXTCOLOR',(0,0),(1,-1),colors.red)]))
    # elements.append(myCanvas)
    # doc.build(elements)
