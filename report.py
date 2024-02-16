from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.pagesizes import A4

def create_report(matrix):
    doc = SimpleDocTemplate('myfile.pdf', pagesize=A4)
    elements = []
    myCanvas=Table(matrix)
    # myCanvas.setStyle(TableStyle([('BACKGROUND',(1,1),(-2,-2),colors.green),
    #                     ('TEXTCOLOR',(0,0),(1,-1),colors.red)]))
    elements.append(myCanvas)
    doc.build(elements)
