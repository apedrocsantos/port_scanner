import argparse
import socket
import ipcalc

def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        return True
    except:
        return False


def scan_rede(rede):
    closed = 1
    print("Host: ", socket.gethostbyaddr(rede[0])[0])
    for ip in rede:
        if scan_port(ip, port):
            print("port ", port, "on rede ", ip, " is open.")
            closed = 0
    if closed:
        print("All probed ports are closed.")

parser = argparse.ArgumentParser(description="Port Scanner")
parser.add_argument("-p", "--port")
parser.add_argument("host")
args = parser.parse_args()

rede = []
input = args.host
port = args.port

if ('/' in input):
    for x in ipcalc.Network('192.168.1.0/24'):
        rede.append(x)
else:
    rede.append(input)
scan_rede(rede)
