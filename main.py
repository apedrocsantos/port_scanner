import parsing
import scan
import report
import globals
import argparse
from datetime import datetime
import netifaces

def basic(device):
    try:
        addrs = netifaces.ifaddresses(device)
        ip = addrs[netifaces.AF_INET][0]["addr"]
        netmask = addrs[netifaces.AF_INET][0]["netmask"]
        cidr = sum([bin(int(x)).count('1') for x in netmask.split('.')])
        return(ip+'/'+str(cidr))
    except Exception:
        globals.device = input(device + " network device not found. Write network device name (e.g. en0) or 'exit' to exit program: ")
        if (globals.device == "exit"):
            exit()
        main()

def main():
    array = []
    # Procurar rede interna do host
    default_addr = basic(globals.device)
    # Parsing (flags --host, -p e -v)
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("--host", default=default_addr)
    parser.add_argument("-p", "--port", default="0-1023")
    parser.add_argument("-v", action='store_true')
    args = parser.parse_args()
    ip_list = []
    port_list = []
    input_host = args.host
    input_port = args.port
    globals.verbose = args.v
    # Validação dos valores de ip e portas introduzidos pelo utilizador
    if (parsing.check_valid_ip(input_host, ip_list)):
        print("Invalid host values. Try again.")
        exit()
    ip_list = list(dict.fromkeys(ip_list))
    if (parsing.check_valid_port(input_port, port_list)):
        print("Invalid port values. Try again.")
        exit()
    # Data e hora do início do scan
    current_time = datetime.now()
    start_time = str(current_time.date()) + " " + str(current_time.hour) + ":" + str(current_time.minute) + ":" + str(current_time.second)
    print("Starting:", start_time)
    # Fazer scan à rede
    scan.scan_network(ip_list, port_list, array)
    # Criar relatório (y/n)
    if input("Create report? y/n: ") == "y":
        report.create_report(array, start_time)
    print ("Done")


if __name__ == "__main__":
    main()