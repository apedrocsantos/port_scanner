import parsing
import scan
import report
import globals
import argparse
from datetime import datetime

# Data e hora / api com nome e link da vulnerabilidade / report / print lista no terminal

def print_screen(array):
    print("Done")

def main():
    array = []
    current_time = datetime.now()
    start_time = str(current_time.date()) + " " + str(current_time.hour) + ":" + str(current_time.minute) + ":" + str(current_time.second)
    print("Starting:", start_time)
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("-p", "--port", default="0-1023")
    parser.add_argument("-v", action='store_true')
    parser.add_argument("host")
    args = parser.parse_args()

    ip_list = []
    port_list = []
    input_host = args.host
    input_port = args.port
    globals.verbose = args.v
    if (parsing.check_valid_ip(input_host, ip_list)):
        print("Invalid host values. Try again.")
        exit()
    ip_list = list(dict.fromkeys(ip_list))
    if (parsing.check_valid_port(input_port, port_list)):
        print("Invalid port values. Try again.")
        exit()
    scan.scan_network(ip_list, port_list, array)
    print_screen(array)
    # if input("Create report? y/n: ") == "y":
    #     report.create_report(array, start_time)


if __name__ == "__main__":
    main()