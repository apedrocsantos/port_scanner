import ipaddress
import ipcalc
import socket

def check_range(string, port_list):
    temp = string.split("-")
    a = int(temp[0])
    b = int(temp[1])
    if (a > b):
       print("Error")
       return 1
    while (a <= b):
        port_list.append(a)
        a += 1

def check_valid_port(string, port_list):
    if (string.isdigit()):
        port_list.append(int(string))
    elif ("," in string):
        temp = string.split(",")
        for item in temp:
            if not item.isdigit():
                print("Error")
                return 1
            port_list.append(int(item))
    elif ("-" in string):
        if check_range(string, port_list):
            return 1
    else:
        print ("Error")
        return 1

def check_cidr(string, ips):
    try:
        for x in ipcalc.Network(string):
            ips.append(str(x))
    except Exception:
        print("ERROR")
        return (1)

def check_ip(string, ip_list):
    try:
        ip = ipaddress.ip_address(string)
        ip_list.append(string)
    except Exception:
        print("ERROR")
        return (1)
    return (0)

def check_valid_ip(string, ip_list):
    temp = []
    if ("," in string):
        temp = string.split(",")
    else:
        temp.append(string)
    i = 0
    while i < len(temp):
        if (temp[i][0].isalpha()):
            try:
                ip_list.append(socket.gethostbyname(temp[i]))
            except Exception:
                print("Error")
                return 1
        elif ("/" in str(temp[i])):
            if (check_cidr(temp[i], ip_list)):
                return (1)
        elif check_ip(temp[i], ip_list):
            return (1)
        # else:
        #     print("Appending ", string)
        #     ip_list.append(string)
        i += 1
    return (0)