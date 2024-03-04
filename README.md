## Requirements

-   install python3
-   install pip3
-   pip3 install netifaces
-   pip3 install python-nmap

## Instruções

### 1.  Scan básico rede caseira
-   Correr `python3 main.py`

### 2.  Scan ips e portas específicas
-   Correr `python3 main.py [--host <host(s)>] [-p <porta(s)>] [-v]`

#### Exemplos:
-   `python3 main.py --host scanme.nmap.org` - faz scan às 1024 well known ports

-   `python3 main.py --host 192.168.1.1,192.168.1.30 -p 22,80` - faz scan às portas 22 e 80 do host nos ips 192.168.1.1 e 192.168.1.30

-   `python3 main.py --host 192.168.1.0/24 -v` - faz scan às 1024 well known ports do gama de ips 192.168.1.0/24, modo verbose.

Depois de correr o scan, programa pergunta se utilizador quer fazer scan de vulnerabilidades nos portos descobertos e por fim, se quer criar um relatório.

`python3 main.py -h` - help