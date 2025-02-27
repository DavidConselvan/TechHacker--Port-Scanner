#!/usr/bin/env python3
import socket
import threading
import argparse
from queue import Queue
from datetime import datetime
import ipaddress

WELL_KNOWN_PORTS = {
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    17: "QOTD",
    19: "Chargen",
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    70: "Gopher",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    115: "SFTP",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMPTRAP",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    520: "RIP",
    587: "SMTP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1812: "RADIUS",
    1813: "RADIUS-ACCT",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}

port_queue = Queue()
results = []

def get_service(port):
    return WELL_KNOWN_PORTS.get(port, "Unknown")

def scan_port(ip, port, protocol="tcp"):
    try:
        ip_obj = ipaddress.ip_address(ip)
        family = socket.AF_INET if ip_obj.version == 4 else socket.AF_INET6
        
        if protocol == "tcp":
            sock = socket.socket(family, socket.SOCK_STREAM)
        else:  
            sock = socket.socket(family, socket.SOCK_DGRAM)
        
        sock.settimeout(1)
        
        if protocol == "tcp":
            result = sock.connect_ex((ip, port))
            if result == 0:
                state = "open"
                try:
                    sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = None
            else:
                state = "closed" if result == 111 else "filtered"
                banner = None
        else: 
            sock.sendto(b"TEST", (ip, port))
            try:
                sock.recvfrom(1024)
                state = "open"
                banner = None 
            except socket.timeout:
                state = "open|filtered"
                
        sock.close()

        results.append({
            "port": port,
            "state": state,
            "service": get_service(port),
            "banner": banner,
            "protocol": protocol.upper()
        })
        
    except Exception as e:
        results.append({
            "port": port,
            "state": "error",
            "service": get_service(port),
            "banner": str(e),
            "protocol": protocol.upper()
        })

def scan_range(ip, start_port, end_port, protocol="tcp"):
    print(f"\nIniciando escaneamento em {ip} ({protocol.upper()}) - {datetime.now()}")
    print(f"Escaneando portas de {start_port} a {end_port}...")
    
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    threads = []
    for _ in range(min(100, end_port - start_port + 1)):
        t = threading.Thread(target=worker, args=(ip, protocol))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

    print_results()

def worker(ip, protocol):
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(ip, port, protocol)
        port_queue.task_done()

def print_results():
    print("\nResultados do escaneamento:")
    print("-" * 60)
    print(f"{'Porta':<8} {'Estado':<12} {'Protocolo':<10} {'Serviço':<15} {'Banner/SO'}")
    print("-" * 60)
    for result in sorted(results, key=lambda x: x["port"]):
        banner = result["banner"] if result["banner"] else "-"
        print(f"{result['port']:<8} {result['state']:<12} {result['protocol']:<10} "
              f"{result['service']:<15} {banner}")
    print("-" * 60)

def main():
    parser = argparse.ArgumentParser(description="Port Scanner em Python")
    parser.add_argument("host", help="Host ou IP a ser escaneado (IPv4 ou IPv6)")
    parser.add_argument("-s", "--start", type=int, default=1, help="Porta inicial")
    parser.add_argument("-e", "--end", type=int, default=1024, help="Porta final")
    parser.add_argument("-p", "--protocol", choices=["tcp", "udp"], default="tcp",
                        help="Protocolo: tcp ou udp")
    
    args = parser.parse_args()
    
    if not (1 <= args.start <= args.end <= 65535):
        print("Erro: Intervalo de portas inválido (1-65535).")
        return
    
    try:
        ip = socket.getaddrinfo(args.host, None)[0][4][0]
        scan_range(ip, args.start, args.end, args.protocol)
    except socket.gaierror:
        print("Erro: Host inválido ou não resolvido.")
    except Exception as e:
        print(f"Erro inesperado: {e}")

if __name__ == "__main__":
    main()