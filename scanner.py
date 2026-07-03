import socket
def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        if scan_port(host, port):
            open_ports.append(port)
    return open_ports
