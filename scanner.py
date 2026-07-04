import socket

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    banner = None
    if result == 0:
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except:
            pass
    sock.close()
    return result == 0, banner

def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        is_open, banner = scan_port(host, port)
        if is_open:
            open_ports.append({"port": port, "banner": banner})
    return open_ports