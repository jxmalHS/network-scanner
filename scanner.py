import socket
from concurrent.futures import ThreadPoolExecutor

DEFAULT_WORKERS = 20

def scan_port(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        banner = None
        if result == 0:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except OSError:
                pass
    return result == 0, banner

def scan_ports(host: str, ports: list[int], workers: int = DEFAULT_WORKERS) -> list[dict]:
    """Scan ports `workers` at a time; results come back in the original port order."""
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        results = list(pool.map(lambda port: scan_port(host, port), ports))
    finally:
        # cancel_futures=True: on Ctrl+C or an error, drop the ports still waiting in the
        # queue instead of scanning them all before stopping.
        pool.shutdown(wait=True, cancel_futures=True)
    return [{"port": port, "banner": banner}
            for port, (is_open, banner) in zip(ports, results) if is_open]