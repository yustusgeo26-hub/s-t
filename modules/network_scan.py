import shutil
import socket
import subprocess
from typing import Dict, List

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


def _socket_scan(host: str, ports: List[int], timeout: float = 0.8) -> List[Dict]:
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append({"port": port, "state": "open"})
        except Exception:
            continue
        finally:
            sock.close()
    return open_ports


def run_network_scan(target: str, ports: List[int] = None) -> Dict:
    ports = ports or TOP_PORTS
    result: Dict = {"target": target, "method": "socket", "open_ports": []}

    if shutil.which("nmap"):
        command = ["nmap", "-Pn", "-sV", "-p", ",".join(str(p) for p in ports), target]
        try:
            output = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            result.update({"method": "nmap", "command": " ".join(command), "stdout": output.stdout, "stderr": output.stderr})
            return result
        except Exception as e:
            result["nmap_error"] = str(e)

    result["open_ports"] = _socket_scan(target, ports)
    return result
