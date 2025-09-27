import nmap
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-sS -sV -p- --open')
    ports = []
    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto].keys():
            service = nm[ip][proto][port]['name']
            ports.append((port, service))
    return ports

def ssh_connect(ip, port, user, password):
    cmd = [
        'sshpass', '-p', password,
        'ssh', '-o', 'StrictHostKeyChecking=no', '-p', str(port),
        f'{user}@{ip}'
    ]
    try:
        return subprocess.call(cmd) == 0
    except Exception as e:
        print(f"SSH FAIL: {user}@{ip}:{port} - {e}")
        return False

def rdp_connect(ip, port, username, password):
    cmd = [
        'xfreerdp',
        f'/v:{ip}:{port}',
        f'/u:{username}',
        f'/p:{password}',
        '/cert-ignore',
    ]
    try:
        proc = subprocess.Popen(cmd)
        print(f"RDP started: {username}@{ip}:{port}")
        return True
    except Exception as e:
        print(f"RDP FAIL: {username}@{ip}:{port} - {e}")
        return False


def vnc_connect(ip, port):
    try:
        cmd = ['vncviewer', f'{ip}:{port}']
        subprocess.run(cmd)
        print(f"VNC attempt done: {ip}:{port}")
        return True
    except Exception as e:
        print(f"VNC FAIL: {ip}:{port} - {e}")
        return False

def telnet_connect(ip, port, user=None, password=None):

    try:
        cmd = ['telnet', ip, str(port)]
        subprocess.run(cmd)
        print(f"Telnet attempt done: {ip}:{port}")
        return True
    except Exception as e:
        print(f"Telnet FAIL: {ip}:{port} - {e}")
        return False

def try_connect(ip, port, service, login, password):
    svc = service.lower()
    print(f"Trying {service.upper()} on port {port}...")
    if 'ssh' in svc:
        return ssh_connect(ip, port, login, password)
    elif 'rdp' in svc or 'ms-wbt-server' in svc:
        return rdp_connect(ip, port, login, password)
    elif 'vnc' in svc:
        return vnc_connect(ip, port)
    elif 'telnet' in svc:
        return telnet_connect(ip, port, login, password)
    else:
        print(f"Service {service} not supported automatically.")
        return False

def main():
    if len(sys.argv) < 4:
        sys.exit(1)

    ip = sys.argv[1]
    login = sys.argv[2]
    password = sys.argv[3]

    print(f"Scanning {ip} ...")
    ports = scan_ports(ip)
    if not ports:
        print(f"No open ports found on {ip}")
        sys.exit(0)

    print(f"Found {len(ports)} open ports.")

    # Параллельные попытки подключения к сервисам на разных портах
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_port = {executor.submit(try_connect, ip, port, service, login, password): (port, service) for port, service in ports}
        for future in as_completed(future_to_port):
            port, service = future_to_port[future]
            try:
                success = future.result()
                if success:
                    print(f"Connected successfully to {service} on port {port}. Stopping further attempts.")
                    executor.shutdown(wait=False, cancel_futures=True)  # Останавливаем остальные попытки
                    break
            except Exception as exc:
                print(f'Exception on port {port}: {exc}')

if __name__ == "__main__":
    main()
