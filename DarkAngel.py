import socket
import re
import requests
import logging

# Setup logging
logging.basicConfig(filename='vulnerability_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Expanded list of common vulnerable ports and services
vulnerable_services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
    9200: "Elasticsearch",
    9300: "Elasticsearch Transport",
    5000: "Docker",
    8000: "HTTP Alternative"
}

# Expanded CVE checks for ports
cve_dict = {
    21: ["CVE-2021-23021", "CVE-2016-20012"],  # FTP
    22: ["CVE-2021-28041", "CVE-2018-15473"],  # SSH
    23: ["CVE-2021-26116"],                      # Telnet
    25: ["CVE-2021-22942"],                      # SMTP
    53: ["CVE-2021-20090"],                      # DNS
    67: ["CVE-2020-10730"],                      # DHCP
    69: ["CVE-2018-9286"],                       # TFTP
    80: ["CVE-2021-22954", "CVE-2021-22955"],   # HTTP
    88: ["CVE-2021-3156"],                       # Kerberos
    110: ["CVE-2021-22980"],                     # POP3
    139: ["CVE-2021-31956"],                     # NetBIOS
    143: ["CVE-2021-22979"],                     # IMAP
    161: ["CVE-2021-22982"],                     # SNMP
    162: ["CVE-2021-22983"],                     # SNMP Trap
    443: ["CVE-2021-22956", "CVE-2021-22957"],   # HTTPS
    3306: ["CVE-2021-23028", "CVE-2020-2574"],   # MySQL
    3389: ["CVE-2021-26855"],                     # RDP
    5432: ["CVE-2021-23214"],                     # PostgreSQL
    5900: ["CVE-2020-15778"],                     # VNC
    6379: ["CVE-2021-32650"],                     # Redis
    8080: ["CVE-2021-22959"],                     # HTTP Proxy
    9200: ["CVE-2021-22964"],                     # Elasticsearch
    9300: ["CVE-2021-22965"],                     # Elasticsearch Transport
    5000: ["CVE-2020-10665"],                     # Docker
    8000: ["CVE-2021-22960"],                     # HTTP Alternative
}

# List of common directories for web directory scan
common_directories = [
    "admin", "login", "dashboard", "api", "uploads", "wp-admin", "admin.php", "config.php", "user", "settings"
]

# Common payloads for SQL injection and XSS
sql_injection_payloads = ["' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"]
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "'><script>alert(1)</script>"]

def is_port_open(ip, port):
    """Check if a port is open on the target IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((ip, port)) == 0

def scan_vulnerable_ports(ip, ports):
    """Scan for vulnerable ports and services."""
    open_ports = []
    for port in ports:
        if is_port_open(ip, port):
            open_ports.append(port)
            logging.info(f"Vulnerable service detected: {vulnerable_services[port]} on port {port}")
            print(f"Vulnerable service detected: {vulnerable_services[port]} on port {port}")
            # Check for known CVEs if port is in CVE dictionary
            if port in cve_dict:
                logging.info(f"Known CVEs for port {port}: {', '.join(cve_dict[port])}")
                print(f"Known CVEs for port {port}: {', '.join(cve_dict[port])}")
    return open_ports

def check_default_credentials(ip, port):
    """Check for default credentials on common services."""
    if port == 21:  # FTP
        try:
            response = requests.get(f"ftp://{ip}", auth=('anonymous', 'user'))
            if response.status_code == 200:
                logging.info(f"Default credentials found for FTP on {ip}.")
                print(f"Default credentials found for FTP on {ip}.")
        except Exception:
            pass

def web_directory_scan(ip):
    """Perform a basic web directory scan."""
    for directory in common_directories:
        url = f"http://{ip}/{directory}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                logging.info(f"Directory found: {url}")
                print(f"Directory found: {url}")
        except requests.ConnectionError:
            pass

def directory_traversal_check(ip):
    """Check for potential directory traversal vulnerabilities."""
    traversal_payload = "../../../../etc/passwd"  # Example payload
    url = f"http://{ip}/{traversal_payload}"
    try:
        response = requests.get(url)
        if response.status_code == 200 and "root:" in response.text:
            logging.warning(f"Potential directory traversal vulnerability found at {url}")
            print(f"Potential directory traversal vulnerability found at {url}")
    except requests.ConnectionError:
        pass

def sql_injection_check(ip):
    """Check for potential SQL injection vulnerabilities."""
    for payload in sql_injection_payloads:
        url = f"http://{ip}/search?query={payload}"
        try:
            response = requests.get(url)
            if "error" in response.text.lower() or "sql" in response.text.lower():
                logging.warning(f"Potential SQL injection vulnerability found at {url}")
                print(f"Potential SQL injection vulnerability found at {url}")
        except requests.ConnectionError:
            pass

def xss_check(ip):
    """Check for potential XSS vulnerabilities."""
    for payload in xss_payloads:
        url = f"http://{ip}/search?query={payload}"
        try:
            response = requests.get(url)
            if payload in response.text:
                logging.warning(f"Potential XSS vulnerability found at {url}")
                print(f"Potential XSS vulnerability found at {url}")
        except requests.ConnectionError:
            pass

def get_ip_from_url(url):
    """Extract the IP address from a given URL."""
    try:
        url = re.sub(r'https?://', '', url)
        hostname = url.split('/')[0]
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.error:
        logging.error("Could not resolve the URL to an IP address.")
        print("Could not resolve the URL to an IP address.")
        return None

if __name__ == "__main__":
    target_input = input("Enter the target IP address or URL: ")
    target_ip = None

    if re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$', target_input):
        target_ip = target_input
    else:
        target_ip = get_ip_from_url(target_input)

    if target_ip:
        print(f"Resolved IP: {target_ip}")

        # User input for port scanning options
        ports_input = input("Enter ports to scan (comma-separated) or press Enter for default (21, 22, 23, 80, 443): ")
        if ports_input:
            ports = [int(port.strip()) for port in ports_input.split(",")]
        else:
            ports = list(vulnerable_services.keys())

        print(f"Scanning ports: {ports}")

        open_ports = scan_vulnerable_ports(target_ip, ports)

        if open_ports:
            print(f"Open ports: {', '.join(map(str, open_ports))}")
            logging.info(f"Open ports: {', '.join(map(str, open_ports))}")
            # Check for default credentials and perform a web directory scan for HTTP/HTTPS services
            if any(port in [80, 443] for port in open_ports):
                check_default_credentials(target_ip, 80)
                web_directory_scan(target_ip)
                directory_traversal_check(target_ip)
                sql_injection_check(target_ip)
                xss_check(target_ip)
        else:
            print("No open ports found.")
            logging.info("No open ports found.")
