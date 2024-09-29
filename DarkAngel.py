import socket
import re
import requests
import logging
import concurrent.futures

# Setup logging
logging.basicConfig(filename='vulnerability_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Expanded list of common vulnerable ports and services with comments on attacker operations
vulnerable_services = {
    21: "FTP",  # File Transfer Protocol - attackers can exploit weak credentials to gain access to sensitive files.
    22: "SSH",  # Secure Shell - attackers may try brute force attacks to gain unauthorized access to servers.
    23: "Telnet",  # Telnet - unencrypted connections can lead to credential theft and unauthorized access.
    25: "SMTP",  # Simple Mail Transfer Protocol - attackers can send spam or phishing emails through misconfigured servers.
    53: "DNS",  # Domain Name System - attackers might manipulate DNS records to redirect traffic or perform DNS spoofing.
    67: "DHCP",  # Dynamic Host Configuration Protocol - attackers could set up rogue DHCP servers to intercept traffic.
    69: "TFTP",  # Trivial File Transfer Protocol - can be used to transfer files, including malware, due to lack of authentication.
    80: "HTTP",  # Hypertext Transfer Protocol - attackers may exploit web vulnerabilities to inject malicious scripts.
    88: "Kerberos",  # Kerberos - vulnerabilities can lead to credential theft and unauthorized access to systems.
    110: "POP3",  # Post Office Protocol 3 - attackers can gain access to email accounts by exploiting weak passwords.
    139: "NetBIOS",  # NetBIOS - can be used for network file sharing, and attacks can lead to unauthorized file access.
    143: "IMAP",  # Internet Message Access Protocol - attackers can access and manipulate emails if credentials are compromised.
    161: "SNMP",  # Simple Network Management Protocol - vulnerabilities can allow attackers to gather sensitive network information.
    162: "SNMP Trap",  # SNMP Trap - can be exploited to receive unauthorized notifications or alerts.
    443: "HTTPS",  # Hypertext Transfer Protocol Secure - attackers might exploit misconfigurations or weak SSL/TLS setups.
    3306: "MySQL",  # MySQL - SQL injection attacks can lead to data theft and unauthorized database access.
    3389: "RDP",  # Remote Desktop Protocol - attackers can exploit weak passwords to gain access to remote systems.
    5432: "PostgreSQL",  # PostgreSQL - similar to MySQL, vulnerable to SQL injection and misconfigured access.
    5900: "VNC",  # Virtual Network Computing - weak passwords can allow unauthorized remote access to desktops.
    6379: "Redis",  # Redis - insecure setups can lead to unauthorized access to databases.
    8080: "HTTP Proxy",  # HTTP Proxy - misconfigured proxies can be exploited to bypass security controls.
    9200: "Elasticsearch",  # Elasticsearch - attackers can access sensitive data if security is misconfigured.
    9300: "Elasticsearch Transport",  # Elasticsearch Transport - vulnerabilities can expose cluster data to attackers.
    5000: "Docker",  # Docker - insecure APIs can be exploited to gain access to container management.
    8000: "HTTP Alternative"  # HTTP Alternative - can be exploited similarly to HTTP for web vulnerabilities.
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

def scan_single_port(ip, port):
    """Check a single port and log results."""
    if is_port_open(ip, port):
        logging.info(f"Vulnerable service detected: {vulnerable_services[port]} on port {port}")
        print(f"Vulnerable service detected: {vulnerable_services[port]} on port {port}")
        # Check for known CVEs if port is in CVE dictionary
        if port in cve_dict:
            logging.info(f"Known CVEs for port {port}: {', '.join(cve_dict[port])}")
            print(f"Known CVEs for port {port}: {', '.join(cve_dict[port])}")

def scan_vulnerable_ports(ip, ports):
    """Scan for vulnerable ports and services using threading."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(scan_single_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            if future.result() is not None:
                open_ports.append(port)
    return open_ports

def check_default_credentials(ip, port):
    """Check for default credentials on common services."""
    if port == 21:  # FTP
        try:
            response = requests.get(f"ftp://{ip}", auth=('anonymous', 'user'))
            if response.status_code == 200:
                logging.info(f"Default credentials found for FTP on {ip}.")
                print(f"Default credentials found for FTP on {ip}.")
        except requests.RequestException as e:
            logging.error(f"Error checking FTP default credentials: {e}")

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
        url = f"http://{ip}/search?q={payload}"
        try:
            response = requests.get(url)
            if "error" in response.text.lower():  # Check for SQL error messages
                logging.warning(f"Potential SQL injection vulnerability found at {url}")
                print(f"Potential SQL injection vulnerability found at {url}")
        except requests.ConnectionError:
            pass

def xss_check(ip):
    """Check for potential XSS vulnerabilities."""
    for payload in xss_payloads:
        url = f"http://{ip}/search?q={payload}"
        try:
            response = requests.get(url)
            if payload in response.text:  # Check if the payload is reflected in the response
                logging.warning(f"Potential XSS vulnerability found at {url}")
                print(f"Potential XSS vulnerability found at {url}")
        except requests.ConnectionError:
            pass

if __name__ == "__main__":
    target_ip = input("Enter the target IP address or domain (without http/https): ").strip()

    # Validate target IP or URL format
    if re.match(r"^(http://|https://)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+)$", target_ip) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_ip):
        ports = [21, 22, 23, 25, 53, 67, 69, 80, 88, 110, 139, 143, 161, 162, 443, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 9300, 5000, 8000]
        print(f"Scanning ports: {ports}")
        scan_vulnerable_ports(target_ip, ports)

        # Additional checks
        check_default_credentials(target_ip, 21)  # FTP
        web_directory_scan(target_ip)
        directory_traversal_check(target_ip)
        sql_injection_check(target_ip)
        xss_check(target_ip)

        print("Vulnerability scanning complete.")
    else:
        print("Invalid target. Please enter a valid IP address or URL.")
