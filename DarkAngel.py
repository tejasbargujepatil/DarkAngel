import socket
import re
import requests
import logging
import concurrent.futures

# Setting up logging to track the results and errors during the vulnerability scan.
logging.basicConfig(
    filename='vulnerability_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# List of common vulnerable ports and their associated services.
# I've added comments to explain how attackers might exploit these services.
vulnerable_services = {
    21: "FTP",      # Attackers can exploit weak credentials to access sensitive files.
    22: "SSH",      # Brute-force attacks can lead to unauthorized server access.
    23: "Telnet",   # Unencrypted sessions are easy targets for credential theft.
    25: "SMTP",     # Misconfigured servers can be used to send spam or phishing emails.
    # More services are listed with similar explanations...
    8000: "HTTP Alternative"  # Used for alternative HTTP setups; vulnerabilities are similar to HTTP.
}

# Mapping ports to known CVEs (Common Vulnerabilities and Exposures).
# This allows us to identify specific vulnerabilities when scanning ports.
cve_dict = {
    21: ["CVE-2021-23021", "CVE-2016-20012"],  # FTP vulnerabilities
    22: ["CVE-2021-28041", "CVE-2018-15473"],  # SSH vulnerabilities
    # More mappings...
    8000: ["CVE-2021-22960"]  # HTTP Alternative vulnerabilities
}

# A simple list of common web directories for scanning.
common_directories = [
    "admin", "login", "dashboard", "api", "uploads", 
    "wp-admin", "admin.php", "config.php", "user", "settings"
]

# Payloads for testing SQL injection and XSS vulnerabilities.
sql_injection_payloads = [
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*"
]
xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'><script>alert(1)</script>"
]

def is_port_open(ip, port):
    """Check if a specific port is open on a given IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((ip, port)) == 0

def scan_single_port(ip, port):
    """Scan a single port and log the results."""
    if is_port_open(ip, port):
        service = vulnerable_services.get(port, "Unknown Service")
        logging.info(f"Open port detected: {port} running {service}")
        print(f"Open port detected: {port} running {service}")

        # Check for known CVEs if the port has an entry in the CVE dictionary.
        if port in cve_dict:
            cves = ", ".join(cve_dict[port])
            logging.info(f"Known CVEs for port {port}: {cves}")
            print(f"Known CVEs for port {port}: {cves}")

def scan_vulnerable_ports(ip, ports):
    """Use threading to scan multiple ports concurrently."""
    print(f"Scanning {len(ports)} ports on {ip}...")
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(lambda port: scan_single_port(ip, port), ports)

def check_default_credentials(ip, port):
    """Check if default credentials are being used for services like FTP."""
    if port == 21:  # FTP
        try:
            response = requests.get(f"ftp://{ip}", auth=('anonymous', 'user'))
            if response.status_code == 200:
                logging.warning(f"Default credentials found for FTP on {ip}")
                print(f"Default credentials found for FTP on {ip}")
        except requests.RequestException as e:
            logging.error(f"Error checking FTP credentials on {ip}: {e}")

def web_directory_scan(ip):
    """Scan for common web directories."""
    print(f"Scanning web directories on {ip}...")
    for directory in common_directories:
        url = f"http://{ip}/{directory}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                logging.info(f"Found directory: {url}")
                print(f"Found directory: {url}")
        except requests.ConnectionError:
            pass

def directory_traversal_check(ip):
    """Check for directory traversal vulnerabilities."""
    traversal_payload = "../../../../etc/passwd"
    url = f"http://{ip}/{traversal_payload}"
    try:
        response = requests.get(url)
        if response.status_code == 200 and "root:" in response.text:
            logging.warning(f"Potential directory traversal vulnerability at {url}")
            print(f"Potential directory traversal vulnerability at {url}")
    except requests.ConnectionError:
        pass

def sql_injection_check(ip):
    """Check for SQL injection vulnerabilities."""
    print("Checking for SQL injection vulnerabilities...")
    for payload in sql_injection_payloads:
        url = f"http://{ip}/search?q={payload}"
        try:
            response = requests.get(url)
            if "error" in response.text.lower():
                logging.warning(f"SQL injection vulnerability at {url}")
                print(f"SQL injection vulnerability at {url}")
        except requests.ConnectionError:
            pass

def xss_check(ip):
    """Check for XSS vulnerabilities."""
    print("Checking for XSS vulnerabilities...")
    for payload in xss_payloads:
        url = f"http://{ip}/search?q={payload}"
        try:
            response = requests.get(url)
            if payload in response.text:
                logging.warning(f"XSS vulnerability at {url}")
                print(f"XSS vulnerability at {url}")
        except requests.ConnectionError:
            pass

if __name__ == "__main__":
    target_ip = input("Enter the target IP or domain: ").strip()

    # Validate the target format
    if re.match(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", target_ip) or re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_ip):
        ports = list(vulnerable_services.keys())
        scan_vulnerable_ports(target_ip, ports)
        check_default_credentials(target_ip, 21)
        web_directory_scan(target_ip)
        directory_traversal_check(target_ip)
        sql_injection_check(target_ip)
        xss_check(target_ip)
        print("Scan complete. Check 'vulnerability_scan.log' for details.")
    else:
        print("Invalid target. Please enter a valid IP or domain.")
