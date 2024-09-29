# DarkAngel - Vulnerability Scanning Tool

<img src="https://assets.burberry.com/is/image/Burberryltd/797747F1-08C1-4D69-A1E7-B7428A762092?$BBY_V2_SL_1x1$&wid=2500&hei=2500" alt="DarkAngel Logo" width="400" height="400">
 <!-- Replace with your logo URL if available -->

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [Functionality Overview](#functionality-overview)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

## Introduction
DarkAngel is a powerful vulnerability scanning tool designed for security professionals and enthusiasts. This script helps identify potential vulnerabilities in network services and web applications by scanning for open ports, checking for default credentials, and performing various web security tests.

## Features
- **Port Scanning**: Detects common vulnerable ports and associated services.
- **CVE Checks**: Identifies known vulnerabilities associated with the detected services.
- **Default Credentials Testing**: Attempts to connect using default credentials for services like FTP.
- **Web Directory Scanning**: Searches for common web directories that may be exposed.
- **Security Testing**: Conducts checks for directory traversal, SQL injection, and XSS vulnerabilities.

## Technologies Used
- Python 3.x
- `socket` library for network connections
- `requests` library for HTTP requests
- `concurrent.futures` for multithreading
- Logging for tracking scan results

## Installation
To get started with DarkAngel, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/tejasbargujepatil/DarkAngel.git
Navigate to the Project Directory:

 ```bash
cd DarkAngel
 ```
Install Required Libraries: Ensure you have Python and pip installed, then run:

 ```bash
pip install requests
 ```
Usage
To run the vulnerability scanner, execute the script in your terminal:

 ```bash

python vulnerability_scan.py

 ```
You will be prompted to enter the target IP address or domain (without http/https). Ensure the target is valid and that you have permission to scan it.

**Example**

Enter the target IP address or domain (without http/https): 192.168.1.1 <br>

**Functionality Overview** <br>
<br>
Port Scanning: Scans for common vulnerable ports including FTP, SSH, HTTP, and more.
<br>
CVE Checks: If a vulnerable service is detected, the script logs known CVEs associated with that service. <br>
Default Credentials Check: Attempts to connect to FTP using default anonymous credentials. <br>
Web Directory Scan: Checks for common directories like /admin, /login, etc., to find potentially exposed areas of a web application. <br>

<hr>
**Security Checks:** <br>

Directory Traversal: Tests for directory traversal vulnerabilities. <br>
SQL Injection: Checks for potential SQL injection points. <br>
XSS Vulnerabilities: Tests for reflected XSS vulnerabilities. <br>

**Contributing:**

*Contributions are welcome! If you have suggestions or improvements, feel free to submit a pull request or open an issue. Please ensure that your contributions follow the project’s code style and standards.*
<br>
**License**

This project is licensed under the MIT License. See the LICENSE file for details.

**_Author_**

**_Tejas Bargujepatil_**

**Disclaimer: This tool is intended for educational purposes only. Ensure you have permission to scan and test any network or application before use.**
