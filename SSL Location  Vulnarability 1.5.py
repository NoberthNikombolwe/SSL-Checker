import tkinter as tk
from tkinter import messagebox
import requests
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
import socket
import nmap

def get_san_entries(x509_cert):
    try:
        ext = x509_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value.get_values_for_type(x509.DNSName)
        return sans
    except x509.ExtensionNotFound:
        return []

def get_server_location(ip_address):
    try:
        response = requests.get(f"http://ipinfo.io/{ip_address}/json")
        data = response.json()
        return data.get('city', ''), data.get('region', ''), data.get('country', '')
    except requests.exceptions.RequestException:
        return None, None, None

def check_vulnerabilities(url):
    try:
        # Check for open ports using Nmap
        nm = nmap.PortScanner()
        nm.scan(urlparse(f"https://{url}").hostname, arguments='-p 80,443')
        open_ports = nm[urlparse(f"https://{url}").hostname].all_tcp()

        # Check for common vulnerabilities (simplified example)
        vulnerabilities = []
        if 80 in open_ports:
            vulnerabilities.append("HTTP (port 80) is open, consider enforcing HTTPS.")
        if 443 in open_ports:
            vulnerabilities.append("HTTPS (port 443) is open.")

        return vulnerabilities

    except nmap.PortScannerError as e:
        print(f"Error during port scanning: {e}")
        return []

def get_ssl_certificate_info():
    url = url_entry.get()

    try:
        # Fetch the SSL certificate
        response = requests.get(f"https://{url}", timeout=5)
        cert = ssl.get_server_certificate((url, 443))

        # Parse the certificate
        x509_cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())

        # Extract certificate details
        common_name = x509_cert.subject.rfc4514_string().split(',')[0][3:]
        expiration_date = x509_cert.not_valid_after
        issuer = x509_cert.issuer.rfc4514_string()
        issue_date = x509_cert.not_valid_before
        sans = get_san_entries(x509_cert)
        server_type = response.headers.get('Server')
        ip_address = socket.gethostbyname(urlparse(f"https://{url}").netloc)

        # Get server location
        city, region, country = get_server_location(ip_address)

        # Check for vulnerabilities
        vulnerabilities = check_vulnerabilities(url)

        # Display information using Text widget
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"SSL certificate for {url}:\n"
                                    f"Common Name: {common_name}\n"
                                    f"Issuer: {issuer}\n"
                                    f"Certificate Validity: {issue_date} to {expiration_date}\n"
                                    f"Subject Alternative Names (SANs):\n")
        for san in sans:
            result_text.insert(tk.END, f"- {san}\n")

        result_text.insert(tk.END, f"Server Type: {server_type}\n"
                                    f"IP Address: {ip_address}\n"
                                    f"Server Location: {city}, {region}, {country}\n"
                                    f"Vulnerabilities: {', '.join(vulnerabilities)}")

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Error", f"Failed to fetch SSL certificate for {url}: {e}")

# Create the main window
window = tk.Tk()
window.title("SSL Certificate and Vulnerability Info Viewer")

# Create and place widgets
url_label = tk.Label(window, text="Enter URL:")
url_label.pack(pady=10)

url_entry = tk.Entry(window, width=30)
url_entry.pack(pady=10)

check_button = tk.Button(window, text="Get SSL Certificate and Vulnerability Info", command=get_ssl_certificate_info)
check_button.pack(pady=10)

# Use a Text widget for displaying information
result_text = tk.Text(window, height=20, width=80, wrap=tk.WORD)
result_text.pack(pady=10)

# Run the main loop
window.mainloop()
