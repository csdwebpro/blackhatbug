#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import threading
import time
import json
import requests
import socket
import dns.resolver
from urllib.parse import urlparse
import nmap
import concurrent.futures
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama
init(autoreset=True)

class BlackHatRecon:
    def __init__(self, target, threads=10, output_dir="./recon_results", mode="quick"):
        self.target = target
        self.threads = threads
        self.output_dir = output_dir
        self.mode = mode
        self.results = {}
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(f"{output_dir}/subdomains", exist_ok=True)
        os.makedirs(f"{output_dir}/ports", exist_ok=True)
        os.makedirs(f"{output_dir}/web", exist_ok=True)
        os.makedirs(f"{output_dir}/vulnerabilities", exist_ok=True)
        os.makedirs(f"{output_dir}/osint", exist_ok=True)
        
    def print_banner(self):
        banner = pyfiglet.figlet_format("BlackHat Recon", font="slant")
        print(Fore.RED + banner)
        print(Fore.CYAN + "Advanced Reconnaissance Tool v2.0")
        print(Fore.YELLOW + "=" * 50)
        
    def run_command(self, cmd, timeout=300):
        """Execute system command with timeout"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return "", "Command timed out"
        except Exception as e:
            return "", str(e)
    
    def validate_target(self):
        """Validate the target domain or URL"""
        try:
            # Remove protocol if present
            domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
            
            # Basic domain validation
            if '.' not in domain:
                raise ValueError("Invalid domain format")
                
            # Try to resolve domain
            socket.gethostbyname(domain)
            self.clean_domain = domain
            return True
        except Exception as e:
            print(Fore.RED + f"[ERROR] Invalid target: {e}")
            return False
    
    def passive_subdomain_enum(self):
        """Passive subdomain enumeration"""
        print(Fore.CYAN + f"[INFO] Starting passive subdomain enumeration for {self.clean_domain}")
        
        subdomains = set()
        
        # Use multiple methods for subdomain discovery
        methods = [
            f"subfinder -d {self.clean_domain} -silent",
            f"amass enum -passive -d {self.clean_domain} -o {self.output_dir}/subdomains/amass.txt",
            f"curl -s 'https://crt.sh/?q=%25.{self.clean_domain}&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\\.//g' | sort -u"
        ]
        
        for cmd in methods:
            stdout, stderr = self.run_command(cmd)
            if stdout:
                for subdomain in stdout.split('\n'):
                    if subdomain and self.clean_domain in subdomain:
                        subdomains.add(subdomain.strip())
        
        # Save results
        with open(f"{self.output_dir}/subdomains/passive.txt", "w") as f:
            for subdomain in sorted(subdomains):
                f.write(subdomain + "\n")
                
        print(Fore.GREEN + f"[SUCCESS] Found {len(subdomains)} subdomains passively")
        return list(subdomains)
    
    def dns_enumeration(self):
        """DNS record enumeration"""
        print(Fore.CYAN + f"[INFO] Starting DNS enumeration for {self.clean_domain}")
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.clean_domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        # Save DNS results
        with open(f"{self.output_dir}/osint/dns_records.txt", "w") as f:
            for record_type, values in records.items():
                if values:
                    f.write(f"{record_type} Records:\n")
                    for value in values:
                        f.write(f"  {value}\n")
                    f.write("\n")
        
        print(Fore.GREEN + "[SUCCESS] DNS enumeration completed")
        return records
    
    def port_scanning(self):
        """Advanced port scanning with Nmap"""
        print(Fore.CYAN + f"[INFO] Starting port scan for {self.clean_domain}")
        
        try:
            nm = nmap.PortScanner()
            
            # Adjust scan based on mode
            if self.mode == "quick":
                arguments = "-sS -T4 --top-ports 100"
            elif self.mode == "deep":
                arguments = "-sS -sV -sC -O -T4 -p-"
            else:  # stealth
                arguments = "-sS -T2 --top-ports 50"
            
            scan_result = nm.scan(self.clean_domain, arguments=arguments)
            
            # Save detailed results
            with open(f"{self.output_dir}/ports/nmap_scan.txt", "w") as f:
                f.write(json.dumps(scan_result, indent=2))
            
            # Save simplified results
            open_ports = []
            for protocol in nm[self.clean_domain].all_protocols():
                ports = nm[self.clean_domain][protocol].keys()
                for port in ports:
                    state = nm[self.clean_domain][protocol][port]['state']
                    if state == 'open':
                        service = nm[self.clean_domain][protocol][port].get('name', 'unknown')
                        open_ports.append((port, protocol, service))
            
            with open(f"{self.output_dir}/ports/open_ports.txt", "w") as f:
                for port, protocol, service in open_ports:
                    f.write(f"{port}/{protocol} - {service}\n")
            
            print(Fore.GREEN + f"[SUCCESS] Found {len(open_ports)} open ports")
            return open_ports
            
        except Exception as e:
            print(Fore.RED + f"[ERROR] Port scanning failed: {e}")
            return []
    
    def web_discovery(self):
        """Discover web services and endpoints"""
        print(Fore.CYAN + f"[INFO] Starting web discovery for {self.clean_domain}")
        
        # Check common web ports
        web_services = []
        common_ports = [80, 443, 8080, 8443, 3000, 5000, 8000, 9000]
        
        def check_web_service(port):
            try:
                for scheme in ['http', 'https']:
                    url = f"{scheme}://{self.clean_domain}:{port}"
                    try:
                        response = requests.get(url, timeout=5, verify=False)
                        if response.status_code < 500:
                            web_services.append({
                                'url': url,
                                'port': port,
                                'status': response.status_code,
                                'title': self.extract_title(response.text)
                            })
                            break
                    except:
                        continue
            except:
                pass
        
        # Threaded port checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_web_service, common_ports)
        
        # Save web services
        with open(f"{self.output_dir}/web/discovered_services.txt", "w") as f:
            for service in web_services:
                f.write(f"URL: {service['url']}\n")
                f.write(f"Status: {service['status']}\n")
                f.write(f"Title: {service['title']}\n")
                f.write("-" * 50 + "\n")
        
        print(Fore.GREEN + f"[SUCCESS] Found {len(web_services)} web services")
        return web_services
    
    def extract_title(self, html):
        """Extract title from HTML"""
        try:
            start = html.find('<title>') + 7
            end = html.find('</title>')
            return html[start:end].strip() if start > 6 and end > start else "No title"
        except:
            return "No title"
    
    def directory_bruteforce(self, url):
        """Basic directory brute force"""
        print(Fore.CYAN + f"[INFO] Starting directory brute force for {url}")
        
        common_dirs = [
            'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin',
            'test', 'backup', 'uploads', 'images', 'css', 'js', 'api',
            'dashboard', 'control', 'manager', 'webmail', 'cpanel'
        ]
        
        found_dirs = []
        
        def check_directory(dir_path):
            try:
                test_url = f"{url}/{dir_path}"
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code in [200, 301, 302, 403]:
                    found_dirs.append({
                        'path': dir_path,
                        'url': test_url,
                        'status': response.status_code
                    })
            except:
                pass
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_directory, common_dirs)
        
        # Save results
        domain = urlparse(url).netloc
        with open(f"{self.output_dir}/web/directories_{domain}.txt", "w") as f:
            for dir_info in found_dirs:
                f.write(f"{dir_info['status']} - {dir_info['url']}\n")
        
        print(Fore.GREEN + f"[SUCCESS] Found {len(found_dirs)} directories")
        return found_dirs
    
    def vulnerability_scan(self, urls):
        """Basic vulnerability checks"""
        print(Fore.CYAN + f"[INFO] Starting vulnerability assessment")
        
        vulnerabilities = []
        
        for url in urls:
            # Check for common vulnerabilities
            vuln_checks = [
                self.check_sql_injection,
                self.check_xss,
                self.check_info_disclosure
            ]
            
            for check in vuln_checks:
                result = check(url)
                if result:
                    vulnerabilities.append(result)
        
        # Save vulnerabilities
        with open(f"{self.output_dir}/vulnerabilities/findings.txt", "w") as f:
            for vuln in vulnerabilities:
                f.write(f"Type: {vuln['type']}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Description: {vuln['description']}\n")
                f.write(f"Severity: {vuln['severity']}\n")
                f.write("-" * 50 + "\n")
        
        print(Fore.GREEN + f"[SUCCESS] Found {len(vulnerabilities)} potential vulnerabilities")
        return vulnerabilities
    
    def check_sql_injection(self, url):
        """Basic SQL injection check"""
        try:
            test_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users--"]
            
            for payload in test_payloads:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                # Simple error-based detection
                error_indicators = [
                    "sql", "mysql", "ora", "syntax", "error", "warning"
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    return {
                        'type': 'SQL Injection',
                        'url': url,
                        'description': f'Possible SQL injection with payload: {payload}',
                        'severity': 'High'
                    }
        except:
            pass
        return None
    
    def check_xss(self, url):
        """Basic XSS check"""
        try:
            test_payload = "<script>alert('XSS')</script>"
            test_url = f"{url}?q={test_payload}"
            response = requests.get(test_url, timeout=5, verify=False)
            
            if test_payload in response.text:
                return {
                    'type': 'XSS',
                    'url': url,
                    'description': 'Possible XSS vulnerability',
                    'severity': 'Medium'
                }
        except:
            pass
        return None
    
    def check_info_disclosure(self, url):
        """Check for information disclosure"""
        try:
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            # Check for sensitive headers
            sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            for header in sensitive_headers:
                if header in headers:
                    return {
                        'type': 'Information Disclosure',
                        'url': url,
                        'description': f'Sensitive header exposed: {header}: {headers[header]}',
                        'severity': 'Low'
                    }
        except:
            pass
        return None
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(Fore.CYAN + "[INFO] Generating final report")
        
        report_data = {
            'target': self.target,
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'scan_mode': self.mode,
            'results': self.results
        }
        
        # Save JSON report
        with open(f"{self.output_dir}/final_report.json", "w") as f:
            json.dump(report_data, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(report_data)
        
        print(Fore.GREEN + f"[SUCCESS] Reports generated in {self.output_dir}")
    
    def generate_html_report(self, data):
        """Generate HTML report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Recon Report - {data['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: #2d2d2d; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
                .section {{ background: #2d2d2d; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
                .critical {{ color: #ff4444; }}
                .high {{ color: #ff8800; }}
                .medium {{ color: #ffcc00; }}
                .low {{ color: #44ff44; }}
                pre {{ background: #3d3d3d; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🕵️ BlackHat Recon Report</h1>
                    <h2>Target: {data['target']}</h2>
                    <p>Scan Date: {data['timestamp']} | Mode: {data['scan_mode']}</p>
                </div>
        """
        
        # Add sections based on available data
        if 'subdomains' in data['results']:
            html_content += f"""
                <div class="section">
                    <h3>🔍 Subdomain Enumeration</h3>
                    <p>Found {len(data['results']['subdomains'])} subdomains</p>
                    <pre>{chr(10).join(data['results']['subdomains'])}</pre>
                </div>
            """
        
        if 'ports' in data['results']:
            html_content += """
                <div class="section">
                    <h3>🔒 Port Scanning</h3>
                    <pre>
            """
            for port_info in data['results']['ports']:
                html_content += f"Port {port_info[0]}/{port_info[1]} - {port_info[2]}\n"
            html_content += """
                    </pre>
                </div>
            """
        
        if 'vulnerabilities' in data['results']:
            html_content += """
                <div class="section">
                    <h3>⚠️ Vulnerability Findings</h3>
            """
            for vuln in data['results']['vulnerabilities']:
                severity_class = vuln['severity'].lower()
                html_content += f"""
                    <div class="{severity_class}">
                        <strong>{vuln['type']} ({vuln['severity']})</strong><br>
                        URL: {vuln['url']}<br>
                        Description: {vuln['description']}
                    </div>
                    <hr>
                """
            html_content += "</div>"
        
        html_content += """
            </div>
        </body>
        </html>
        """
        
        with open(f"{self.output_dir}/report.html", "w") as f:
            f.write(html_content)
    
    def run_full_scan(self):
        """Execute complete reconnaissance"""
        self.print_banner()
        
        if not self.validate_target():
            return False
        
        print(Fore.YELLOW + f"[START] Beginning reconnaissance for: {self.clean_domain}")
        
        # Execute all reconnaissance modules
        self.results['subdomains'] = self.passive_subdomain_enum()
        self.results['dns_records'] = self.dns_enumeration()
        self.results['ports'] = self.port_scanning()
        
        # Web discovery on main domain and subdomains
        web_services = self.web_discovery()
        self.results['web_services'] = web_services
        
        # Directory brute force on discovered web services
        all_directories = []
        for service in web_services:
            directories = self.directory_bruteforce(service['url'])
            all_directories.extend(directories)
        self.results['directories'] = all_directories
        
        # Vulnerability scanning
        urls = [service['url'] for service in web_services]
        self.results['vulnerabilities'] = self.vulnerability_scan(urls)
        
        # Generate final report
        self.generate_report()
        
        print(Fore.GREEN + f"[COMPLETED] Full reconnaissance finished for {self.clean_domain}")
        print(Fore.GREEN + f"[RESULTS] Check {self.output_dir} for detailed reports")
        
        return True

def main():
    parser = argparse.ArgumentParser(description='BlackHat Recon - Advanced Reconnaissance Tool')
    parser.add_argument('-u', '--url', help='Single target URL or domain')
    parser.add_argument('-f', '--file', help='File containing multiple targets')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', default='./recon_results', help='Output directory')
    parser.add_argument('-m', '--mode', choices=['quick', 'deep', 'stealth'], default='quick', help='Scan mode')
    
    args = parser.parse_args()
    
    targets = []
    
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"[ERROR] File not found: {args.file}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    for target in targets:
        print(Fore.YELLOW + f"\n🎯 Processing target: {target}")
        recon = BlackHatRecon(
            target=target,
            threads=args.threads,
            output_dir=args.output,
            mode=args.mode
        )
        recon.run_full_scan()

if __name__ == "__main__":
    main()
