import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import ipaddress
import sys

class EnhancedWebScanner:
    def __init__(self):
        self.visited_urls = set()
        self.target_domains = set()

    def add_url(self, url):
        """Adds a URL to the scan list."""
        if self.is_valid_url(url):
            self.visited_urls.add(url)
            netloc = urlparse(url).netloc
            if self.is_ip_address(netloc):
                self.target_domains.add(netloc)
            else:
                self.target_domains.add(netloc)
            print(f"\033[32m[INFO]\033[0m Added URL for scanning: {url}")
        else:
            print("\033[31m[ERROR]\033[0m Invalid URL. Please enter a valid URL.")

    def is_valid_url(self, url):
        """Validates a URL."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def is_ip_address(self, address):
        """Checks if the address is an IP address."""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def crawl(self, url, max_depth=1):
        """Crawls a domain or subdomain to find links."""
        if url in self.visited_urls or max_depth == 0:
            return
        print(f"\033[34m[CRAWLING]\033[0m {url}")
        self.visited_urls.add(url)

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            for link in soup.find_all('a', href=True):
                full_url = urljoin(url, link['href'])
                parsed_url = urlparse(full_url)

                # Include only URLs from the target domains or IP addresses
                if parsed_url.netloc in self.target_domains or self.is_ip_address(parsed_url.netloc):
                    self.crawl(full_url, max_depth - 1)
        except requests.RequestException as e:
            print(f"\033[31m[ERROR]\033[0m Error crawling {url}: {e}")

    def test_xss(self, url):
        """Tests for XSS vulnerabilities."""
        payload = "<script>alert('XSS')</script>"
        params = {'q': payload}
        try:
            response = requests.get(url, params=params, timeout=10)
            if payload in response.text:
                print(f"\033[31m[VULNERABILITY]\033[0m Potential XSS vulnerability found at {url}")
        except requests.RequestException as e:
            print(f"\033[31m[ERROR]\033[0m Error testing XSS on {url}: {e}")

    def test_sql_injection(self, url):
        """Tests for SQL Injection vulnerabilities."""
        payload = "' OR '1'='1"
        params = {'id': payload}
        try:
            response = requests.get(url, params=params, timeout=10)
            if "syntax" in response.text.lower() or "sql" in response.text.lower():
                print(f"\033[31m[VULNERABILITY]\033[0m Potential SQL Injection vulnerability found at {url}")
        except requests.RequestException as e:
            print(f"\033[31m[ERROR]\033[0m Error testing SQL Injection on {url}: {e}")

    def check_security_headers(self, url):
        """Checks for missing security headers."""
        try:
            response = requests.head(url, timeout=10)
            headers = response.headers

            # Check for common security headers
            missing_headers = []
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            if 'Content-Security-Policy' not in headers:
                missing_headers.append('Content-Security-Policy')
            if 'Strict-Transport-Security' not in headers:
                missing_headers.append('Strict-Transport-Security')
            
            if missing_headers:
                print(f"\033[31m[WARNING]\033[0m Missing security headers at {url}: {', '.join(missing_headers)}")
            else:
                print(f"\033[32m[INFO]\033[0m All security headers present at {url}.")
        except requests.RequestException as e:
            print(f"\033[31m[ERROR]\033[0m Error checking headers on {url}: {e}")

    def check_outdated_software(self, url):
        """Checks for outdated server software."""
        try:
            response = requests.get(url, timeout=10)
            server_header = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')

            if server_header:
                print(f"\033[33m[INFO]\033[0m Server header at {url}: {server_header} (Check for known vulnerabilities)")
            if powered_by:
                print(f"\033[33m[INFO]\033[0m X-Powered-By header at {url}: {powered_by} (Check for known vulnerabilities)")
        except requests.RequestException as e:
            print(f"\033[31m[ERROR]\033[0m Error checking software version on {url}: {e}")

    def test_known_weaknesses(self, url):
        """Checks for known weaknesses like exposed robots.txt and admin panels."""
        try:
            # Check for exposed robots.txt
            robots_url = urljoin(url, '/robots.txt')
            response = requests.get(robots_url, timeout=10)
            if response.status_code == 200:
                print(f"\033[33m[INFO]\033[0m Exposed robots.txt file found at {robots_url}")

            # Check for exposed admin panels
            admin_url = urljoin(url, '/admin')
            response = requests.get(admin_url, timeout=10)
            if response.status_code == 200:
                print(f"\033[33m[INFO]\033[0m Exposed admin panel found at {admin_url}")
        except requests.RequestException as e:
            print(f"\033[31m[ERROR]\033[0m Error testing for known weaknesses on {url}: {e}")

    def scan(self):
        """Performs the scan on all collected URLs."""
        print("\n\033[1m[SCAN RESULTS]\033[0m")
        for url in self.visited_urls:
            print(f"\nScanning: \033[34m{url}\033[0m")
            self.test_xss(url)
            self.test_sql_injection(url)
            self.check_security_headers(url)
            self.check_outdated_software(url)
            self.test_known_weaknesses(url)
            print("\033[32m[INFO]\033[0m Scan complete for: " + url)


def main():
    scanner = EnhancedWebScanner()
    while True:
        print("\n\033[1m--- Simple Web Vulnerability Scanner ---\033[0m")
        print("1. Add a URL for scanning")
        print("2. Crawl a domain or subdomain")
        print("3. Start the scan")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            url = input("Enter the URL to add: ")
            scanner.add_url(url)
        elif choice == '2':
            url = input("Enter the domain or subdomain to crawl: ")
            if scanner.is_valid_url(url):
                max_depth = int(input("Enter the crawl depth (default: 1): ") or 1)
                scanner.crawl(url, max_depth)
            else:
                print("\033[31m[ERROR]\033[0m Invalid URL. Please enter a valid URL.")
        elif choice == '3':
            scanner.scan()
        elif choice == '4':
            print("\033[32m[INFO]\033[0m Exiting the scanner. Goodbye!")
            break
        else:
            print("\033[31m[ERROR]\033[0m Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
