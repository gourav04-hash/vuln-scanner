
# Web Vulnerability Scanner



## Features

- **URL Validation & Crawling**: Automatically validates and crawls domains or subdomains.
- **SQL Injection Detection**: Detects potential SQL injection vulnerabilities by testing common payloads.
- **XSS Detection**: Tests for Cross-Site Scripting (XSS) vulnerabilities with various payloads.
- **Security Header Checks**: Identifies missing security headers such as `X-Content-Type-Options`, `Content-Security-Policy`, and `Strict-Transport-Security`.
- **Outdated Software Detection**: Flags servers running outdated or vulnerable software versions.
- **Known Weaknesses**: Identifies exposed files like `robots.txt` or admin panels.
  
## Installation

### Requirements

This tool requires the following Python libraries:
- `requests`
- `beautifulsoup4`
- `ipaddress`

To install the required dependencies, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/gourav04-hash/vuln-scanner.git
    ```

2. **Install dependencies**:
    Using `pip`, install the necessary Python packages:
    ```bash
    pip install -r requirements.txt
    ```

### Requirements File (`requirements.txt`)

If you don't have a `requirements.txt` file, create it with the following content:

```
requests==2.28.0
beautifulsoup4==4.11.1
```

## Usage

### Running the Scanner

Once the dependencies are installed, you can run the vulnerability scanner by executing the Python script:

```bash
python scanner.py
```

### Interactive Menu

Once the script starts, you'll see the following interactive menu:

```
--- Simple Web Vulnerability Scanner ---
1. Add a URL for scanning
2. Crawl a domain or subdomain
3. Start the scan
4. Exit
```

#### 1. **Add a URL for scanning**

You can add URLs that you'd like to scan for vulnerabilities. The scanner will check each URL for issues like XSS, SQL injection, and security headers.

#### 2. **Crawl a domain or subdomain**

You can enter a domain or subdomain to crawl, and the scanner will follow links found on the page up to a specified depth.

#### 3. **Start the scan**

Once URLs are added and optionally crawled, you can start the scan. This will check for:
- **XSS Vulnerabilities**
- **SQL Injection Vulnerabilities**
- **Security Header Misconfigurations**
- **Outdated Software Versions**
- **Exposed Files & Admin Panels**

#### 4. **Exit**

Exits the scanner.

### Example Output

Here's what the output might look like after a scan:

```plaintext
[INFO] Added URL for scanning: http://example.com

[INFO] Scanning: http://example.com
[CRAWLING] http://example.com
[VULNERABILITY] Potential XSS vulnerability found at http://example.com
[VULNERABILITY] Potential SQL Injection vulnerability found at http://example.com
[WARNING] Missing security headers at http://example.com/: X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security
[INFO] Server header at http://example.com/: Apache (Check for known vulnerabilities)
[INFO] Exposed robots.txt file found at http://example.com/robots.txt
[INFO] Exposed admin panel found at http://example.com/admin
[INFO] Scan complete for: http://example.com
```

### Scan Details

1. **XSS**: Checks if the site is vulnerable to Cross-Site Scripting (XSS).
2. **SQL Injection**: Tests for SQL injection vulnerabilities by injecting common payloads.
3. **Security Headers**: Verifies that the site is using proper HTTP security headers to prevent attacks.
4. **Outdated Software**: Identifies outdated software versions and provides information on known vulnerabilities.
5. **Known Weaknesses**: Detects exposed sensitive files such as `robots.txt` or publicly accessible admin panels.

## Contributing

Feel free to fork this repository, create a branch, and submit a pull request. We welcome contributions that improve the functionality and detection capabilities of the scanner.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Create a new pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- **requests**: HTTP library for Python.
- **BeautifulSoup4**: HTML parsing library.
- **ipaddress**: Provides IP address manipulation capabilities.

##Notes:
   -Security Warning: Use this tool only on websites you own or have explicit permission to test. Unauthorized scanning can be illegal and unethical.
