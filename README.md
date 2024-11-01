# Security Headers Analyzer

A command-line tool to analyze and report on security headers of web applications. This tool helps security professionals and developers assess the implementation of HTTP security headers and provides recommendations for improving website security.

## Features

- 🔍 Analyzes crucial security headers including:
  - Strict-Transport-Security (HSTS)
  - X-Frame-Options
  - X-Content-Type-Options
  - Content-Security-Policy
  - X-XSS-Protection
  - Referrer-Policy
- 📊 Generates detailed reports in both TXT and JSON formats
- 🎯 Provides specific recommendations for improving security headers
- 💯 Calculates an overall security score
- 📁 Maintains a history of security scans
- 🚀 Easy-to-use command-line interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/oussben811/SecurityHeaderAnalyzer.git
cd SecurityHeaderAnalyzer
```

2. Install the required dependencies:
```bash
pip install requests
```

## Usage

Basic usage:
```bash
python main.py https://example.com
```

Advanced options:
```bash
python main.py https://example.com -o custom_reports -f json -q
```

### Command Line Arguments

- `url`: The URL to analyze (required)
- `-o, --output-dir`: Directory to save reports (default: "reports")
- `-f, --format`: Output format (choices: txt, json; default: txt)
- `-q, --quiet`: Only output the report file location

## Sample Output

```
Security Headers Analysis Report
==============================
URL: https://example.com
Scan Time: 2024-01-01T12:00:00
Overall Score: 75/100

Present Security Headers:
-----------------------
Strict-Transport-Security:
  Value: max-age=31536000; includeSubDomains
  Recommendation: Value appears to be properly configured
  Severity: HIGH
  Details: Prevents downgrade attacks and cookie hijacking

Missing Security Headers:
------------------------
Content-Security-Policy:
  Recommended: script-src 'self'; object-src 'none'
  Severity: HIGH
  Details: Defines approved sources of content that browser may load
```

## Project Structure

```
SecurityHeaderAnalyzer/
├── main.py                  # Command-line interface and main program flow
├── security_header_analyzer.py  # Core analysis functionality
├── report_manager.py        # Report generation and management
└── reports/                 # Directory for saved reports
```

## Security Headers Analyzed

| Header Name | Severity | Purpose |
|------------|----------|---------|
| Strict-Transport-Security | HIGH | Enforces HTTPS connections |
| Content-Security-Policy | HIGH | Controls resource loading |
| X-Frame-Options | MEDIUM | Prevents clickjacking attacks |
| X-Content-Type-Options | MEDIUM | Prevents MIME-sniffing |
| X-XSS-Protection | MEDIUM | Enables XSS filtering |
| Referrer-Policy | LOW | Controls referrer information |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request


## Acknowledgments

- Inspired by OWASP Security Headers Project
- Built with Python and the Requests library

## Author

[@oussben811](https://github.com/oussben811)

## Disclaimer

This tool is for educational and testing purposes only. Always ensure you have permission to test security headers on any web application.