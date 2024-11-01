# File: security_header_analyzer.py

import requests
from datetime import datetime
from typing import Dict, List

class SecurityHeaderAnalyzer:
    def __init__(self):
        """Initialize the analyzer with expected security headers."""
        # Dictionary of security headers to check, with descriptions and recommendations
        self.expected_headers = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'recommended': 'max-age=31536000; includeSubDomains',
                'severity': 'HIGH',
                'details': 'Prevents downgrade attacks and cookie hijacking'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'recommended': 'DENY or SAMEORIGIN',
                'severity': 'MEDIUM',
                'details': 'Controls whether the page can be embedded in frames'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME-sniffing',
                'recommended': 'nosniff',
                'severity': 'MEDIUM',
                'details': 'Stops browsers from interpreting files as a different MIME type'
            },
            'Content-Security-Policy': {
                'description': 'Controls resource loading',
                'recommended': 'script-src \'self\'; object-src \'none\'',
                'severity': 'HIGH',
                'details': 'Defines approved sources of content that browser may load'
            },
            'X-XSS-Protection': {
                'description': 'Enables XSS filtering',
                'recommended': '1; mode=block',
                'severity': 'MEDIUM',
                'details': 'Enables browser\'s XSS protection mechanisms'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'recommended': 'strict-origin-when-cross-origin',
                'severity': 'LOW',
                'details': 'Controls how much referrer information is sent'
            }
        }

    def analyze_headers(self, url: str) -> Dict:
        """
        Analyze security headers for the given URL.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            Dict: Analysis results including present and missing headers
        """
        try:
            # Set up request headers
            headers = {
                'User-Agent': 'Security-Header-Analyzer/1.0'
            }
            
            # Make the request
            response = requests.get(url, headers=headers, verify=True, timeout=10)
            
            # Analyze the response headers
            results = {
                'url': url,
                'scan_time': datetime.now().isoformat(),
                'status_code': response.status_code,
                'headers_analysis': self._analyze_security_headers(response.headers),
                'missing_headers': self._get_missing_headers(response.headers),
                'overall_score': self._calculate_score(response.headers)
            }
            
            return results
            
        except requests.exceptions.SSLError:
            return {'error': 'SSL/TLS connection failed', 'url': url}
        except requests.exceptions.ConnectionError:
            return {'error': 'Failed to connect to the server', 'url': url}
        except requests.exceptions.Timeout:
            return {'error': 'Request timed out', 'url': url}
        except requests.exceptions.RequestException as e:
            return {'error': f'Request failed: {str(e)}', 'url': url}

    def _analyze_security_headers(self, headers: Dict) -> Dict:
        """
        Analyze the security headers that are present.
        
        Args:
            headers (Dict): Response headers from the request
            
        Returns:
            Dict: Analysis of present security headers
        """
        analysis = {}
        
        for header in self.expected_headers:
            if header in headers:
                analysis[header] = {
                    'present': True,
                    'value': headers[header],
                    'recommendation': self._analyze_header_value(header, headers[header]),
                    'description': self.expected_headers[header]['description'],
                    'severity': self.expected_headers[header]['severity'],
                    'details': self.expected_headers[header]['details']
                }
        
        return analysis

    def _get_missing_headers(self, headers: Dict) -> List[Dict]:
        """
        Identify which expected security headers are missing.
        
        Args:
            headers (Dict): Response headers from the request
            
        Returns:
            List[Dict]: List of missing headers and their details
        """
        missing = []
        
        for header in self.expected_headers:
            if header not in headers:
                missing.append({
                    'header': header,
                    'description': self.expected_headers[header]['description'],
                    'recommended': self.expected_headers[header]['recommended'],
                    'severity': self.expected_headers[header]['severity'],
                    'details': self.expected_headers[header]['details']
                })
                
        return missing

    def _analyze_header_value(self, header: str, value: str) -> str:
        """
        Analyze the value of a specific security header.
        
        Args:
            header (str): The header name
            value (str): The header value
            
        Returns:
            str: Recommendation based on the header value
        """
        if header == 'Strict-Transport-Security':
            if 'includeSubDomains' not in value:
                return 'Consider adding includeSubDomains directive'
            if 'max-age' not in value:
                return 'Missing max-age directive'
            max_age = int(value.split('max-age=')[1].split(';')[0])
            if max_age < 31536000:  # One year in seconds
                return 'Consider increasing max-age to at least one year'
                
        elif header == 'X-Frame-Options':
            if value.upper() not in ['DENY', 'SAMEORIGIN']:
                return 'Consider using DENY or SAMEORIGIN'
                
        elif header == 'Content-Security-Policy':
            missing_directives = []
            if 'script-src' not in value:
                missing_directives.append('script-src')
            if 'default-src' not in value:
                missing_directives.append('default-src')
            if missing_directives:
                return f'Consider adding these directives: {", ".join(missing_directives)}'
                
        return 'Value appears to be properly configured'

    def _calculate_score(self, headers: Dict) -> int:
        """
        Calculate overall security score based on headers.
        
        Args:
            headers (Dict): Response headers from the request
            
        Returns:
            int: Security score from 0-100
        """
        score = 0
        max_score = len(self.expected_headers) * 2  # Maximum possible score
        
        for header in self.expected_headers:
            if header in headers:
                # Points for header presence
                score += 1
                # Additional points for correct configuration
                if self._analyze_header_value(header, headers[header]) == 'Value appears to be properly configured':
                    score += 1
                    
        return int((score / max_score) * 100)

    def generate_report(self, results: Dict) -> str:
        """
        Generate a formatted report from analysis results.
        
        Args:
            results (Dict): Analysis results
            
        Returns:
            str: Formatted report
        """
        if 'error' in results:
            return f"""
Error Report
===========
URL: {results['url']}
Error: {results['error']}
"""

        report = f"""
Security Headers Analysis Report
==============================
URL: {results['url']}
Scan Time: {results['scan_time']}
Overall Score: {results.get('overall_score', 'N/A')}/100

Present Security Headers:
-----------------------"""
        
        for header, analysis in results.get('headers_analysis', {}).items():
            report += f"\n\n{header}:"
            report += f"\n  Value: {analysis['value']}"
            report += f"\n  Recommendation: {analysis['recommendation']}"
            report += f"\n  Severity: {analysis['severity']}"
            report += f"\n  Details: {analysis['details']}"
            
        report += "\n\nMissing Security Headers:"
        report += "\n------------------------"
        
        for header in results.get('missing_headers', []):
            report += f"\n\n{header['header']}:"
            report += f"\n  Recommended: {header['recommended']}"
            report += f"\n  Severity: {header['severity']}"
            report += f"\n  Details: {header['details']}"
            
        return report