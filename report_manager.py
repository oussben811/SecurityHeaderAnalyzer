# File: report_manager.py

import os
import json
from datetime import datetime
from typing import Dict, Optional

class ReportManager:
    def __init__(self, output_dir: str = "reports"):
        """
        Initialize the report manager.
        
        Args:
            output_dir (str): Directory where reports will be saved
        """
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self) -> None:
        """Create the output directory if it doesn't exist."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def _generate_filename(self, url: str, extension: str = 'txt') -> str:
        """
        Generate a filename for the report.
        
        Args:
            url (str): URL that was analyzed
            extension (str): File extension (txt, json, etc.)
            
        Returns:
            str: Generated filename
        """
        # Remove http:// or https:// and replace special characters
        safe_url = "".join(c if c.isalnum() else "_" for c in url.split("//")[-1])
        # Add timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return f"security_headers_{safe_url}_{timestamp}.{extension}"

    def save_report(self, report: str, url: str, format: str = 'txt') -> str:
        """
        Save the report to a file.
        
        Args:
            report (str): Report content
            url (str): URL that was analyzed
            format (str): Output format (txt or json)
            
        Returns:
            str: Path to the saved report file
        """
        filename = self._generate_filename(url, format)
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(report)
            
        return filepath

    def save_json_report(self, results: Dict, url: str) -> str:
        """
        Save the report in JSON format.
        
        Args:
            results (Dict): Analysis results
            url (str): URL that was analyzed
            
        Returns:
            str: Path to the saved JSON file
        """
        filename = self._generate_filename(url, 'json')
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=4)
            
        return filepath

    def list_reports(self, url: Optional[str] = None) -> list:
        """
        List all reports or reports for a specific URL.
        
        Args:
            url (str, optional): Filter reports for this URL
            
        Returns:
            list: List of report filenames
        """
        all_reports = os.listdir(self.output_dir)
        
        if url:
            # Remove http:// or https:// and filter
            safe_url = "".join(c if c.isalnum() else "_" for c in url.split("//")[-1])
            return [r for r in all_reports if safe_url in r]
        
        return all_reports

    def get_latest_report(self, url: Optional[str] = None) -> Optional[str]:
        """
        Get the most recent report.
        
        Args:
            url (str, optional): Filter for this URL
            
        Returns:
            str: Path to the latest report file
        """
        reports = self.list_reports(url)
        
        if not reports:
            return None
            
        # Sort by timestamp in filename
        latest = sorted(reports)[-1]
        return os.path.join(self.output_dir, latest)