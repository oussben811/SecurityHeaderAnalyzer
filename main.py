# File: main.py

import argparse
from security_header_analyzer import SecurityHeaderAnalyzer
from report_manager import ReportManager

def main():
    # 1. Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description='Security Headers Analyzer - Check website security headers'
    )
    
    # Add command line arguments
    parser.add_argument(
        'url',
        help='URL to analyze (include http:// or https://)'
    )
    parser.add_argument(
        '-o', '--output-dir',
        default='reports',
        help='Directory to save reports (default: reports)'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['txt', 'json'],
        default='txt',
        help='Output format (default: txt)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only output the report file location'
    )

    # 2. Parse the command line arguments
    args = parser.parse_args()

    try:
        # 3. Initialize our classes
        analyzer = SecurityHeaderAnalyzer()  # The security header analyzer
        report_manager = ReportManager(args.output_dir)  # The report handler

        # 4. Print start message (unless quiet mode)
        if not args.quiet:
            print(f"\nAnalyzing security headers for: {args.url}")
            print("Please wait...\n")

        # 5. Perform the analysis
        results = analyzer.analyze_headers(args.url)

        # 6. Generate the report
        report = analyzer.generate_report(results)

        # 7. Save the report
        report_file = report_manager.save_report(report, args.url)

        # 8. Output results
        if args.quiet:
            print(report_file)  # Only print the file location
        else:
            print("\nAnalysis complete!")
            print(report)  # Print the full report
            print(f"\nReport saved to: {report_file}")

    except KeyboardInterrupt:
        print("\nAnalysis cancelled by user.")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0

# 9. Standard Python idiom for running the main function
if __name__ == "__main__":
    exit(main())