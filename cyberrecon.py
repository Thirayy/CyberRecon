import whois
import dns.resolver
import requests

# Function to fetch WHOIS data
def fetch_whois(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return f"Error fetching WHOIS data: {e}"

# Function to fetch DNS records
def fetch_dns_records(domain):
    records = {}
    try:
        for record_type in ["A", "MX", "TXT", "CNAME"]:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(r) for r in answers]
    except Exception as e:
        records["Error"] = f"Error fetching DNS records: {e}"
    return records

# Function to enumerate subdomains
def enumerate_subdomains(domain):
    subdomains = []
    try:
        # Example static list of subdomains for demonstration
        common_subdomains = ["www", "mail", "blog", "ftp", "test"]
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(subdomain, "A")
                subdomains.append(subdomain)
            except:
                continue
    except Exception as e:
        return f"Error enumerating subdomains: {e}"
    return subdomains

# Function to analyze basic web vulnerabilities (SQL Injection and XSS)
def analyze_web_vulnerabilities(target_url):
    vulnerability_report = "\nWeb Vulnerability Analysis (Basic Indicators Only):\n"
    vulnerability_report += "WARNING: This is NOT a full vulnerability scanner and should ONLY be used on websites you have explicit permission to test.\n"
    vulnerability_report += "Actual exploitation of vulnerabilities is illegal and unethical without consent.\n\n"

    # Basic SQL Injection check
    sqli_payload = "'"
    test_url_sqli = f"{target_url}?q={sqli_payload}" if '?' not in target_url else f"{target_url}&q={sqli_payload}"
    
    try:
        response_sqli = requests.get(test_url_sqli, timeout=5)
        if any(err_msg in response_sqli.text.lower() for err_msg in ["sql error", "syntax error", "mysql", "odbc", "ORA-"]):
            vulnerability_report += f"- Potential SQL Injection indicator found with payload: {sqli_payload} (URL: {test_url_sqli})\n"
        else:
            vulnerability_report += "- No immediate SQL Injection indicator found with simple quote payload.\n"
    except requests.exceptions.RequestException as e:
        vulnerability_report += f"- Error during SQLi check: {e}\n"

    # Basic XSS check
    xss_payload = "<script>alert('XSS')</script>"
    test_url_xss = f"{target_url}?p={xss_payload}" if '?' not in target_url else f"{target_url}&p={xss_payload}"

    try:
        response_xss = requests.get(test_url_xss, timeout=5)
        if xss_payload in response_xss.text:
            vulnerability_report += f"- Potential XSS reflection found with payload: {xss_payload} (URL: {test_url_xss})\n"
        else:
            vulnerability_report += "- No immediate XSS reflection found with simple script payload.\n"
    except requests.exceptions.RequestException as e:
        vulnerability_report += f"- Error during XSS check: {e}\n"
        
    return vulnerability_report

# Main function
def domain_intelligence_tool(domain):
    report = f"Domain Intelligence Report for {domain}\n"
    report += "=" * 50 + "\n\n"
    
    # WHOIS Data
    report += "WHOIS Data:\n"
    whois_data = fetch_whois(domain)
    report += str(whois_data) + "\n\n"
    
    # DNS Records
    report += "DNS Records:\n"
    dns_records = fetch_dns_records(domain)
    for record_type, records in dns_records.items():
        report += f"{record_type} Records: {records}\n"
    report += "\n"
    
    # Subdomain Enumeration
    report += "Subdomain Enumeration:\n"
    subdomains = enumerate_subdomains(domain)
    report += "\n".join(subdomains) if subdomains else "No subdomains found."
    report += "\n\n"

    # Web Vulnerability Analysis (Basic)
    web_vulnerability_result = analyze_web_vulnerabilities(f"http://{domain}") # Assuming http for basic check
    report += web_vulnerability_result
    
    return report

# Main execution
if __name__ == "__main__":
    print("Welcome to Domain Intelligence Tool")
    domain = input("Enter the domain to analyze (e.g., example.com): ")
    
    # Run the tool
    report = domain_intelligence_tool(domain)
    
    # Save report to file
    with open("domain_report.txt", "w") as file:
        file.write(report)
    
    print("\nAnalysis complete. The report is saved as 'domain_report.txt'.")
