import os
import nmap
import requests
from bs4 import BeautifulSoup
import whois
import socket
from colorama import Fore, init
from urllib.parse import urlparse
import re
import argparse
from pathlib import Path

# Selenium for JavaScript tech detection
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

init(autoreset=True)

# Base class
class PentestAgent:
    def __init__(self, agent_name, specialty):
        self.agent_name = agent_name
        self.specialty = specialty
        self.findings = []

    def report(self):
        print(Fore.CYAN + f"\n🧾 {self.agent_name} Report:")
        if self.findings:
            for i, finding in enumerate(self.findings, 1):
                print(f"{i}. {finding}")
        else:
            print("No findings in this category.")

# Network Scanner
class NetworkScannerAgent(PentestAgent):
    def scan_network(self, url):
        try:
            print(Fore.YELLOW + f"\n🛸 {self.agent_name} scanning network for {url}...")
            nm = nmap.PortScanner()
            domain = urlparse(url).netloc
            ip = socket.gethostbyname(domain)
            nm.scan(ip, '21-443')
            open_ports = []
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto].keys():
                    open_ports.append(port)
            if open_ports:
                self.findings.append(f"Open ports: {', '.join(map(str, open_ports))}")
            else:
                self.findings.append("No open ports found.")
        except Exception as e:
            self.findings.append(f"Error: {e}")

# Phishing Detector
class SocialEngineeringAgent(PentestAgent):
    def scan_for_phishing(self, url):
        try:
            print(Fore.YELLOW + f"\n🕵️ {self.agent_name} analyzing for phishing...")
            res = requests.get(url, timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '').lower()
                if "login" in action or "signin" in action:
                    self.findings.append(f"Suspicious form action: {action}")
            if "login" in url.lower() or "signin" in url.lower():
                self.findings.append("Suspicious URL pattern detected.")
        except Exception as e:
            self.findings.append(f"Error: {e}")

# WHOIS Agent
class WhoisAgent(PentestAgent):
    def scan_whois(self, url):
        try:
            print(Fore.YELLOW + f"\n📜 {self.agent_name} retrieving WHOIS data...")
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            self.findings.append(f"Domain: {w.domain_name}")
            self.findings.append(f"Registrar: {w.registrar}")
            self.findings.append(f"Created: {w.creation_date}")
            self.findings.append(f"Expires: {w.expiration_date}")
        except Exception as e:
            self.findings.append(f"WHOIS error: {e}")

# Security Header Check
class HeaderCheckAgent(PentestAgent):
    def check_headers(self, url):
        try:
            print(Fore.YELLOW + f"\n🧠 {self.agent_name} checking security headers...")
            res = requests.get(url, timeout=5)
            headers = res.headers
            missing = []
            required_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection"]
            for h in required_headers:
                if h not in headers:
                    missing.append(h)
            if missing:
                self.findings.append(f"Missing important headers: {', '.join(missing)}")
            else:
                self.findings.append("All major security headers are present.")
        except Exception as e:
            self.findings.append(f"Header check error: {e}")

# JS Fingerprinting Agent
class FingerprintAgent(PentestAgent):
    def identify_tech(self, url):
        try:
            print(Fore.YELLOW + f"\n🔍 {self.agent_name} identifying technologies with JS support...")
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)

            driver.get(url)
            html = driver.page_source
            driver.quit()

            tech_signatures = {
                "React": r"__REACT_DEVTOOLS_GLOBAL_HOOK__|react",
                "Next.js": r"_next|next.config",
                "jQuery": r"jquery",
                "Bootstrap": r"bootstrap",
                "Cloudflare": r"cloudflare",
                "Vue.js": r"vue",
                "Angular": r"angular",
                "Wix": r"wix",
                "Shopify": r"cdn\.shopify|shopify"
            }

            detected = set()
            for name, pattern in tech_signatures.items():
                if re.search(pattern, html, re.IGNORECASE):
                    detected.add(name)

            if detected:
                self.findings.append(f"🧬 JS-Based Tech Stack Detected: {', '.join(detected)}")
            else:
                self.findings.append("⚠️ No recognizable technologies detected even after JS rendering.")
        except Exception as e:
            self.findings.append(f"JS Fingerprinting error: {e}")

# Directory Bruteforcing
class DirectoryBruteAgent(PentestAgent):
    def bruteforce_dirs(self, url):
        try:
            print(Fore.YELLOW + f"\n🔓 {self.agent_name} bruteforcing common directories...")
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            common_paths = ["/admin", "/login", "/dashboard", "/.git", "/.env"]
            found = []

            for path in common_paths:
                full_url = base_url + path
                try:
                    res = requests.get(full_url, timeout=5)
                    if res.status_code == 200:
                        found.append(full_url)
                except requests.RequestException:
                    continue

            if found:
                self.findings.append(f"Accessible sensitive paths: {', '.join(found)}")
            else:
                self.findings.append("No common sensitive paths exposed.")
        except Exception as e:
            self.findings.append(f"Directory brute error: {e}")

# 🔥 GitHub Repo Scanner (BONUS)
class RepoScanAgent(PentestAgent):
    def __init__(self, repo_path):
        super().__init__("RepoScan Agent", "Malware/Secrets in Code")
        self.repo_path = Path(repo_path)

    def scan_repository(self):
        print(Fore.YELLOW + f"\n🧪 {self.agent_name} scanning repository at {self.repo_path}...")
        if not self.repo_path.exists():
            self.findings.append("Repository path does not exist.")
            return

        risky_patterns = {
            "eval()": r"\beval\(",
            "exec()": r"\bexec\(",
            "os.system": r"\bos\.system\(",
            "subprocess": r"\bsubprocess\.(run|call|Popen)",
            "base64 payload": r"(?:[A-Za-z0-9+/]{30,}={0,2})",
            "API key / Secret": r"(apikey|secret|token|passwd|password)[\s:=]+['\"][A-Za-z0-9_\-]{8,}['\"]",
            "Suspicious Comment": r"#.*?(backdoor|TODO|FIXME)"
        }

        for file_path in self.repo_path.rglob("*"):
            if file_path.is_file() and file_path.suffix in {".py", ".js", ".sh", ".env", ".ts"}:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for i, line in enumerate(lines, 1):
                            for label, pattern in risky_patterns.items():
                                if re.search(pattern, line, re.IGNORECASE):
                                    self.findings.append(
                                        f"{label} in {file_path.relative_to(self.repo_path)} (line {i}): {line.strip()}"
                                    )
                except Exception as e:
                    self.findings.append(f"Error reading {file_path.name}: {e}")

# CyberSleuth Engine
class CyberSleuth:
    def __init__(self, url=None, repo_path=None):
        self.url = url
        self.repo_path = repo_path
        self.agents = []
        self.risk_flags = 0

        if self.url:
            self.agents.extend([
                NetworkScannerAgent("Network Agent", "Port Scan"),
                SocialEngineeringAgent("Social Agent", "Phishing Detection"),
                WhoisAgent("WHOIS Agent", "Domain Info"),
                HeaderCheckAgent("Header Agent", "Security Headers"),
                FingerprintAgent("Tech Agent", "Technology Fingerprint"),
                DirectoryBruteAgent("Brute Agent", "Dir Bruteforce"),
            ])
        if self.repo_path:
            self.agents.append(RepoScanAgent(self.repo_path))

    def run_scan(self):
        print(Fore.GREEN + f"\n📱 Starting CyberSleuth scan...\n")
        for agent in self.agents:
            if isinstance(agent, NetworkScannerAgent):
                agent.scan_network(self.url)
            elif isinstance(agent, SocialEngineeringAgent):
                agent.scan_for_phishing(self.url)
            elif isinstance(agent, WhoisAgent):
                agent.scan_whois(self.url)
            elif isinstance(agent, HeaderCheckAgent):
                agent.check_headers(self.url)
            elif isinstance(agent, FingerprintAgent):
                agent.identify_tech(self.url)
            elif isinstance(agent, DirectoryBruteAgent):
                agent.bruteforce_dirs(self.url)
            elif isinstance(agent, RepoScanAgent):
                agent.scan_repository()
            agent.report()

            for finding in agent.findings:
                if any(x in finding.lower() for x in ["suspicious", "error", "missing", "⚠️"]):
                    self.risk_flags += 1

        print(Fore.MAGENTA + "\n🧠 Final Verdict:")
        if self.risk_flags > 2:
            print(Fore.RED + "⚠️ Potential risks found. Caution advised.")
        else:
            print(Fore.GREEN + "✅ No major issues detected.")

        print(Fore.CYAN + "\n🎉 Thank you for using CyberSleuth!")
        print("🔐 Keep learning, keep securing — The CYBER CLUBERS 🚀")

# CLI entry
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberSleuth: Ethical Hacking & Malware Scanner")
    parser.add_argument("--url", help="Target website URL")
    parser.add_argument("--repo", help="Path to local GitHub repository to scan")
    args = parser.parse_args()

    if not args.url and not args.repo:
        print("Please provide at least --url or --repo.")
    else:
        sleuth = CyberSleuth(url=args.url, repo_path=args.repo)
        sleuth.run_scan()
