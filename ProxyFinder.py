#!/usr/bin/env python3
import requests
import argparse
import json
import time
import random
import threading
import queue
import socket
import socks
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings("ignore")
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init(autoreset=True)

class ProxyFinder:
    def __init__(self, output_file="proxies.txt", max_proxies=5000000, timeout=5):
        self.output_file = output_file
        self.max_proxies = max_proxies
        self.timeout = timeout
        self.proxies = set()
        self.working_proxies = set()
        self.proxy_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stats = {
            "total_found": 0,
            "working_proxies": 0,
            "http_proxies": 0,
            "socks4_proxies": 0,
            "socks5_proxies": 0,
            "start_time": "",
            "end_time": ""
        }
        
        # Mở rộng danh sách nguồn proxy
        self.proxy_sources = [
            # HTTP/HTTPS proxies
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
            "https://raw.githubusercontent.com/sxsx/proxy-list/master/proxy_list.txt",
            "https://raw.githubusercontent.com/opsxcq/proxy-list/master/list.txt",
            "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list",
            "https://raw.githubusercontent.com/roosterkid/http_proxy_list/main/proxy_list.txt",
            "https://raw.githubusercontent.com/almroot/proxylist/master/proxy.list",
            "https://raw.githubusercontent.com/Anonym0usWork1221/Proxy-Scraper/main/proxies.txt",
            "https://raw.githubusercontent.com/jhassanpro/proxy-list/main/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list.txt",
            "https://raw.githubusercontent.com/elliottophell/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/NotContagion/proxy-list/main/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
            "https://raw.githubusercontent.com/andigwandi/proxy-list/main/proxy.txt",
            "https://raw.githubusercontent.com/ProxyList/ProxyList/master/proxy.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/proxy.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxy.txt",
            "https://raw.githubusercontent.com/saisuiu/proxy-list/master/proxy.txt",
            "https://raw.githubusercontent.com/officialputuid/proxy-list/main/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/proxies.txt",
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/https.txt",
            "https://raw.githubusercontent.com/AsokaT/Proxy-Scraper/main/proxies.txt",
            "https://raw.githubusercontent.com/ProxyDB/ProxyDB/master/proxies.txt",
            "https://raw.githubusercontent.com/scarpyoff/Proxy-List/master/proxies.txt",
            "https://raw.githubusercontent.com/r00ted-Proxy/proxy-list/main/proxy.txt",
            "https://raw.githubusercontent.com/ALIILAPROXY/Proxy-List/main/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/ProxyHunter/ProxyHunter/master/proxies.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/proxy.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/https.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/socks4.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/socks5.txt",
            
            # SOCKS4 proxies
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks4.txt",
            "https://raw.githubusercontent.com/scarpyoff/Proxy-List/main/socks4.txt",
            "https://raw.githubusercontent.com/ALIILAPROXY/Proxy-List/main/socks4.txt",
            "https://raw.githubusercontent.com/ProxyHunter/ProxyHunter/master/socks4.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/socks4.txt",
            
            # SOCKS5 proxies
            "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
            "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
            "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/socks5.txt",
            "https://raw.githubusercontent.com/scarpyoff/Proxy-List/main/socks5.txt",
            "https://raw.githubusercontent.com/ALIILAPROXY/Proxy-List/main/socks5.txt",
            "https://raw.githubusercontent.com/ProxyHunter/ProxyHunter/master/socks5.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/socks5.txt",
            
            # Additional sources
            "https://raw.githubusercontent.com/acidvegas/proxies/master/proxies/http.txt",
            "https://raw.githubusercontent.com/acidvegas/proxies/master/proxies/socks4.txt",
            "https://raw.githubusercontent.com/acidvegas/proxies/master/proxies/socks5.txt",
            "https://raw.githubusercontent.com/ProxyDB/ProxyDB/master/proxies/http.txt",
            "https://raw.githubusercontent.com/ProxyDB/ProxyDB/master/proxies/socks4.txt",
            "https://raw.githubusercontent.com/ProxyDB/ProxyDB/master/proxies/socks5.txt",
            "https://raw.githubusercontent.com/Proxifier/proxy-list/main/http.txt",
            "https://raw.githubusercontent.com/Proxifier/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/Proxifier/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/andigwandi/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/andigwandi/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/socks4.txt",
            "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/socks5.txt",
            "https://raw.githubusercontent.com/NotContagion/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/NotContagion/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt",
            "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks4.txt",
            "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/rdavydov/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/saisuiu/proxy-list/master/socks4.txt",
            "https://raw.githubusercontent.com/saisuiu/proxy-list/master/socks5.txt",
            "https://raw.githubusercontent.com/officialputuid/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/officialputuid/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/AsokaT/Proxy-Scraper/main/socks4.txt",
            "https://raw.githubusercontent.com/AsokaT/Proxy-Scraper/main/socks5.txt",
            "https://raw.githubusercontent.com/r00ted-Proxy/proxy-list/main/socks4.txt",
            "https://raw.githubusercontent.com/r00ted-Proxy/proxy-list/main/socks5.txt",
            "https://raw.githubusercontent.com/ALIILAPROXY/Proxy-List/main/socks4.txt",
            "https://raw.githubusercontent.com/ALIILAPROXY/Proxy-List/main/socks5.txt",
            "https://raw.githubusercontent.com/ProxyHunter/ProxyHunter/master/socks4.txt",
            "https://raw.githubusercontent.com/ProxyHunter/ProxyHunter/master/socks5.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/socks4.txt",
            "https://raw.githubusercontent.com/ProxyList-Official/Proxy-List/main/socks5.txt"
        ]
        
        # Test URLs for different proxy types
        self.test_urls = {
            "http": "http://httpbin.org/ip",
            "socks4": "http://httpbin.org/ip",
            "socks5": "http://httpbin.org/ip"
        }
    
    def fetch_proxies_from_source(self, source):
        try:
            response = requests.get(source, verify=False, timeout=10)
            if response.status_code == 200:
                proxies = response.text.splitlines()
                new_proxies = set()
                
                for proxy in proxies:
                    proxy = proxy.strip()
                    if proxy and not proxy.startswith("#"):
                        new_proxies.add(proxy)
                
                return new_proxies
        except Exception as e:
            print(f"{Fore.RED}[-] Error fetching from {source}: {str(e)}")
        
        return set()
    
    def fetch_all_proxies(self):
        print(f"{Fore.YELLOW}[+] Fetching proxies from {len(self.proxy_sources)} sources...")
        
        # Use ThreadPoolExecutor to fetch proxies in parallel
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(self.fetch_proxies_from_source, source) for source in self.proxy_sources]
            
            for future in as_completed(futures):
                source_proxies = future.result()
                self.proxies.update(source_proxies)
                
                print(f"{Fore.GREEN}[+] Total proxies found: {len(self.proxies)}")
                
                # Stop if we have enough proxies
                if len(self.proxies) >= self.max_proxies:
                    break
        
        print(f"{Fore.GREEN}[+] Total unique proxies found: {len(self.proxies)}")
        self.stats["total_found"] = len(self.proxies)
    
    def test_http_proxy(self, proxy):
        try:
            proxy_dict = {
                "http": f"http://{proxy}",
                "https": f"http://{proxy}"
            }
            
            response = requests.get(
                self.test_urls["http"], 
                proxies=proxy_dict, 
                timeout=self.timeout,
                verify=False
            )
            
            if response.status_code == 200:
                return ("http", proxy, True)
            else:
                return ("http", proxy, False)
        except:
            return ("http", proxy, False)
    
    def test_socks4_proxy(self, proxy):
        try:
            proxy_parts = proxy.split(":")
            if len(proxy_parts) != 2:
                return ("socks4", proxy, False)
            
            proxy_host = proxy_parts[0]
            proxy_port = int(proxy_parts[1])
            
            # Create socket with SOCKS4 proxy
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS4, proxy_host, proxy_port)
            s.settimeout(self.timeout)
            
            # Test connection
            s.connect(("httpbin.org", 80))
            
            # Send HTTP request
            request = f"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            
            # Receive response
            response = s.recv(1024)
            
            # Check if response contains HTTP status code 200
            if b"200 OK" in response:
                s.close()
                return ("socks4", proxy, True)
            else:
                s.close()
                return ("socks4", proxy, False)
        except:
            return ("socks4", proxy, False)
    
    def test_socks5_proxy(self, proxy):
        try:
            proxy_parts = proxy.split(":")
            if len(proxy_parts) != 2:
                return ("socks5", proxy, False)
            
            proxy_host = proxy_parts[0]
            proxy_port = int(proxy_parts[1])
            
            # Create socket with SOCKS5 proxy
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
            s.settimeout(self.timeout)
            
            # Test connection
            s.connect(("httpbin.org", 80))
            
            # Send HTTP request
            request = f"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
            s.send(request.encode())
            
            # Receive response
            response = s.recv(1024)
            
            # Check if response contains HTTP status code 200
            if b"200 OK" in response:
                s.close()
                return ("socks5", proxy, True)
            else:
                s.close()
                return ("socks5", proxy, False)
        except:
            return ("socks5", proxy, False)
    
    def test_proxy(self, proxy):
        # Determine proxy type based on source or format
        if "socks4" in proxy or proxy.endswith(".txt:socks4"):
            proxy = proxy.replace(":socks4", "")
            return self.test_socks4_proxy(proxy)
        elif "socks5" in proxy or proxy.endswith(".txt:socks5"):
            proxy = proxy.replace(":socks5", "")
            return self.test_socks5_proxy(proxy)
        else:
            # Default to HTTP proxy
            return self.test_http_proxy(proxy)
    
    def test_all_proxies(self):
        print(f"{Fore.YELLOW}[+] Testing {len(self.proxies)} proxies...")
        
        # Convert set to list for processing
        proxy_list = list(self.proxies)
        
        # Test proxies in batches
        batch_size = 1000
        working_count = 0
        
        for i in range(0, len(proxy_list), batch_size):
            batch = proxy_list[i:i+batch_size]
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(self.test_proxy, proxy) for proxy in batch]
                
                for future in as_completed(futures):
                    proxy_type, proxy, is_working = future.result()
                    
                    if is_working:
                        self.working_proxies.add((proxy_type, proxy))
                        working_count += 1
                        
                        if proxy_type == "http":
                            self.stats["http_proxies"] += 1
                        elif proxy_type == "socks4":
                            self.stats["socks4_proxies"] += 1
                        elif proxy_type == "socks5":
                            self.stats["socks5_proxies"] += 1
                        
                        # Add to queue for immediate use
                        self.proxy_queue.put((proxy_type, proxy))
                    
                    # Print progress every 1000 proxies
                    if working_count % 1000 == 0:
                        print(f"{Fore.GREEN}[+] Working proxies found: {working_count}")
                    
                    # Stop if we have enough working proxies
                    if working_count >= self.max_proxies:
                        break
            
            # Stop if we have enough working proxies
            if working_count >= self.max_proxies:
                break
        
        self.stats["working_proxies"] = working_count
        print(f"{Fore.GREEN}[+] Working proxies found: {working_count}")
        print(f"{Fore.GREEN}[+] HTTP proxies: {self.stats['http_proxies']}")
        print(f"{Fore.GREEN}[+] SOCKS4 proxies: {self.stats['socks4_proxies']}")
        print(f"{Fore.GREEN}[+] SOCKS5 proxies: {self.stats['socks5_proxies']}")
    
    def save_proxies(self):
        print(f"{Fore.YELLOW}[+] Saving proxies to {self.output_file}...")
        
        with open(self.output_file, "w") as f:
            # Save working proxies
            for proxy_type, proxy in self.working_proxies:
                f.write(f"{proxy}\n")
        
        print(f"{Fore.GREEN}[+] Saved {len(self.working_proxies)} working proxies to {self.output_file}")
        
        # Also save categorized proxies
        with open(f"http_{self.output_file}", "w") as f:
            for proxy_type, proxy in self.working_proxies:
                if proxy_type == "http":
                    f.write(f"{proxy}\n")
        
        with open(f"socks4_{self.output_file}", "w") as f:
            for proxy_type, proxy in self.working_proxies:
                if proxy_type == "socks4":
                    f.write(f"{proxy}\n")
        
        with open(f"socks5_{self.output_file}", "w") as f:
            for proxy_type, proxy in self.working_proxies:
                if proxy_type == "socks5":
                    f.write(f"{proxy}\n")
        
        print(f"{Fore.GREEN}[+] Saved {self.stats['http_proxies']} HTTP proxies to http_{self.output_file}")
        print(f"{Fore.GREEN}[+] Saved {self.stats['socks4_proxies']} SOCKS4 proxies to socks4_{self.output_file}")
        print(f"{Fore.GREEN}[+] Saved {self.stats['socks5_proxies']} SOCKS5 proxies to socks5_{self.output_file}")
    
    def save_stats(self):
        stats_file = f"proxy_stats_{time.strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(stats_file, "w") as f:
            json.dump(self.stats, f, indent=4)
        
        print(f"{Fore.GREEN}[+] Saved statistics to {stats_file}")
    
    def run(self):
        self.stats["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Fetch all proxies
        self.fetch_all_proxies()
        
        # Test all proxies
        self.test_all_proxies()
        
        # Save proxies
        self.save_proxies()
        
        # Save statistics
        self.save_stats()
        
        self.stats["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"{Fore.CYAN}[*] Proxy finding completed!")
        print(f"{Fore.CYAN}[*] Total proxies found: {self.stats['total_found']}")
        print(f"{Fore.CYAN}[*] Working proxies: {self.stats['working_proxies']}")
        print(f"{Fore.CYAN}[*] HTTP proxies: {self.stats['http_proxies']}")
        print(f"{Fore.CYAN}[*] SOCKS4 proxies: {self.stats['socks4_proxies']}")
        print(f"{Fore.CYAN}[*] SOCKS5 proxies: {self.stats['socks5_proxies']}")
        
        return self.stats

def main():
    parser = argparse.ArgumentParser(description="Advanced Proxy Finder")
    parser.add_argument("-o", "--output", default="proxies.txt", help="Output file to save proxies (default: proxies.txt)")
    parser.add_argument("-m", "--max", type=int, default=5000000, help="Maximum number of proxies to find (default: 5000000)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Proxy test timeout in seconds (default: 5)")
    
    args = parser.parse_args()
    
    proxy_finder = ProxyFinder(
        output_file=args.output,
        max_proxies=args.max,
        timeout=args.timeout
    )
    
    proxy_finder.run()

if __name__ == "__main__":
    main()
