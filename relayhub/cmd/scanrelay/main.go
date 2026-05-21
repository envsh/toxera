package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/envsh/toxera/relayhub"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds | log.Lshortfile)
	log.Println("scanning for circuit relay nodes...")

	data, err := os.ReadFile("/tmp/libp2p_peerstore.json")
	if err != nil {
		log.Fatal("read peerstore:", err)
	}
	var ps map[string][]string
	if err := json.Unmarshal(data, &ps); err != nil {
		log.Fatal("parse:", err)
	}

	seen := make(map[string]struct{})
	var addrs []string
	for _, alist := range ps {
		for _, a := range alist {
			if a == "" {
				continue
			}
			parts := splitMultiaddr(a)
			if parts == nil {
				continue
			}
			ip, port := parts[0], parts[1]
			if skipIP(ip) {
				continue
			}
			key := ip + ":" + port
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				addrs = append(addrs, key)
			}
		}
	}

	log.Printf("testing %d unique public endpoints...", len(addrs))

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 20)
	stats := make(map[string]int)

	for _, addr := range addrs {
		wg.Add(1)
		sem <- struct{}{}
		go func(a string) {
			defer wg.Done()
			defer func() { <-sem }()

			result, code, err := testRelay(a, priv)
			mu.Lock()
			if err != nil {
				key := fmt.Sprintf("FAIL: %v", err)
				stats[key]++
				log.Printf("[%s] %s", a, key)
			} else if result {
				stats["SUCCESS(100)"]++
				log.Printf("[%s] ✅ CAN_HOP = SUCCESS (100)! RELAY NODE!", a)
			} else {
				key := fmt.Sprintf("CODE_%d", code)
				stats[key]++
				log.Printf("[%s] CAN_HOP = %d", a, code)
			}
			mu.Unlock()
		}(addr)
	}
	wg.Wait()

	log.Println("=== SCAN SUMMARY ===")
	for k, v := range stats {
		log.Printf("  %s: %d", k, v)
	}
	log.Printf("  total: %d", len(addrs))
}

func testRelay(addr string, key ed25519.PrivateKey) (result bool, code int, rerr error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	r := relayhub.DetectRelay(ctx, addr, key)
	if !r.YamuxOK {
		return false, 0, fmt.Errorf("protocol stack failed")
	}
	if r.V1OK {
		return r.V1Code == 100, r.V1Code, nil
	}
	return false, 0, fmt.Errorf("circuit v1 not available")
}

func splitMultiaddr(addr string) []string {
	parts := splitPath(addr)
	var ip, port string
	for i, p := range parts {
		if p == "tcp" && i+1 < len(parts) {
			port = parts[i+1]
		}
		if p == "ip4" && i+1 < len(parts) {
			ip = parts[i+1]
		}
	}
	if ip != "" && port != "" {
		return []string{ip, port}
	}
	return nil
}

func splitPath(s string) []string {
	var result []string
	for _, p := range splitRaw(s, '/') {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func splitRaw(s string, sep byte) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			if i > start {
				result = append(result, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

func skipIP(ip string) bool {
	if ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" {
		return true
	}
	if len(ip) >= 7 && ip[:7] == "172.33." {
		return true
	}
	if len(ip) >= 6 && ip[:6] == "169.25" {
		return true
	}
	if contains(ip, ":") {
		return true
	}
	if contains(ip, ".") {
		parts := splitRaw(ip, '.')
		if len(parts) == 4 {
			if parts[0] == "10" {
				return true
			}
			if parts[0] == "192" && parts[1] == "168" {
				return true
			}
		}
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsStr(s, substr)
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
